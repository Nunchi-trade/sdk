use super::{
    block::MAX_BLOCK_TRANSACTIONS, types::Context, Block, Mempool, Scheme, SharedState, EPOCH,
};
use crate::coins::Ledger;
use commonware_actor::Feedback;
use commonware_consensus::{
    marshal::{ancestry::Ancestry, Update},
    types::{Height, Round, View},
    Application as ConsensusApplication, Reporter,
};
use commonware_cryptography::{ed25519, sha256, Digest as _, Digestible, Signer};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{Acknowledgement, SystemTimeExt};
use futures::StreamExt;
use rand::Rng;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

const MAX_BLOCK_TIMESTAMP_MS: u64 = 7_258_118_400_000;

#[derive(Clone, Debug)]
pub struct Application {
    mempool: Mempool,
    state: SharedState,
}

impl Application {
    pub fn new(mempool: Mempool, state: SharedState) -> Self {
        Self { mempool, state }
    }

    pub fn genesis() -> Block {
        Self::genesis_with_ledger(&Ledger::default())
    }

    pub fn genesis_with_ledger(ledger: &Ledger) -> Block {
        let genesis_context = Context {
            round: Round::new(EPOCH, View::zero()),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::zero(), sha256::Digest::EMPTY),
        };
        Block::new(
            genesis_context,
            sha256::Digest::EMPTY,
            Height::zero(),
            0,
            Vec::new(),
            ledger.state_root(),
        )
    }

    async fn ledger_for_parent(
        &self,
        parent: Block,
        mut ancestry: impl Ancestry<Block>,
    ) -> Option<Ledger> {
        if let Some(ledger) = self.state.ledger_for(&parent.digest()) {
            return Some(ledger);
        }

        let mut missing = vec![parent];
        while let Some(ancestor) = ancestry.next().await {
            if let Some(mut ledger) = self.state.ledger_for(&ancestor.digest()) {
                for block in missing.iter().rev() {
                    if !apply_block(&mut ledger, block) {
                        return None;
                    }
                    self.state.insert_block_state(block, ledger.clone());
                }
                return Some(ledger);
            }
            missing.push(ancestor);
        }

        None
    }

    fn ledger_for_finalized_block(&self, block: &Block, digest: &sha256::Digest) -> Option<Ledger> {
        if let Some(ledger) = self.state.ledger_for(digest) {
            return Some(ledger);
        }

        let Some(mut ledger) = self.state.ledger_for(&block.parent) else {
            warn!(
                height = %block.height,
                digest = %digest,
                parent = %block.parent,
                "missing parent ledger for finalized coinschain block"
            );
            return None;
        };

        if !apply_block(&mut ledger, block) {
            warn!(
                height = %block.height,
                digest = %digest,
                "failed to reconstruct finalized coinschain ledger"
            );
            return None;
        }
        let state_root = ledger.state_root();
        if state_root != block.state_root {
            warn!(
                height = %block.height,
                digest = %digest,
                expected = %block.state_root,
                actual = %state_root,
                "reconstructed finalized coinschain ledger has wrong state root"
            );
            return None;
        }

        self.state.insert_block_state(block, ledger.clone());
        Some(ledger)
    }
}

impl<E> ConsensusApplication<E> for Application
where
    E: Rng + Spawner + Metrics + Clock,
{
    type SigningScheme = Scheme;
    type Context = Context;
    type Block = Block;

    async fn propose(
        &mut self,
        (runtime_context, context): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> Option<Self::Block> {
        let parent = ancestry.next().await?;
        let mut ledger = self.ledger_for_parent(parent.clone(), ancestry).await?;

        let candidates = self.mempool.snapshot(&ledger, MAX_BLOCK_TRANSACTIONS);
        let mut included = Vec::with_capacity(candidates.len());
        for transaction in candidates {
            match ledger.apply_transaction(&transaction) {
                Ok(()) => included.push(transaction),
                Err(error) => debug!(?error, "dropped invalid transaction from proposal"),
            }
        }

        let mut current = runtime_context.current().epoch_millis();
        if current <= parent.timestamp_ms {
            current = parent
                .timestamp_ms
                .checked_add(1)
                .expect("parent timestamp overflowed");
        }
        assert!(
            current <= MAX_BLOCK_TIMESTAMP_MS,
            "proposed timestamp exceeded maximum"
        );

        let block = Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            current,
            included,
            ledger.state_root(),
        );
        self.state.insert_block_state(&block, ledger);
        Some(block)
    }

    async fn verify(
        &mut self,
        (runtime_context, _): (E, Self::Context),
        mut ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        let Some(block) = ancestry.next().await else {
            return false;
        };
        let Some(parent) = ancestry.next().await else {
            return false;
        };

        if block.timestamp_ms <= parent.timestamp_ms || block.timestamp_ms > MAX_BLOCK_TIMESTAMP_MS
        {
            return false;
        }

        let Some(mut ledger) = self.ledger_for_parent(parent.clone(), ancestry).await else {
            warn!(height = %block.height, "missing parent ledger for verification");
            return false;
        };

        if !apply_block(&mut ledger, &block) {
            return false;
        }
        if ledger.state_root() != block.state_root {
            return false;
        }

        let deadline = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_millis(block.timestamp_ms))
            .expect("block timestamp exceeded maximum");
        runtime_context.sleep_until(deadline).await;
        self.state.insert_block_state(&block, ledger);
        true
    }
}

impl Reporter for Application {
    type Activity = Update<Block>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(block, ack_rx) = activity {
            let digest = block.digest();
            let height = block.height.get();
            let transactions = block.transactions.clone();
            info!(
                height,
                digest = %digest,
                transactions = block.transactions.len(),
                "finalized coinschain block"
            );
            if let Some(ledger) = self.ledger_for_finalized_block(&block, &digest) {
                if !self.state.finalize(block) {
                    warn!(
                        height,
                        digest = %digest,
                        "skipped stale or unavailable coinschain finalization"
                    );
                    ack_rx.acknowledge();
                    return Feedback::Ok;
                }
                let removed = self
                    .mempool
                    .remove_finalized_and_invalid(&transactions, &ledger);
                if removed > 0 {
                    debug!(
                        removed,
                        remaining = self.mempool.len(),
                        "pruned coinschain mempool"
                    );
                }
            } else {
                warn!(
                    height,
                    digest = %digest,
                    "skipped coinschain finalization because block state is unavailable"
                );
            }
            ack_rx.acknowledge();
        }
        Feedback::Ok
    }
}

fn apply_block(ledger: &mut Ledger, block: &Block) -> bool {
    for transaction in &block.transactions {
        if let Err(error) = ledger.apply_transaction(transaction) {
            debug!(?error, "block transaction failed ledger validation");
            return false;
        }
    }
    true
}
