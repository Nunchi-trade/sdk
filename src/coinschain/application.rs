use super::{
    block::{MAX_BLOCK_BYTES, MAX_BLOCK_TRANSACTIONS},
    types::Context,
    Block, Mempool, Scheme, SharedState, EPOCH,
};
use crate::coins::Ledger;
use commonware_actor::Feedback;
use commonware_codec::EncodeSize;
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
                    if !apply_block(&mut ledger, block, Some(&self.mempool)) {
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

        if !apply_block(&mut ledger, block, Some(&self.mempool)) {
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
        let started = Instant::now();
        let parent = ancestry.next().await?;
        let mut ledger = self.ledger_for_parent(parent.clone(), ancestry).await?;

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

        let candidates = self.mempool.snapshot(&ledger, MAX_BLOCK_TRANSACTIONS);
        let mut included = Vec::with_capacity(candidates.len());
        let mut encoded_bytes = empty_block_encoded_size(&context, &parent, current);
        let mut invalid = 0usize;
        let mut byte_limit_hit = false;
        for candidate in candidates {
            if !candidate.signature_valid() || !candidate.stateless_valid() {
                invalid += 1;
                continue;
            }
            let next_encoded_bytes = encoded_bytes + candidate.encoded_size();
            if next_encoded_bytes > MAX_BLOCK_BYTES {
                byte_limit_hit = true;
                break;
            }

            let transaction = candidate.transaction();
            match ledger.apply_verified_transaction(transaction) {
                Ok(()) => {
                    encoded_bytes = next_encoded_bytes;
                    included.push(candidate.into_transaction());
                }
                Err(error) => {
                    invalid += 1;
                    debug!(?error, "dropped invalid transaction from proposal");
                }
            }
        }

        let included_count = included.len();
        let candidate_count = included_count + invalid;
        let block = Block::new(
            context,
            parent.digest(),
            parent.height.next(),
            current,
            included,
            ledger.state_root(),
        );
        let actual_encoded_bytes = block.encode_size();
        if actual_encoded_bytes > MAX_BLOCK_BYTES {
            warn!(
                height = %block.height,
                encoded_bytes = actual_encoded_bytes,
                max_bytes = MAX_BLOCK_BYTES,
                "skipping oversized coinschain proposal"
            );
            return None;
        }
        if included_count > 0 || byte_limit_hit {
            info!(
                height = %block.height,
                transactions = block.transactions.len(),
                candidates = candidate_count,
                invalid,
                byte_limit_hit,
                encoded_bytes = actual_encoded_bytes,
                max_bytes = MAX_BLOCK_BYTES,
                elapsed_ms = started.elapsed().as_millis(),
                "built coinschain proposal"
            );
        } else {
            debug!(
                height = %block.height,
                transactions = block.transactions.len(),
                candidates = candidate_count,
                invalid,
                byte_limit_hit,
                encoded_bytes = actual_encoded_bytes,
                max_bytes = MAX_BLOCK_BYTES,
                elapsed_ms = started.elapsed().as_millis(),
                "built coinschain proposal"
            );
        }
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
        let encoded_bytes = block.encode_size();
        if encoded_bytes > MAX_BLOCK_BYTES {
            warn!(
                height = %block.height,
                encoded_bytes,
                max_bytes = MAX_BLOCK_BYTES,
                "rejected oversized coinschain block"
            );
            return false;
        }

        let Some(mut ledger) = self.ledger_for_parent(parent.clone(), ancestry).await else {
            warn!(height = %block.height, "missing parent ledger for verification");
            return false;
        };

        let started = Instant::now();
        if !apply_block(&mut ledger, &block, Some(&self.mempool)) {
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
        if !block.transactions.is_empty() {
            info!(
                height = %block.height,
                transactions = block.transactions.len(),
                encoded_bytes,
                elapsed_ms = started.elapsed().as_millis(),
                "verified coinschain block"
            );
        } else {
            debug!(
                height = %block.height,
                transactions = block.transactions.len(),
                encoded_bytes,
                elapsed_ms = started.elapsed().as_millis(),
                "verified coinschain block"
            );
        }
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
                encoded_bytes = block.encode_size(),
                certify_latency_ms = block_certify_latency_ms(&block),
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

fn apply_block(ledger: &mut Ledger, block: &Block, mempool: Option<&Mempool>) -> bool {
    for transaction in &block.transactions {
        let digest = transaction.digest();
        let result = if mempool.is_some_and(|mempool| mempool.has_valid_signature(&digest)) {
            ledger.apply_verified_transaction(transaction)
        } else {
            ledger.apply_transaction(transaction)
        };
        if let Err(error) = result {
            debug!(?error, "block transaction failed ledger validation");
            return false;
        }
    }
    true
}

fn empty_block_encoded_size(context: &Context, parent: &Block, timestamp_ms: u64) -> usize {
    let transactions: Vec<crate::coins::Transaction> = Vec::new();
    context.encode_size()
        + parent.digest().encode_size()
        + parent.height.next().encode_size()
        + timestamp_ms.encode_size()
        + transactions.encode_size()
        + sha256::Digest::EMPTY.encode_size()
}

fn block_certify_latency_ms(block: &Block) -> u128 {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    now.as_millis()
        .saturating_sub(u128::from(block.timestamp_ms))
}
