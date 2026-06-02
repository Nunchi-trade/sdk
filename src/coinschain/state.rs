use super::Block;
use crate::coins::Ledger;
use commonware_consensus::Heightable;
use commonware_cryptography::{sha256::Digest, Digestible};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const LEDGER_RETENTION_DEPTH: u64 = 8;

#[derive(Clone, Debug, Serialize)]
pub struct ChainStatus {
    pub height: u64,
    pub block_digest: String,
    pub state_root: String,
    pub finalized_blocks: u64,
}

#[derive(Clone, Debug)]
pub struct SharedState {
    inner: Arc<Mutex<StateInner>>,
}

#[derive(Debug)]
struct StateInner {
    finalized: Block,
    finalized_blocks: u64,
    ledgers: BTreeMap<Digest, LedgerSnapshot>,
}

#[derive(Debug)]
struct LedgerSnapshot {
    height: u64,
    ledger: Ledger,
}

impl SharedState {
    pub fn new(genesis: Block, ledger: Ledger) -> Self {
        let mut ledgers = BTreeMap::new();
        ledgers.insert(
            genesis.digest(),
            LedgerSnapshot {
                height: genesis.height().get(),
                ledger,
            },
        );
        Self {
            inner: Arc::new(Mutex::new(StateInner {
                finalized: genesis,
                finalized_blocks: 0,
                ledgers,
            })),
        }
    }

    pub fn finalized(&self) -> Block {
        self.inner
            .lock()
            .expect("chain state lock poisoned")
            .finalized
            .clone()
    }

    pub fn finalized_ledger(&self) -> Ledger {
        let inner = self.inner.lock().expect("chain state lock poisoned");
        let digest = inner.finalized.digest();
        inner
            .ledgers
            .get(&digest)
            .map(|snapshot| snapshot.ledger.clone())
            .expect("finalized block ledger missing")
    }

    pub fn ledger_for(&self, digest: &Digest) -> Option<Ledger> {
        self.inner
            .lock()
            .expect("chain state lock poisoned")
            .ledgers
            .get(digest)
            .map(|snapshot| snapshot.ledger.clone())
    }

    pub fn insert_block_state(&self, block: &Block, ledger: Ledger) {
        self.inner
            .lock()
            .expect("chain state lock poisoned")
            .ledgers
            .insert(
                block.digest(),
                LedgerSnapshot {
                    height: block.height().get(),
                    ledger,
                },
            );
    }

    pub fn finalize(&self, block: Block) -> bool {
        let mut inner = self.inner.lock().expect("chain state lock poisoned");
        if block.height() > inner.finalized.height() {
            if !inner.ledgers.contains_key(&block.digest()) {
                return false;
            }
            inner.finalized_blocks = inner.finalized_blocks.saturating_add(1);
            inner.finalized = block;
            inner.prune_ledgers();
            return true;
        }
        false
    }

    pub fn status(&self) -> ChainStatus {
        let inner = self.inner.lock().expect("chain state lock poisoned");
        ChainStatus {
            height: inner.finalized.height().get(),
            block_digest: inner.finalized.digest().to_string(),
            state_root: inner.finalized.state_root.to_string(),
            finalized_blocks: inner.finalized_blocks,
        }
    }
}

impl StateInner {
    fn prune_ledgers(&mut self) {
        let finalized_height = self.finalized.height().get();
        let minimum_height = finalized_height.saturating_sub(LEDGER_RETENTION_DEPTH);
        let finalized_digest = self.finalized.digest();
        self.ledgers.retain(|digest, snapshot| {
            *digest == finalized_digest || snapshot.height >= minimum_height
        });
    }
}

impl Default for SharedState {
    fn default() -> Self {
        let ledger = Ledger::default();
        let genesis = crate::coinschain::application::Application::genesis_with_ledger(&ledger);
        Self::new(genesis, ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_refuses_blocks_without_ledger_state() {
        let ledger = Ledger::default();
        let genesis = crate::coinschain::application::Application::genesis_with_ledger(&ledger);
        let block = Block::new(
            genesis.context.clone(),
            genesis.digest(),
            genesis.height.next(),
            1,
            Vec::new(),
            ledger.state_root(),
        );
        let state = SharedState::new(genesis, ledger.clone());

        assert!(!state.finalize(block.clone()));
        assert_eq!(state.status().height, 0);

        state.insert_block_state(&block, ledger);
        assert!(state.finalize(block));
        assert_eq!(state.status().height, 1);
        assert_eq!(
            state.finalized_ledger().state_root(),
            state.finalized().state_root
        );
    }

    #[test]
    fn finalize_prunes_old_ledger_snapshots() {
        let ledger = Ledger::default();
        let genesis = crate::coinschain::application::Application::genesis_with_ledger(&ledger);
        let genesis_digest = genesis.digest();
        let state = SharedState::new(genesis.clone(), ledger.clone());
        let mut parent = genesis;

        for height in 1..=(LEDGER_RETENTION_DEPTH + 2) {
            let block = Block::new(
                parent.context.clone(),
                parent.digest(),
                parent.height.next(),
                height,
                Vec::new(),
                ledger.state_root(),
            );
            state.insert_block_state(&block, ledger.clone());
            assert!(state.finalize(block.clone()));
            parent = block;
        }

        let inner = state.inner.lock().expect("chain state lock poisoned");
        assert!(!inner.ledgers.contains_key(&genesis_digest));
        assert!(inner.ledgers.contains_key(&parent.digest()));
        assert!(inner.ledgers.len() <= LEDGER_RETENTION_DEPTH as usize + 1);
    }
}
