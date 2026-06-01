use super::Block;
use crate::coins::Ledger;
use commonware_consensus::Heightable;
use commonware_cryptography::{sha256::Digest, Digestible};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

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
    ledgers: BTreeMap<Digest, Ledger>,
}

impl SharedState {
    pub fn new(genesis: Block, ledger: Ledger) -> Self {
        let mut ledgers = BTreeMap::new();
        ledgers.insert(genesis.digest(), ledger);
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
            .cloned()
            .expect("finalized block ledger missing")
    }

    pub fn ledger_for(&self, digest: &Digest) -> Option<Ledger> {
        self.inner
            .lock()
            .expect("chain state lock poisoned")
            .ledgers
            .get(digest)
            .cloned()
    }

    pub fn insert_block_state(&self, block: &Block, ledger: Ledger) {
        self.inner
            .lock()
            .expect("chain state lock poisoned")
            .ledgers
            .insert(block.digest(), ledger);
    }

    pub fn finalize(&self, block: Block) {
        let mut inner = self.inner.lock().expect("chain state lock poisoned");
        if block.height() > inner.finalized.height() {
            inner.finalized_blocks = inner.finalized_blocks.saturating_add(1);
            inner.finalized = block;
        }
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

impl Default for SharedState {
    fn default() -> Self {
        let ledger = Ledger::default();
        let genesis = crate::coinschain::application::Application::genesis_with_ledger(&ledger);
        Self::new(genesis, ledger)
    }
}
