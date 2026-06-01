use crate::coins::Transaction;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default)]
pub struct Mempool {
    inner: Arc<Mutex<VecDeque<Transaction>>>,
}

impl Mempool {
    pub fn push(&self, transaction: Transaction) {
        self.inner
            .lock()
            .expect("mempool lock poisoned")
            .push_back(transaction);
    }

    pub fn drain(&self, max: usize) -> Vec<Transaction> {
        let mut inner = self.inner.lock().expect("mempool lock poisoned");
        let count = max.min(inner.len());
        inner.drain(..count).collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("mempool lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
