use crate::coins::{
    CoinOperation, Ledger, TokenFactory, Transaction, MAX_NAME_BYTES, MAX_SYMBOL_BYTES,
};
use std::{
    collections::{BTreeSet, VecDeque},
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

    pub fn snapshot(&self, max: usize) -> Vec<Transaction> {
        let inner = self.inner.lock().expect("mempool lock poisoned");
        inner.iter().take(max).cloned().collect()
    }

    pub fn remove_finalized_and_invalid(
        &self,
        finalized: &[Transaction],
        ledger: &Ledger,
    ) -> usize {
        let finalized = finalized
            .iter()
            .map(Transaction::digest)
            .collect::<BTreeSet<_>>();
        let mut removed = 0;
        let mut inner = self.inner.lock().expect("mempool lock poisoned");
        inner.retain(|transaction| {
            let remove = finalized.contains(&transaction.digest())
                || is_stale_or_permanently_invalid(transaction, ledger);
            if remove {
                removed += 1;
            }
            !remove
        });
        removed
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("mempool lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn is_stale_or_permanently_invalid(transaction: &Transaction, ledger: &Ledger) -> bool {
    if !transaction.verify() {
        return true;
    }

    let expected = ledger.nonce(&transaction.signer);
    if transaction.payload.nonce < expected {
        return true;
    }
    if transaction.payload.nonce > expected {
        return false;
    }

    match &transaction.payload.operation {
        CoinOperation::CreateToken { spec } => {
            if spec.symbol.is_empty()
                || spec.symbol.len() > MAX_SYMBOL_BYTES
                || spec.name.is_empty()
                || spec.name.len() > MAX_NAME_BYTES
                || spec
                    .max_supply
                    .is_some_and(|max_supply| spec.initial_supply > max_supply)
            {
                return true;
            }
            let coin = TokenFactory::derive_coin_id(
                &transaction.signer,
                ledger.factory().next_nonce(),
                spec,
            );
            ledger.token(&coin).is_some()
        }
        CoinOperation::Mint { coin, amount, .. } => {
            if *amount == 0 {
                return true;
            }
            ledger
                .token(coin)
                .is_some_and(|token| token.issuer != transaction.signer)
        }
        CoinOperation::Burn { from, amount, .. } | CoinOperation::Transfer { from, amount, .. } => {
            *amount == 0 || from != &transaction.signer
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coins::{CoinOperation, CoinSpec, PrivateKey, TokenFactory};
    use commonware_cryptography::Signer;

    #[test]
    fn snapshot_does_not_remove_transactions() {
        let issuer = PrivateKey::from_seed(1);
        let first = Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("A", "A Coin", 0, 10, Some(10)),
            },
        );
        let second = Transaction::sign(
            &issuer,
            1,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("B", "B Coin", 0, 10, Some(10)),
            },
        );
        let mempool = Mempool::default();
        mempool.push(first.clone());
        mempool.push(second.clone());

        assert_eq!(mempool.snapshot(1), vec![first.clone()]);
        assert_eq!(mempool.len(), 2);
        assert_eq!(mempool.snapshot(10), vec![first, second]);
    }

    #[test]
    fn remove_finalized_and_invalid_keeps_future_valid_transactions() {
        let issuer = PrivateKey::from_seed(10);
        let outsider = PrivateKey::from_seed(11);
        let recipient = PrivateKey::from_seed(12).public_key();
        let issuer_id = issuer.public_key();
        let spec = CoinSpec::new("KEEP", "Keep Coin", 0, 100, Some(100));
        let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);
        let create = Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken { spec: spec.clone() },
        );
        let stale = Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("OLD", "Old Coin", 0, 1, Some(1)),
            },
        );
        let valid_now = Transaction::sign(
            &issuer,
            1,
            CoinOperation::Transfer {
                coin,
                from: issuer_id.clone(),
                to: recipient.clone(),
                amount: 10,
            },
        );
        let future_valid = Transaction::sign(
            &issuer,
            2,
            CoinOperation::Transfer {
                coin,
                from: issuer_id.clone(),
                to: recipient,
                amount: 5,
            },
        );
        let unauthorized = Transaction::sign(
            &outsider,
            0,
            CoinOperation::Mint {
                coin,
                to: outsider.public_key(),
                amount: 1,
            },
        );

        let mut ledger = Ledger::default();
        ledger.apply_transaction(&create).unwrap();

        let mempool = Mempool::default();
        for transaction in [
            create.clone(),
            stale,
            valid_now.clone(),
            future_valid.clone(),
            unauthorized,
        ] {
            mempool.push(transaction);
        }

        assert_eq!(mempool.remove_finalized_and_invalid(&[create], &ledger), 3);
        assert_eq!(mempool.snapshot(10), vec![valid_now, future_valid]);
    }
}
