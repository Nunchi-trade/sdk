use crate::coins::{Ledger, LedgerError, Transaction};
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
            .collect::<Vec<_>>();
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

    let mut ledger = ledger.clone();
    match ledger.apply_transaction(transaction) {
        Ok(()) => false,
        Err(LedgerError::BadSignature)
        | Err(LedgerError::InvalidTokenSpec(_))
        | Err(LedgerError::InvalidAmount)
        | Err(LedgerError::DuplicateToken(_))
        | Err(LedgerError::Unauthorized) => true,
        Err(LedgerError::NonceMismatch { actual, .. }) => actual < expected,
        Err(LedgerError::NonceOverflow)
        | Err(LedgerError::UnknownToken(_))
        | Err(LedgerError::InsufficientBalance { .. })
        | Err(LedgerError::BalanceOverflow)
        | Err(LedgerError::SupplyOverflow)
        | Err(LedgerError::MaxSupplyExceeded { .. }) => false,
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
