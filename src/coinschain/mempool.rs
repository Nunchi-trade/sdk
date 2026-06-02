use crate::coins::{
    AccountId, CoinOperation, Ledger, TokenFactory, Transaction, MAX_NAME_BYTES, MAX_SYMBOL_BYTES,
};
use commonware_codec::EncodeSize;
use commonware_cryptography::sha256::Digest;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex},
};

const VALID_SIGNATURE_CACHE_CAPACITY: usize = 250_000;

#[derive(Clone, Debug, Default)]
pub struct Mempool {
    inner: Arc<Mutex<MempoolInner>>,
}

#[derive(Debug, Default)]
struct MempoolInner {
    signer_order: VecDeque<AccountId>,
    pending: BTreeMap<AccountId, BTreeMap<u64, VecDeque<CachedTransaction>>>,
    valid_signatures: BTreeSet<Digest>,
    signature_order: VecDeque<Digest>,
    len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedTransaction {
    transaction: Transaction,
    digest: Digest,
    encoded_size: usize,
    signature_valid: bool,
    stateless_valid: bool,
}

impl CachedTransaction {
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub fn into_transaction(self) -> Transaction {
        self.transaction
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn encoded_size(&self) -> usize {
        self.encoded_size
    }

    pub fn signature_valid(&self) -> bool {
        self.signature_valid
    }

    pub fn stateless_valid(&self) -> bool {
        self.stateless_valid
    }
}

impl Mempool {
    pub fn push(&self, transaction: Transaction) {
        self.extend([transaction]);
    }

    pub fn extend(&self, transactions: impl IntoIterator<Item = Transaction>) -> usize {
        let mut inner = self.inner.lock().expect("mempool lock poisoned");
        for transaction in transactions {
            inner.push(transaction, None);
        }
        inner.len
    }

    pub fn push_verified(&self, transaction: Transaction) -> usize {
        self.extend_verified([transaction])
    }

    pub fn extend_verified(&self, transactions: impl IntoIterator<Item = Transaction>) -> usize {
        let mut inner = self.inner.lock().expect("mempool lock poisoned");
        for transaction in transactions {
            inner.push(transaction, Some(true));
        }
        inner.len
    }

    pub fn snapshot(&self, ledger: &Ledger, max: usize) -> Vec<CachedTransaction> {
        if max == 0 {
            return Vec::new();
        }

        let inner = self.inner.lock().expect("mempool lock poisoned");
        let mut next_nonces = inner
            .signer_order
            .iter()
            .map(|signer| (signer.clone(), ledger.nonce(signer)))
            .collect::<BTreeMap<_, _>>();
        let mut selected = Vec::with_capacity(max.min(inner.len));

        loop {
            let mut progressed = false;
            for signer in &inner.signer_order {
                if selected.len() == max {
                    return selected;
                }
                let expected = next_nonces
                    .get(signer)
                    .copied()
                    .unwrap_or_else(|| ledger.nonce(signer));
                let Some(by_nonce) = inner.pending.get(signer) else {
                    continue;
                };
                let Some(transactions) = by_nonce.get(&expected) else {
                    continue;
                };
                if transactions.is_empty() {
                    continue;
                }

                progressed = true;
                for transaction in transactions {
                    if selected.len() == max {
                        return selected;
                    }
                    selected.push(transaction.clone());
                }
                next_nonces.insert(signer.clone(), expected.saturating_add(1));
            }

            if !progressed {
                return selected;
            }
        }
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
        let mut empty_signers = BTreeSet::new();
        for (signer, by_nonce) in &mut inner.pending {
            let mut empty_nonces = Vec::new();
            for (nonce, transactions) in by_nonce.iter_mut() {
                transactions.retain(|transaction| {
                    let remove = finalized.contains(&transaction.digest)
                        || is_stale_or_permanently_invalid(transaction, ledger);
                    if remove {
                        removed += 1;
                    }
                    !remove
                });
                if transactions.is_empty() {
                    empty_nonces.push(*nonce);
                }
            }
            for nonce in empty_nonces {
                by_nonce.remove(&nonce);
            }
            if by_nonce.is_empty() {
                empty_signers.insert(signer.clone());
            }
        }
        for signer in &empty_signers {
            inner.pending.remove(signer);
        }
        inner
            .signer_order
            .retain(|signer| !empty_signers.contains(signer));
        inner.len = inner.len.saturating_sub(removed);
        removed
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("mempool lock poisoned").len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn has_valid_signature(&self, digest: &Digest) -> bool {
        self.inner
            .lock()
            .expect("mempool lock poisoned")
            .valid_signatures
            .contains(digest)
    }
}

impl MempoolInner {
    fn push(&mut self, transaction: Transaction, signature_valid: Option<bool>) {
        let cached = CachedTransaction::new(transaction, signature_valid);
        if cached.signature_valid {
            self.insert_valid_signature(cached.digest);
        }

        let signer = cached.transaction.signer.clone();
        let nonce = cached.transaction.payload.nonce;
        if !self.pending.contains_key(&signer) {
            self.signer_order.push_back(signer.clone());
        }
        self.pending
            .entry(signer)
            .or_default()
            .entry(nonce)
            .or_default()
            .push_back(cached);
        self.len += 1;
    }

    fn insert_valid_signature(&mut self, digest: Digest) {
        if !self.valid_signatures.insert(digest) {
            return;
        }
        self.signature_order.push_back(digest);
        while self.valid_signatures.len() > VALID_SIGNATURE_CACHE_CAPACITY {
            let Some(oldest) = self.signature_order.pop_front() else {
                break;
            };
            self.valid_signatures.remove(&oldest);
        }
    }
}

impl CachedTransaction {
    fn new(transaction: Transaction, signature_valid: Option<bool>) -> Self {
        let digest = transaction.digest();
        let encoded_size = transaction.encode_size();
        let signature_valid = signature_valid.unwrap_or_else(|| transaction.verify());
        let stateless_valid = signature_valid && is_stateless_valid(&transaction);
        Self {
            transaction,
            digest,
            encoded_size,
            signature_valid,
            stateless_valid,
        }
    }
}

fn is_stale_or_permanently_invalid(transaction: &CachedTransaction, ledger: &Ledger) -> bool {
    if !transaction.signature_valid || !transaction.stateless_valid {
        return true;
    }

    let expected = ledger.nonce(&transaction.transaction.signer);
    if transaction.transaction.payload.nonce < expected {
        return true;
    }
    if transaction.transaction.payload.nonce > expected {
        return false;
    }

    match &transaction.transaction.payload.operation {
        CoinOperation::CreateToken { spec } => {
            let coin = TokenFactory::derive_coin_id(
                &transaction.transaction.signer,
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
                .is_some_and(|token| token.issuer != transaction.transaction.signer)
        }
        CoinOperation::Burn { .. } | CoinOperation::Transfer { .. } => false,
    }
}

fn is_stateless_valid(transaction: &Transaction) -> bool {
    match &transaction.payload.operation {
        CoinOperation::CreateToken { spec } => {
            !spec.symbol.is_empty()
                && spec.symbol.len() <= MAX_SYMBOL_BYTES
                && !spec.name.is_empty()
                && spec.name.len() <= MAX_NAME_BYTES
                && !spec
                    .max_supply
                    .is_some_and(|max_supply| spec.initial_supply > max_supply)
        }
        CoinOperation::Mint { amount, .. } => *amount > 0,
        CoinOperation::Burn { from, amount, .. } | CoinOperation::Transfer { from, amount, .. } => {
            *amount > 0 && from == &transaction.signer
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

        let ledger = Ledger::default();
        assert_eq!(
            mempool
                .snapshot(&ledger, 1)
                .into_iter()
                .map(CachedTransaction::into_transaction)
                .collect::<Vec<_>>(),
            vec![first.clone()]
        );
        assert_eq!(mempool.len(), 2);
        assert_eq!(
            mempool
                .snapshot(&ledger, 10)
                .into_iter()
                .map(CachedTransaction::into_transaction)
                .collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn snapshot_orders_transactions_by_executable_nonce() {
        let issuer = PrivateKey::from_seed(2);
        let issuer_id = issuer.public_key();
        let spec = CoinSpec::new("OOO", "Out Of Order Coin", 0, 10, Some(10));
        let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);
        let future = Transaction::sign(
            &issuer,
            1,
            CoinOperation::Transfer {
                coin,
                from: issuer_id.clone(),
                to: issuer_id.clone(),
                amount: 1,
            },
        );
        let current = Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken { spec: spec.clone() },
        );
        let mempool = Mempool::default();
        mempool.push(future.clone());
        mempool.push(current.clone());

        let ledger = Ledger::default();
        assert_eq!(
            mempool
                .snapshot(&ledger, 10)
                .into_iter()
                .map(CachedTransaction::into_transaction)
                .collect::<Vec<_>>(),
            vec![current, future]
        );
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
        assert_eq!(
            mempool
                .snapshot(&ledger, 10)
                .into_iter()
                .map(CachedTransaction::into_transaction)
                .collect::<Vec<_>>(),
            vec![valid_now, future_valid]
        );
    }

    #[test]
    fn push_verified_caches_signature_digest() {
        let issuer = PrivateKey::from_seed(13);
        let transaction = Transaction::sign(
            &issuer,
            0,
            CoinOperation::CreateToken {
                spec: CoinSpec::new("SIG", "Signature Cache Coin", 0, 1, Some(1)),
            },
        );
        let digest = transaction.digest();
        let mempool = Mempool::default();
        mempool.push_verified(transaction);
        assert!(mempool.has_valid_signature(&digest));
    }
}
