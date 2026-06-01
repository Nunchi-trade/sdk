use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::types::Height;
use commonware_cryptography::{Digestible, Signer};
use nunchi_sdk::{
    coins::{CoinOperation, CoinSpec, LedgerError, PrivateKey, TokenFactory, Transaction},
    Block, Chain, ChainError,
};

#[test]
fn creates_token_and_transfers_across_blocks() {
    let issuer = PrivateKey::from_seed(7);
    let alice = PrivateKey::from_seed(9);
    let issuer_id = issuer.public_key();
    let alice_id = alice.public_key();

    let spec = CoinSpec::new("NCHI", "Nunchi", 6, 1_000, Some(5_000));
    let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);

    let mut chain = Chain::genesis();
    let create = Transaction::sign(
        &issuer,
        0,
        CoinOperation::CreateToken { spec: spec.clone() },
    );
    assert!(create.verify());

    let block1 = chain.append_block(vec![create], 1).unwrap().clone();
    assert_eq!(block1.height, Height::new(1));
    assert_eq!(chain.ledger().balance(&issuer_id, &coin), 1_000);
    assert_eq!(chain.ledger().nonce(&issuer_id), 1);

    let transfer = Transaction::sign(
        &issuer,
        1,
        CoinOperation::Transfer {
            coin,
            from: issuer_id.clone(),
            to: alice_id.clone(),
            amount: 250,
        },
    );
    let block2 = chain.append_block(vec![transfer], 2).unwrap().clone();

    assert_eq!(block2.height, Height::new(2));
    assert_eq!(block2.parent, block1.digest());
    assert_eq!(chain.ledger().balance(&issuer_id, &coin), 750);
    assert_eq!(chain.ledger().balance(&alice_id, &coin), 250);
    assert_ne!(block1.state_root, block2.state_root);
}

#[test]
fn rejects_unauthorized_mint_and_preserves_tip() {
    let issuer = PrivateKey::from_seed(11);
    let outsider = PrivateKey::from_seed(12);
    let issuer_id = issuer.public_key();
    let outsider_id = outsider.public_key();

    let spec = CoinSpec::new("LOCAL", "Local Coin", 2, 100, Some(1_000));
    let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);

    let mut chain = Chain::genesis();
    let create = Transaction::sign(&issuer, 0, CoinOperation::CreateToken { spec });
    chain.append_block(vec![create], 1).unwrap();

    let mint = Transaction::sign(
        &outsider,
        0,
        CoinOperation::Mint {
            coin,
            to: outsider_id,
            amount: 50,
        },
    );
    let err = chain.append_block(vec![mint], 2).unwrap_err();

    assert!(matches!(err, ChainError::Ledger(LedgerError::Unauthorized)));
    assert_eq!(chain.tip().height, Height::new(1));
    assert_eq!(chain.ledger().balance(&issuer_id, &coin), 100);
}

#[test]
fn rejects_tampered_transaction_signature() {
    let issuer = PrivateKey::from_seed(13);
    let issuer_id = issuer.public_key();
    let spec = CoinSpec::new("BAD", "Bad Signature", 0, 1, Some(1));
    let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);

    let mut tx = Transaction::sign(&issuer, 0, CoinOperation::CreateToken { spec });
    tx.payload.operation = CoinOperation::Mint {
        coin,
        to: issuer_id,
        amount: 1,
    };
    assert!(!tx.verify());

    let mut chain = Chain::genesis();
    let err = chain.append_block(vec![tx], 1).unwrap_err();
    assert!(matches!(err, ChainError::Ledger(LedgerError::BadSignature)));
    assert_eq!(chain.tip().height, Height::zero());
}

#[test]
fn rejects_replayed_nonce() {
    let issuer = PrivateKey::from_seed(21);
    let issuer_id = issuer.public_key();
    let spec = CoinSpec::new("RPLY", "Replay Coin", 0, 10, Some(10));

    let mut chain = Chain::genesis();
    let create = Transaction::sign(
        &issuer,
        0,
        CoinOperation::CreateToken { spec: spec.clone() },
    );
    chain.append_block(vec![create], 1).unwrap();

    let replay = Transaction::sign(&issuer, 0, CoinOperation::CreateToken { spec });
    let err = chain.append_block(vec![replay], 2).unwrap_err();

    assert!(matches!(
        err,
        ChainError::Ledger(LedgerError::NonceMismatch {
            account,
            expected: 1,
            actual: 0
        }) if account == issuer_id
    ));
}

#[test]
fn commonware_codec_round_trips_transactions_and_blocks() {
    let issuer = PrivateKey::from_seed(31);
    let issuer_id = issuer.public_key();
    let spec = CoinSpec::new("CODEC", "Codec Coin", 8, 42, Some(100));
    let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);

    let tx = Transaction::sign(&issuer, 0, CoinOperation::CreateToken { spec });
    let decoded_tx = Transaction::decode(tx.encode()).unwrap();
    assert_eq!(tx, decoded_tx);
    assert_eq!(tx.digest(), decoded_tx.digest());

    let mut chain = Chain::genesis();
    chain.append_block(vec![tx], 1).unwrap();
    assert_eq!(chain.ledger().balance(&issuer_id, &coin), 42);

    let block = chain.tip().clone();
    let decoded_block = Block::decode(block.encode()).unwrap();
    assert_eq!(block, decoded_block);
    assert_eq!(block.digest(), decoded_block.digest());
}
