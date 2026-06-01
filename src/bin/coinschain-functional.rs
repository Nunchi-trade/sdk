use clap::Parser;
use commonware_codec::Encode;
use commonware_cryptography::Signer;
use commonware_formatting::hex;
use nunchi_sdk::coins::{
    AccountId, CoinId, CoinOperation, CoinSpec, PrivateKey, TokenFactory, Transaction,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:18545")]
    url: String,
    #[arg(long, default_value_t = 60)]
    timeout_secs: u64,
    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SubmitTransaction<'a> {
    transaction: &'a str,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResponse {
    accepted: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct StatusResponse {
    height: u64,
    state_root: String,
    token_factory_nonce: u64,
    mempool_len: usize,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    nonce: u64,
}

#[derive(Debug, Deserialize)]
struct CoinResponse {
    total_supply: u128,
}

#[derive(Debug, Deserialize)]
struct BalanceResponse {
    balance: u128,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let client = Client::new();
    let base = args.url.trim_end_matches('/').to_string();
    let seed = args.seed.unwrap_or_else(default_seed);

    let issuer = PrivateKey::from_seed(seed);
    let alice = PrivateKey::from_seed(seed.wrapping_add(1));
    let bob = PrivateKey::from_seed(seed.wrapping_add(2));
    let outsider = PrivateKey::from_seed(seed.wrapping_add(3));
    let issuer_id = issuer.public_key();
    let alice_id = alice.public_key();
    let bob_id = bob.public_key();
    let outsider_id = outsider.public_key();

    let start = status(&client, &base).await;
    let mut issuer_nonce = account(&client, &base, &issuer_id).await.nonce;
    let mut alice_nonce = account(&client, &base, &alice_id).await.nonce;
    let mut bob_nonce = account(&client, &base, &bob_id).await.nonce;
    let outsider_nonce = account(&client, &base, &outsider_id).await.nonce;
    let spec = CoinSpec::new(
        format!("FN{:08X}", seed as u32),
        format!("Functional Test Coin {seed}"),
        2,
        100,
        Some(200),
    );
    let coin_id = TokenFactory::derive_coin_id(&issuer_id, start.token_factory_nonce, &spec);

    submit(
        &client,
        &base,
        &Transaction::sign(&issuer, issuer_nonce, CoinOperation::CreateToken { spec }),
    )
    .await;
    issuer_nonce += 1;
    let after_create = wait_for_state_change(&client, &base, &start, args.timeout_secs).await;
    assert_eq!(coin(&client, &base, coin_id).await.total_supply, 100);
    assert_eq!(
        balance(&client, &base, coin_id, &issuer_id).await.balance,
        100
    );
    assert_eq!(
        account(&client, &base, &issuer_id).await.nonce,
        issuer_nonce
    );

    submit(
        &client,
        &base,
        &Transaction::sign(
            &issuer,
            issuer_nonce,
            CoinOperation::Mint {
                coin: coin_id,
                to: alice_id.clone(),
                amount: 50,
            },
        ),
    )
    .await;
    issuer_nonce += 1;
    let after_mint = wait_for_state_change(&client, &base, &after_create, args.timeout_secs).await;
    assert_eq!(coin(&client, &base, coin_id).await.total_supply, 150);
    assert_eq!(
        balance(&client, &base, coin_id, &alice_id).await.balance,
        50
    );
    assert_eq!(
        account(&client, &base, &issuer_id).await.nonce,
        issuer_nonce
    );

    submit(
        &client,
        &base,
        &Transaction::sign(
            &alice,
            alice_nonce,
            CoinOperation::Transfer {
                coin: coin_id,
                from: alice_id.clone(),
                to: bob_id.clone(),
                amount: 20,
            },
        ),
    )
    .await;
    alice_nonce += 1;
    let after_transfer =
        wait_for_state_change(&client, &base, &after_mint, args.timeout_secs).await;
    assert_eq!(
        balance(&client, &base, coin_id, &alice_id).await.balance,
        30
    );
    assert_eq!(balance(&client, &base, coin_id, &bob_id).await.balance, 20);
    assert_eq!(account(&client, &base, &alice_id).await.nonce, alice_nonce);

    submit(
        &client,
        &base,
        &Transaction::sign(
            &bob,
            bob_nonce,
            CoinOperation::Burn {
                coin: coin_id,
                from: bob_id.clone(),
                amount: 10,
            },
        ),
    )
    .await;
    bob_nonce += 1;
    let after_burn =
        wait_for_state_change(&client, &base, &after_transfer, args.timeout_secs).await;
    assert_eq!(coin(&client, &base, coin_id).await.total_supply, 140);
    assert_eq!(balance(&client, &base, coin_id, &bob_id).await.balance, 10);
    assert_eq!(account(&client, &base, &bob_id).await.nonce, bob_nonce);

    submit(
        &client,
        &base,
        &Transaction::sign(
            &outsider,
            outsider_nonce,
            CoinOperation::Mint {
                coin: coin_id,
                to: outsider_id.clone(),
                amount: 25,
            },
        ),
    )
    .await;
    let after_invalid =
        wait_for_mempool_at_height(&client, &base, after_burn.height, args.timeout_secs).await;
    assert_eq!(
        after_invalid.state_root, after_burn.state_root,
        "unauthorized mint changed state"
    );
    assert_eq!(coin(&client, &base, coin_id).await.total_supply, 140);
    assert_eq!(
        balance(&client, &base, coin_id, &outsider_id).await.balance,
        0
    );
    assert_eq!(
        account(&client, &base, &outsider_id).await.nonce,
        outsider_nonce
    );

    println!(
        "seed={} coin={} create_height={} mint_height={} transfer_height={} burn_height={} invalid_checked_height={} final_state_root={}",
        seed,
        coin_id.digest(),
        after_create.height,
        after_mint.height,
        after_transfer.height,
        after_burn.height,
        after_invalid.height,
        after_invalid.state_root
    );
}

fn default_seed() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before unix epoch");
    now.as_secs() ^ u64::from(now.subsec_nanos()).rotate_left(32)
}

async fn submit(client: &Client, base: &str, transaction: &Transaction) {
    let encoded = hex(&transaction.encode());
    let response = client
        .post(format!("{base}/tx"))
        .json(&SubmitTransaction {
            transaction: &encoded,
        })
        .send()
        .await
        .expect("failed to submit transaction");
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        panic!("transaction rejected: {status} {body}");
    }
    let accepted: SubmitTransactionResponse = response
        .json()
        .await
        .expect("failed to decode submit response");
    assert!(accepted.accepted);
}

async fn status(client: &Client, base: &str) -> StatusResponse {
    client
        .get(format!("{base}/status"))
        .send()
        .await
        .expect("failed to fetch status")
        .error_for_status()
        .expect("status endpoint returned error")
        .json()
        .await
        .expect("failed to decode status")
}

async fn account(client: &Client, base: &str, account: &AccountId) -> AccountResponse {
    client
        .get(format!("{base}/accounts/{account}"))
        .send()
        .await
        .expect("failed to fetch account")
        .error_for_status()
        .expect("account endpoint returned error")
        .json()
        .await
        .expect("failed to decode account")
}

async fn coin(client: &Client, base: &str, coin: CoinId) -> CoinResponse {
    client
        .get(format!("{base}/coins/{}", coin.digest()))
        .send()
        .await
        .expect("failed to fetch coin")
        .error_for_status()
        .expect("coin endpoint returned error")
        .json()
        .await
        .expect("failed to decode coin")
}

async fn balance(
    client: &Client,
    base: &str,
    coin: CoinId,
    account: &AccountId,
) -> BalanceResponse {
    client
        .get(format!("{base}/coins/{}/balances/{account}", coin.digest()))
        .send()
        .await
        .expect("failed to fetch balance")
        .error_for_status()
        .expect("balance endpoint returned error")
        .json()
        .await
        .expect("failed to decode balance")
}

async fn wait_for_state_change(
    client: &Client,
    base: &str,
    previous: &StatusResponse,
    timeout_secs: u64,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let status = status(client, base).await;
        if status.mempool_len == 0
            && status.height > previous.height
            && status.state_root != previous.state_root
        {
            return status;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for state change, height={}, previous_height={}, remaining_mempool={}",
                status.height, previous.height, status.mempool_len
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_mempool_at_height(
    client: &Client,
    base: &str,
    min_height: u64,
    timeout_secs: u64,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let status = status(client, base).await;
        if status.mempool_len == 0 && status.height > min_height {
            return status;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for mempool drain, height={}, minimum_height={}, remaining_mempool={}",
                status.height, min_height, status.mempool_len
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
