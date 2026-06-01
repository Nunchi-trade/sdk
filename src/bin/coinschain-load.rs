use clap::Parser;
use commonware_codec::Encode;
use commonware_cryptography::Signer;
use commonware_formatting::hex;
use nunchi_sdk::coins::{CoinOperation, CoinSpec, PrivateKey, TokenFactory, Transaction};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:18545")]
    url: String,
    #[arg(long, default_value_t = 1000)]
    transactions: u64,
    #[arg(long, default_value_t = 16)]
    accounts: u64,
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
    #[arg(long)]
    issuer_seed: Option<u64>,
}

#[derive(Debug, Serialize)]
struct SubmitTransaction<'a> {
    transaction: &'a str,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResponse {
    accepted: bool,
}

#[derive(Debug, Deserialize)]
struct StatusResponse {
    height: u64,
    state_root: String,
    mempool_len: usize,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    assert!(
        args.transactions > 0,
        "transactions must be greater than zero"
    );
    assert!(args.accounts > 0, "accounts must be greater than zero");

    let client = Client::new();
    let base = args.url.trim_end_matches('/').to_string();
    let issuer_seed = args.issuer_seed.unwrap_or_else(default_issuer_seed);
    let issuer = PrivateKey::from_seed(issuer_seed);
    let issuer_id = issuer.public_key();
    let spec = CoinSpec::new(
        format!("LD{issuer_seed:x}"),
        format!("Load Test Coin {issuer_seed}"),
        0,
        args.transactions as u128,
        Some(args.transactions as u128),
    );
    let coin = TokenFactory::derive_coin_id(&issuer_id, 0, &spec);

    let start_status = status(&client, &base).await;
    let create = Transaction::sign(&issuer, 0, CoinOperation::CreateToken { spec });
    submit(&client, &base, &create).await;
    wait_for_progress(&client, &base, start_status.height, args.timeout_secs).await;

    let batch_start = status(&client, &base).await;
    let started = Instant::now();
    for nonce in 1..=args.transactions {
        let recipient =
            PrivateKey::from_seed(issuer_seed.wrapping_add(20_000 + (nonce % args.accounts)))
                .public_key();
        let tx = Transaction::sign(
            &issuer,
            nonce,
            CoinOperation::Transfer {
                coin,
                from: issuer_id.clone(),
                to: recipient,
                amount: 1,
            },
        );
        submit(&client, &base, &tx).await;
    }

    wait_for_progress(&client, &base, batch_start.height, args.timeout_secs).await;
    let elapsed = started.elapsed();
    let final_status = status(&client, &base).await;
    assert_ne!(
        start_status.state_root, final_status.state_root,
        "load test did not change the coinschain state root"
    );
    let tps = args.transactions as f64 / elapsed.as_secs_f64();
    println!(
        "issuer_seed={} submitted={} elapsed_ms={} submit_to_empty_tps={:.2} start_height={} final_height={} start_state_root={} final_state_root={}",
        issuer_seed,
        args.transactions,
        elapsed.as_millis(),
        tps,
        start_status.height,
        final_status.height,
        start_status.state_root,
        final_status.state_root
    );
}

fn default_issuer_seed() -> u64 {
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

async fn wait_for_progress(client: &Client, base: &str, min_height: u64, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let status = status(client, base).await;
        if status.mempool_len == 0 && status.height > min_height {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for load progress, height={}, minimum_height={}, remaining_mempool={}",
                status.height, min_height, status.mempool_len
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
