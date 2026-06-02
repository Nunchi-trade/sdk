use clap::Parser;
use commonware_codec::Encode;
use commonware_cryptography::Signer;
use commonware_formatting::hex;
use futures::{
    future::join_all,
    stream::{FuturesUnordered, StreamExt},
};
use nunchi_sdk::coins::{
    AccountId, CoinId, CoinOperation, CoinSpec, PrivateKey, TokenFactory, Transaction,
};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Parser)]
struct Args {
    #[arg(
        long = "url",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:18545"
    )]
    urls: Vec<String>,
    #[arg(long, default_value_t = 1000)]
    transactions: u64,
    #[arg(long, default_value_t = 16)]
    accounts: u64,
    #[arg(long, default_value_t = 4)]
    tokens: u64,
    #[arg(long, default_value_t = 2)]
    issuers: u64,
    #[arg(long, default_value_t = 5)]
    max_transfer_amount: u128,
    #[arg(long, default_value_t = 600)]
    timeout_secs: u64,
    #[arg(long, default_value_t = 512)]
    batch_size: usize,
    #[arg(long, default_value_t = 16)]
    in_flight: usize,
    #[arg(long, default_value_t = 100_000)]
    progress_every: u64,
    #[arg(long)]
    issuer_seed: Option<u64>,
}

#[derive(Clone, Debug)]
struct RpcEndpoints {
    bases: Vec<String>,
}

impl RpcEndpoints {
    fn new(urls: Vec<String>) -> Self {
        let mut bases = Vec::new();
        for url in urls {
            let base = url.trim().trim_end_matches('/');
            if !base.is_empty()
                && !bases
                    .iter()
                    .any(|existing: &String| existing.as_str() == base)
            {
                bases.push(base.to_string());
            }
        }
        assert!(!bases.is_empty(), "at least one --url must be provided");
        Self { bases }
    }

    fn len(&self) -> usize {
        self.bases.len()
    }
}

#[derive(Clone)]
struct TokenPlan {
    issuer_index: usize,
    spec: CoinSpec,
    coin: CoinId,
    initial_supply: u128,
}

#[derive(Debug, Serialize)]
struct SubmitTransactions<'a> {
    transactions: &'a [String],
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionsResponse {
    accepted: bool,
    accepted_count: usize,
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
    assert!(
        args.transactions > 0,
        "transactions must be greater than zero"
    );
    assert!(args.accounts > 0, "accounts must be greater than zero");
    assert!(args.tokens > 0, "tokens must be greater than zero");
    assert!(args.issuers > 0, "issuers must be greater than zero");
    assert!(
        args.max_transfer_amount > 0,
        "max_transfer_amount must be greater than zero"
    );
    assert!(args.batch_size > 0, "batch_size must be greater than zero");
    assert!(args.in_flight > 0, "in_flight must be greater than zero");

    let client = Client::new();
    let endpoints = RpcEndpoints::new(args.urls);
    let issuer_seed = args.issuer_seed.unwrap_or_else(default_issuer_seed);
    let issuers = (0..args.issuers)
        .map(|index| PrivateKey::from_seed(issuer_seed.wrapping_add(index)))
        .collect::<Vec<_>>();
    let issuer_ids = issuers
        .iter()
        .map(PrivateKey::public_key)
        .collect::<Vec<_>>();
    let recipients = (0..args.accounts)
        .map(|index| PrivateKey::from_seed(issuer_seed.wrapping_add(100_000 + index)))
        .map(|key| key.public_key())
        .collect::<Vec<_>>();

    let (read_base, start_status) = status(&client, &endpoints).await;
    let initial_supply = u128::from(args.transactions)
        .checked_mul(args.max_transfer_amount)
        .and_then(|supply| supply.checked_add(args.max_transfer_amount))
        .expect("initial supply overflowed");
    let token_plans = (0..args.tokens)
        .map(|token_index| {
            let issuer_index = (token_index % args.issuers) as usize;
            let spec = CoinSpec::new(
                format!("LD{token_index:04X}"),
                format!("Load Test Coin {token_index}"),
                0,
                initial_supply,
                Some(initial_supply),
            );
            let coin = TokenFactory::derive_coin_id(
                &issuer_ids[issuer_index],
                start_status.token_factory_nonce + token_index,
                &spec,
            );
            TokenPlan {
                issuer_index,
                spec,
                coin,
                initial_supply,
            }
        })
        .collect::<Vec<_>>();

    let mut issuer_nonces = Vec::with_capacity(issuer_ids.len());
    for issuer_id in &issuer_ids {
        issuer_nonces.push(account(&client, &read_base, issuer_id).await.nonce);
    }
    let mut create_transactions = Vec::with_capacity(token_plans.len());
    for token in &token_plans {
        let issuer = &issuers[token.issuer_index];
        let nonce = issuer_nonces[token.issuer_index];
        issuer_nonces[token.issuer_index] += 1;
        create_transactions.push(Transaction::sign(
            issuer,
            nonce,
            CoinOperation::CreateToken {
                spec: token.spec.clone(),
            },
        ));
    }
    let create_in_flight = 1;
    submit_transaction_batches(
        &client,
        &endpoints,
        create_transactions,
        args.batch_size,
        create_in_flight,
    )
    .await;
    println!(
        "submitted_token_creates={} batch_size={} in_flight={}",
        token_plans.len(),
        args.batch_size,
        create_in_flight
    );

    let batch_start = wait_for_created_tokens(
        &client,
        &endpoints,
        &token_plans,
        &issuer_ids,
        &issuer_nonces,
        start_status.height,
        args.timeout_secs,
    )
    .await;

    let mut issuer_balances = token_plans
        .iter()
        .map(|token| (token.coin, token.initial_supply))
        .collect::<BTreeMap<_, _>>();
    let mut recipient_balances = BTreeMap::<(AccountId, CoinId), u128>::new();

    let started = Instant::now();
    let mut pending = FuturesUnordered::new();
    let mut batch = Vec::with_capacity(args.batch_size);
    let mut dispatched = 0u64;
    let mut next_progress = args.progress_every;
    for transfer_index in 0..args.transactions {
        let token = &token_plans[(transfer_index % args.tokens) as usize];
        let issuer = &issuers[token.issuer_index];
        let issuer_id = &issuer_ids[token.issuer_index];
        let nonce = issuer_nonces[token.issuer_index];
        issuer_nonces[token.issuer_index] += 1;
        let recipient = recipients[(transfer_index % args.accounts) as usize].clone();
        let amount = 1 + u128::from(transfer_index) % args.max_transfer_amount;

        *issuer_balances
            .get_mut(&token.coin)
            .expect("token balance missing") -= amount;
        *recipient_balances
            .entry((recipient.clone(), token.coin))
            .or_default() += amount;

        batch.push(Transaction::sign(
            issuer,
            nonce,
            CoinOperation::Transfer {
                coin: token.coin,
                from: issuer_id.clone(),
                to: recipient,
                amount,
            },
        ));

        if batch.len() == args.batch_size {
            while pending.len() >= args.in_flight {
                pending.next().await.expect("pending batch missing");
            }
            dispatched += batch.len() as u64;
            pending.push(submit_batch(
                client.clone(),
                endpoints.clone(),
                std::mem::take(&mut batch),
            ));
            batch = Vec::with_capacity(args.batch_size);
            if args.progress_every > 0 && dispatched >= next_progress {
                println!(
                    "submitted_transfers={} elapsed_ms={} pending_batches={}",
                    dispatched,
                    started.elapsed().as_millis(),
                    pending.len()
                );
                next_progress = next_progress.saturating_add(args.progress_every);
            }
        }
    }
    if !batch.is_empty() {
        while pending.len() >= args.in_flight {
            pending.next().await.expect("pending batch missing");
        }
        dispatched += batch.len() as u64;
        pending.push(submit_batch(client.clone(), endpoints.clone(), batch));
    }
    while pending.next().await.is_some() {}
    println!(
        "submitted_transfer_dispatch_complete={} elapsed_ms={}",
        dispatched,
        started.elapsed().as_millis()
    );

    let final_status = wait_for_transfer_state(
        &client,
        &endpoints,
        &token_plans,
        &issuer_ids,
        &issuer_nonces,
        &issuer_balances,
        &recipient_balances,
        batch_start.height,
        args.timeout_secs,
    )
    .await;
    let elapsed = started.elapsed();
    assert_ne!(
        start_status.state_root, final_status.state_root,
        "load test did not change the coinschain state root"
    );

    let tps = args.transactions as f64 / elapsed.as_secs_f64();
    println!(
        "issuer_seed={} submit_endpoints={} batch_size={} in_flight={} tokens={} issuers={} accounts={} submitted_transfers={} elapsed_ms={} submit_to_verified_tps={:.2} start_height={} final_height={} verified_balances={} start_state_root={} final_state_root={}",
        issuer_seed,
        endpoints.len(),
        args.batch_size,
        args.in_flight,
        args.tokens,
        args.issuers,
        args.accounts,
        args.transactions,
        elapsed.as_millis(),
        tps,
        start_status.height,
        final_status.height,
        token_plans.len() + recipient_balances.len() + issuer_ids.len(),
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

async fn submit_transaction_batches(
    client: &Client,
    endpoints: &RpcEndpoints,
    transactions: Vec<Transaction>,
    batch_size: usize,
    in_flight: usize,
) {
    let mut pending = FuturesUnordered::new();
    for batch in transactions.chunks(batch_size) {
        while pending.len() >= in_flight {
            pending.next().await.expect("pending batch missing");
        }
        pending.push(submit_batch(
            client.clone(),
            endpoints.clone(),
            batch.to_vec(),
        ));
    }
    while pending.next().await.is_some() {}
}

async fn submit_batch(client: Client, endpoints: RpcEndpoints, transactions: Vec<Transaction>) {
    if transactions.is_empty() {
        return;
    }

    let encoded = transactions
        .iter()
        .map(|transaction| hex(&transaction.encode()))
        .collect::<Vec<_>>();
    let results = join_all(
        endpoints
            .bases
            .iter()
            .map(|base| submit_encoded_batch(&client, base, &encoded)),
    )
    .await;
    if results.iter().all(Result::is_ok) {
        return;
    }

    let errors = results
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>()
        .join("; ");
    panic!("transaction batch was not accepted by all endpoints: {errors}");
}

async fn submit_encoded_batch(
    client: &Client,
    base: &str,
    encoded: &[String],
) -> Result<(), String> {
    let response = client
        .post(format!("{base}/txs"))
        .json(&SubmitTransactions {
            transactions: encoded,
        })
        .send()
        .await
        .map_err(|error| format!("{base}: failed to submit transaction batch: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "{base}: transaction batch rejected: {status} {body}"
        ));
    }
    let accepted: SubmitTransactionsResponse = response
        .json()
        .await
        .map_err(|error| format!("{base}: failed to decode submit batch response: {error}"))?;
    if !accepted.accepted || accepted.accepted_count != encoded.len() {
        return Err(format!(
            "{base}: transaction batch accepted_count mismatch: actual={} expected={}",
            accepted.accepted_count,
            encoded.len()
        ));
    }
    Ok(())
}

async fn status(client: &Client, endpoints: &RpcEndpoints) -> (String, StatusResponse) {
    let mut errors = Vec::new();
    for base in &endpoints.bases {
        match try_status(client, base).await {
            Ok(status) => return (base.clone(), status),
            Err(error) => errors.push(error),
        }
    }
    panic!(
        "failed to fetch status from all endpoints: {}",
        errors.join("; ")
    );
}

async fn try_status(client: &Client, base: &str) -> Result<StatusResponse, String> {
    get_json(client, format!("{base}/status")).await
}

async fn account(client: &Client, base: &str, account: &AccountId) -> AccountResponse {
    try_account(client, base, account)
        .await
        .unwrap_or_else(|error| panic!("failed to fetch account {account}: {error}"))
}

async fn try_account(
    client: &Client,
    base: &str,
    account: &AccountId,
) -> Result<AccountResponse, String> {
    get_json(client, format!("{base}/accounts/{account}")).await
}

async fn try_coin(client: &Client, base: &str, coin: CoinId) -> Result<CoinResponse, String> {
    get_json(client, format!("{base}/coins/{}", coin.digest())).await
}

async fn try_balance(
    client: &Client,
    base: &str,
    coin: CoinId,
    account: &AccountId,
) -> Result<BalanceResponse, String> {
    get_json(
        client,
        format!("{base}/coins/{}/balances/{account}", coin.digest()),
    )
    .await
}

async fn get_json<T: DeserializeOwned>(client: &Client, url: String) -> Result<T, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{status} {body}"));
    }
    response
        .json()
        .await
        .map_err(|error| format!("decode failed: {error}"))
}

async fn wait_for_created_tokens(
    client: &Client,
    endpoints: &RpcEndpoints,
    token_plans: &[TokenPlan],
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
    min_height: u64,
    timeout_secs: u64,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let (base, status) = status(client, endpoints).await;
        let error = if status.height > min_height {
            match verify_created_tokens(client, &base, token_plans, issuer_ids, issuer_nonces).await
            {
                Ok(()) => return status,
                Err(error) => error,
            }
        } else {
            format!(
                "height {} has not advanced beyond {}",
                status.height, min_height
            )
        };
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for token creation, height={}, minimum_height={}, remaining_mempool={}, last_error={}",
                status.height, min_height, status.mempool_len, error
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_transfer_state(
    client: &Client,
    endpoints: &RpcEndpoints,
    token_plans: &[TokenPlan],
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
    issuer_balances: &BTreeMap<CoinId, u128>,
    recipient_balances: &BTreeMap<(AccountId, CoinId), u128>,
    min_height: u64,
    timeout_secs: u64,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        let (base, status) = status(client, endpoints).await;
        let error = if status.height > min_height {
            match verify_transfer_state(
                client,
                &base,
                token_plans,
                issuer_ids,
                issuer_nonces,
                issuer_balances,
                recipient_balances,
            )
            .await
            {
                Ok(()) => return status,
                Err(error) => error,
            }
        } else {
            format!(
                "height {} has not advanced beyond {}",
                status.height, min_height
            )
        };
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for transfer verification, height={}, minimum_height={}, remaining_mempool={}, last_error={}",
                status.height, min_height, status.mempool_len, error
            );
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn verify_created_tokens(
    client: &Client,
    base: &str,
    token_plans: &[TokenPlan],
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
) -> Result<(), String> {
    for token in token_plans {
        let actual = try_coin(client, base, token.coin)
            .await
            .map_err(|error| format!("coin {} unavailable: {error}", token.coin.digest()))?;
        if actual.total_supply != token.initial_supply {
            return Err(format!(
                "coin {} total_supply={} expected={}",
                token.coin.digest(),
                actual.total_supply,
                token.initial_supply
            ));
        }
        let issuer = &issuer_ids[token.issuer_index];
        let actual = try_balance(client, base, token.coin, issuer)
            .await
            .map_err(|error| {
                format!(
                    "issuer balance unavailable for coin {} issuer {}: {error}",
                    token.coin.digest(),
                    issuer
                )
            })?;
        if actual.balance != token.initial_supply {
            return Err(format!(
                "issuer balance mismatch for coin {} issuer {} actual={} expected={}",
                token.coin.digest(),
                issuer,
                actual.balance,
                token.initial_supply
            ));
        }
    }
    verify_issuer_nonces(client, base, issuer_ids, issuer_nonces).await
}

async fn verify_transfer_state(
    client: &Client,
    base: &str,
    token_plans: &[TokenPlan],
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
    issuer_balances: &BTreeMap<CoinId, u128>,
    recipient_balances: &BTreeMap<(AccountId, CoinId), u128>,
) -> Result<(), String> {
    for token in token_plans {
        let actual = try_coin(client, base, token.coin)
            .await
            .map_err(|error| format!("coin {} unavailable: {error}", token.coin.digest()))?;
        if actual.total_supply != token.initial_supply {
            return Err(format!(
                "coin {} total_supply={} expected={}",
                token.coin.digest(),
                actual.total_supply,
                token.initial_supply
            ));
        }
        let issuer = &issuer_ids[token.issuer_index];
        let expected = *issuer_balances
            .get(&token.coin)
            .expect("issuer balance missing");
        let actual = try_balance(client, base, token.coin, issuer)
            .await
            .map_err(|error| {
                format!(
                    "issuer balance unavailable for coin {} issuer {}: {error}",
                    token.coin.digest(),
                    issuer
                )
            })?;
        if actual.balance != expected {
            return Err(format!(
                "issuer balance mismatch for coin {} issuer {} actual={} expected={}",
                token.coin.digest(),
                issuer,
                actual.balance,
                expected
            ));
        }
    }
    for ((account, coin), expected) in recipient_balances {
        let actual = try_balance(client, base, *coin, account)
            .await
            .map_err(|error| {
                format!(
                    "recipient balance unavailable for coin {} account {}: {error}",
                    coin.digest(),
                    account
                )
            })?;
        if actual.balance != *expected {
            return Err(format!(
                "recipient balance mismatch for coin {} account {} actual={} expected={}",
                coin.digest(),
                account,
                actual.balance,
                expected
            ));
        }
    }
    verify_issuer_nonces(client, base, issuer_ids, issuer_nonces).await
}

async fn verify_issuer_nonces(
    client: &Client,
    base: &str,
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
) -> Result<(), String> {
    for (issuer_index, issuer_id) in issuer_ids.iter().enumerate() {
        let account = try_account(client, base, issuer_id)
            .await
            .map_err(|error| format!("issuer account {issuer_id} unavailable: {error}"))?;
        if account.nonce != issuer_nonces[issuer_index] {
            return Err(format!(
                "issuer nonce mismatch for {} actual={} expected={}",
                issuer_id, account.nonce, issuer_nonces[issuer_index]
            ));
        }
    }
    Ok(())
}
