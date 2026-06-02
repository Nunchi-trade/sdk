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
    #[arg(long, default_value_t = 0)]
    single_every: u64,
    #[arg(long, default_value_t = 10_000)]
    read_batch_size: usize,
    #[arg(long, default_value_t = 30)]
    request_timeout_secs: u64,
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

#[derive(Clone, Copy)]
enum SubmitMode {
    Batch,
    Single,
}

#[derive(Debug, Serialize)]
struct SubmitTransaction<'a> {
    transaction: &'a str,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactionResponse {
    accepted: bool,
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

#[derive(Debug, Serialize)]
struct AccountsRequest<'a> {
    accounts: &'a [String],
}

#[derive(Debug, Serialize)]
struct CoinsRequest<'a> {
    coins: &'a [String],
}

#[derive(Clone, Debug, Serialize)]
struct BalanceLookup {
    account: String,
    coin: String,
}

#[derive(Debug, Serialize)]
struct BalancesRequest<'a> {
    balances: &'a [BalanceLookup],
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
    assert!(
        args.read_batch_size > 0,
        "read_batch_size must be greater than zero"
    );
    assert!(
        args.request_timeout_secs > 0,
        "request_timeout_secs must be greater than zero"
    );

    let client = Client::builder()
        .timeout(Duration::from_secs(args.request_timeout_secs))
        .build()
        .expect("failed to build HTTP client");
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

    let mut issuer_nonces = accounts(&client, &read_base, &issuer_ids, args.read_batch_size)
        .await
        .into_iter()
        .map(|account| account.nonce)
        .collect::<Vec<_>>();
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
        args.read_batch_size,
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
    let mut single_dispatched = 0u64;
    let mut batched_dispatched = 0u64;
    let mut next_progress = args.progress_every;
    for transfer_index in 0..args.transactions {
        let token = &token_plans[transfer_token_index(transfer_index, args.tokens)];
        let issuer = &issuers[token.issuer_index];
        let issuer_id = &issuer_ids[token.issuer_index];
        let nonce = issuer_nonces[token.issuer_index];
        issuer_nonces[token.issuer_index] += 1;
        let recipient = recipients[recipient_index(transfer_index, args.accounts)].clone();
        let amount = 1 + u128::from(transfer_index) % args.max_transfer_amount;

        *issuer_balances
            .get_mut(&token.coin)
            .expect("token balance missing") -= amount;
        *recipient_balances
            .entry((recipient.clone(), token.coin))
            .or_default() += amount;

        let transaction = Transaction::sign(
            issuer,
            nonce,
            CoinOperation::Transfer {
                coin: token.coin,
                from: issuer_id.clone(),
                to: recipient,
                amount,
            },
        );

        if args.single_every > 0 && (transfer_index + 1) % args.single_every == 0 {
            while pending.len() >= args.in_flight {
                pending.next().await.expect("pending submit missing");
            }
            dispatched += 1;
            single_dispatched += 1;
            pending.push(submit_transactions(
                client.clone(),
                endpoints.clone(),
                vec![transaction],
                SubmitMode::Single,
            ));
            if args.progress_every > 0 && dispatched >= next_progress {
                println!(
                    "submitted_transfers={} singles={} batched={} elapsed_ms={} pending_submits={}",
                    dispatched,
                    single_dispatched,
                    batched_dispatched,
                    started.elapsed().as_millis(),
                    pending.len()
                );
                next_progress = next_progress.saturating_add(args.progress_every);
            }
            continue;
        }

        batch.push(transaction);
        if batch.len() == args.batch_size {
            while pending.len() >= args.in_flight {
                pending.next().await.expect("pending submit missing");
            }
            dispatched += batch.len() as u64;
            batched_dispatched += batch.len() as u64;
            pending.push(submit_transactions(
                client.clone(),
                endpoints.clone(),
                std::mem::take(&mut batch),
                SubmitMode::Batch,
            ));
            batch = Vec::with_capacity(args.batch_size);
            if args.progress_every > 0 && dispatched >= next_progress {
                println!(
                    "submitted_transfers={} singles={} batched={} elapsed_ms={} pending_submits={}",
                    dispatched,
                    single_dispatched,
                    batched_dispatched,
                    started.elapsed().as_millis(),
                    pending.len()
                );
                next_progress = next_progress.saturating_add(args.progress_every);
            }
        }
    }
    if !batch.is_empty() {
        while pending.len() >= args.in_flight {
            pending.next().await.expect("pending submit missing");
        }
        dispatched += batch.len() as u64;
        batched_dispatched += batch.len() as u64;
        pending.push(submit_transactions(
            client.clone(),
            endpoints.clone(),
            batch,
            SubmitMode::Batch,
        ));
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
        args.read_batch_size,
    )
    .await;
    let elapsed = started.elapsed();
    assert_ne!(
        start_status.state_root, final_status.state_root,
        "load test did not change the coinschain state root"
    );

    let tps = args.transactions as f64 / elapsed.as_secs_f64();
    println!(
        "issuer_seed={} submit_endpoints={} batch_size={} in_flight={} single_every={} single_transfers={} batched_transfers={} tokens={} issuers={} accounts={} submitted_transfers={} elapsed_ms={} submit_to_verified_tps={:.2} start_height={} final_height={} verified_balances={} start_state_root={} final_state_root={}",
        issuer_seed,
        endpoints.len(),
        args.batch_size,
        args.in_flight,
        args.single_every,
        single_dispatched,
        batched_dispatched,
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

fn transfer_token_index(transfer_index: u64, tokens: u64) -> usize {
    transfer_index
        .wrapping_mul(8_191)
        .wrapping_add(transfer_index / 97)
        .wrapping_rem(tokens) as usize
}

fn recipient_index(transfer_index: u64, accounts: u64) -> usize {
    transfer_index
        .wrapping_mul(48_271)
        .wrapping_add(transfer_index / 53)
        .wrapping_rem(accounts) as usize
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
        pending.push(submit_transactions(
            client.clone(),
            endpoints.clone(),
            batch.to_vec(),
            SubmitMode::Batch,
        ));
    }
    while pending.next().await.is_some() {}
}

async fn submit_transactions(
    client: Client,
    endpoints: RpcEndpoints,
    transactions: Vec<Transaction>,
    mode: SubmitMode,
) {
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
            .map(|base| submit_encoded_transactions(&client, base, &encoded, mode)),
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
    panic!("transactions were not accepted by all endpoints: {errors}");
}

async fn submit_encoded_transactions(
    client: &Client,
    base: &str,
    encoded: &[String],
    mode: SubmitMode,
) -> Result<(), String> {
    match mode {
        SubmitMode::Batch => submit_encoded_batch(client, base, encoded).await,
        SubmitMode::Single => submit_encoded_single(client, base, &encoded[0]).await,
    }
}

async fn submit_encoded_single(client: &Client, base: &str, encoded: &str) -> Result<(), String> {
    let response = client
        .post(format!("{base}/tx"))
        .json(&SubmitTransaction {
            transaction: encoded,
        })
        .send()
        .await
        .map_err(|error| format!("{base}: failed to submit transaction: {error}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("{base}: transaction rejected: {status} {body}"));
    }
    let accepted: SubmitTransactionResponse = response
        .json()
        .await
        .map_err(|error| format!("{base}: failed to decode submit response: {error}"))?;
    if !accepted.accepted {
        return Err(format!("{base}: transaction was not accepted"));
    }
    Ok(())
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

async fn accounts(
    client: &Client,
    base: &str,
    accounts: &[AccountId],
    batch_size: usize,
) -> Vec<AccountResponse> {
    try_accounts(client, base, accounts, batch_size)
        .await
        .unwrap_or_else(|error| panic!("failed to fetch accounts: {error}"))
}

async fn try_accounts(
    client: &Client,
    base: &str,
    accounts: &[AccountId],
    batch_size: usize,
) -> Result<Vec<AccountResponse>, String> {
    let encoded = accounts.iter().map(ToString::to_string).collect::<Vec<_>>();
    let mut responses = Vec::with_capacity(encoded.len());
    for chunk in encoded.chunks(batch_size) {
        let mut chunk_responses: Vec<AccountResponse> = post_json(
            client,
            format!("{base}/accounts"),
            &AccountsRequest { accounts: chunk },
        )
        .await?;
        if chunk_responses.len() != chunk.len() {
            return Err(format!(
                "account batch response length mismatch: actual={} expected={}",
                chunk_responses.len(),
                chunk.len()
            ));
        }
        responses.append(&mut chunk_responses);
    }
    Ok(responses)
}

async fn try_coins(
    client: &Client,
    base: &str,
    coins: &[CoinId],
    batch_size: usize,
) -> Result<Vec<CoinResponse>, String> {
    let encoded = coins
        .iter()
        .map(|coin| coin.digest().to_string())
        .collect::<Vec<_>>();
    let mut responses = Vec::with_capacity(encoded.len());
    for chunk in encoded.chunks(batch_size) {
        let mut chunk_responses: Vec<CoinResponse> = post_json(
            client,
            format!("{base}/coins"),
            &CoinsRequest { coins: chunk },
        )
        .await?;
        if chunk_responses.len() != chunk.len() {
            return Err(format!(
                "coin batch response length mismatch: actual={} expected={}",
                chunk_responses.len(),
                chunk.len()
            ));
        }
        responses.append(&mut chunk_responses);
    }
    Ok(responses)
}

async fn try_balances(
    client: &Client,
    base: &str,
    balances: &[BalanceLookup],
    batch_size: usize,
) -> Result<Vec<BalanceResponse>, String> {
    let mut responses = Vec::with_capacity(balances.len());
    for chunk in balances.chunks(batch_size) {
        let mut chunk_responses: Vec<BalanceResponse> = post_json(
            client,
            format!("{base}/balances"),
            &BalancesRequest { balances: chunk },
        )
        .await?;
        if chunk_responses.len() != chunk.len() {
            return Err(format!(
                "balance batch response length mismatch: actual={} expected={}",
                chunk_responses.len(),
                chunk.len()
            ));
        }
        responses.append(&mut chunk_responses);
    }
    Ok(responses)
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

async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
    client: &Client,
    url: String,
    body: &B,
) -> Result<T, String> {
    let response = client
        .post(url)
        .json(body)
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
    read_batch_size: usize,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut next_report = Instant::now() + Duration::from_secs(5);
    loop {
        let (base, status) = status(client, endpoints).await;
        let error = if status.height > min_height {
            match verify_created_tokens(
                client,
                &base,
                token_plans,
                issuer_ids,
                issuer_nonces,
                read_batch_size,
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
                "timed out waiting for token creation, height={}, minimum_height={}, remaining_mempool={}, last_error={}",
                status.height, min_height, status.mempool_len, error
            );
        }
        if Instant::now() >= next_report {
            println!(
                "waiting_for_token_creation height={} minimum_height={} remaining_mempool={} last_error={}",
                status.height, min_height, status.mempool_len, error
            );
            next_report += Duration::from_secs(5);
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
    read_batch_size: usize,
) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut next_report = Instant::now() + Duration::from_secs(5);
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
                read_batch_size,
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
        if Instant::now() >= next_report {
            println!(
                "waiting_for_transfer_state height={} minimum_height={} remaining_mempool={} last_error={}",
                status.height, min_height, status.mempool_len, error
            );
            next_report += Duration::from_secs(5);
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
    read_batch_size: usize,
) -> Result<(), String> {
    let coin_ids = token_plans
        .iter()
        .map(|token| token.coin)
        .collect::<Vec<_>>();
    let coins = try_coins(client, base, &coin_ids, read_batch_size).await?;
    for (token, actual) in token_plans.iter().zip(coins.iter()) {
        if actual.total_supply != token.initial_supply {
            return Err(format!(
                "coin {} total_supply={} expected={}",
                token.coin.digest(),
                actual.total_supply,
                token.initial_supply
            ));
        }
    }

    let issuer_balance_requests = token_plans
        .iter()
        .map(|token| BalanceLookup {
            account: issuer_ids[token.issuer_index].to_string(),
            coin: token.coin.digest().to_string(),
        })
        .collect::<Vec<_>>();
    let issuer_balances =
        try_balances(client, base, &issuer_balance_requests, read_batch_size).await?;
    for (token, actual) in token_plans.iter().zip(issuer_balances.iter()) {
        let issuer = &issuer_ids[token.issuer_index];
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
    verify_issuer_nonces(client, base, issuer_ids, issuer_nonces, read_batch_size).await
}

async fn verify_transfer_state(
    client: &Client,
    base: &str,
    token_plans: &[TokenPlan],
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
    issuer_balances: &BTreeMap<CoinId, u128>,
    recipient_balances: &BTreeMap<(AccountId, CoinId), u128>,
    read_batch_size: usize,
) -> Result<(), String> {
    let coin_ids = token_plans
        .iter()
        .map(|token| token.coin)
        .collect::<Vec<_>>();
    let coins = try_coins(client, base, &coin_ids, read_batch_size).await?;
    for (token, actual) in token_plans.iter().zip(coins.iter()) {
        if actual.total_supply != token.initial_supply {
            return Err(format!(
                "coin {} total_supply={} expected={}",
                token.coin.digest(),
                actual.total_supply,
                token.initial_supply
            ));
        }
    }

    let issuer_balance_requests = token_plans
        .iter()
        .map(|token| BalanceLookup {
            account: issuer_ids[token.issuer_index].to_string(),
            coin: token.coin.digest().to_string(),
        })
        .collect::<Vec<_>>();
    let actual_issuer_balances =
        try_balances(client, base, &issuer_balance_requests, read_batch_size).await?;
    for (token, actual) in token_plans.iter().zip(actual_issuer_balances.iter()) {
        let issuer = &issuer_ids[token.issuer_index];
        let expected = *issuer_balances
            .get(&token.coin)
            .expect("issuer balance missing");
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

    let recipient_balance_requests = recipient_balances
        .keys()
        .map(|(account, coin)| BalanceLookup {
            account: account.to_string(),
            coin: coin.digest().to_string(),
        })
        .collect::<Vec<_>>();
    let actual_recipient_balances =
        try_balances(client, base, &recipient_balance_requests, read_batch_size).await?;
    for (((account, coin), expected), actual) in recipient_balances
        .iter()
        .zip(actual_recipient_balances.iter())
    {
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
    verify_issuer_nonces(client, base, issuer_ids, issuer_nonces, read_batch_size).await
}

async fn verify_issuer_nonces(
    client: &Client,
    base: &str,
    issuer_ids: &[AccountId],
    issuer_nonces: &[u64],
    read_batch_size: usize,
) -> Result<(), String> {
    let accounts = try_accounts(client, base, issuer_ids, read_batch_size).await?;
    for (issuer_index, account) in accounts.iter().enumerate() {
        if account.nonce != issuer_nonces[issuer_index] {
            return Err(format!(
                "issuer nonce mismatch for {} actual={} expected={}",
                issuer_ids[issuer_index], account.nonce, issuer_nonces[issuer_index]
            ));
        }
    }
    Ok(())
}
