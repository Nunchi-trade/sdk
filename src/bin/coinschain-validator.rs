use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use commonware_codec::{Decode, DecodeExt};
use commonware_consensus::{marshal, types::ViewDelta};
use commonware_cryptography::{
    bls12381::primitives::{
        group,
        sharing::{ModeVersion, Sharing},
        variant::MinSig,
    },
    ed25519::{PrivateKey, PublicKey},
    Signer,
};
use commonware_formatting::from_hex;
use commonware_p2p::{authenticated::discovery as authenticated, Ingress, Manager};
use commonware_runtime::{tokio as cw_tokio, Runner, Supervisor as _, ThreadPooler};
use commonware_utils::{ordered::Set, union_unique, NZUsize, NZU32};
use futures::future::try_join_all;
use governor::Quota;
use nunchi_sdk::{
    coins::{AccountId, CoinId, Ledger, Transaction},
    coinschain::{engine, Config, Mempool, Peers, SharedState, EPOCH, NAMESPACE},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{error, info, Level};

const PENDING_CHANNEL: u64 = 0;
const RECOVERED_CHANNEL: u64 = 1;
const RESOLVER_CHANNEL: u64 = 2;
const BROADCASTER_CHANNEL: u64 = 3;
const MARSHAL_CHANNEL: u64 = 4;

const LEADER_TIMEOUT: Duration = Duration::from_secs(1);
const CERTIFICATION_TIMEOUT: Duration = Duration::from_secs(2);
const NULLIFY_RETRY: Duration = Duration::from_secs(10);
const ACTIVITY_TIMEOUT: ViewDelta = ViewDelta::new(256);
const SKIP_TIMEOUT: ViewDelta = ViewDelta::new(32);
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);
const FETCH_CONCURRENT: usize = 4;
const MAX_MESSAGE_SIZE: u32 = 32 * 1024 * 1024;
const MESSAGE_RATE_PER_PEER: u32 = 512;
const BROADCAST_RATE_PER_PEER: u32 = 128;
const MARSHAL_RATE_PER_PEER: u32 = 128;
const BLOCKS_FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(18);
const FINALIZED_FREEZER_TABLE_INITIAL_SIZE: u32 = 2u32.pow(18);
const MAX_SUBMIT_BATCH: usize = 10_000;
const MAX_READ_BATCH: usize = 100_000;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    peers: PathBuf,
}

#[derive(Clone)]
struct RpcState {
    public_key: PublicKey,
    mempool: Mempool,
    chain: SharedState,
}

#[derive(Debug, Deserialize)]
struct SubmitTransaction {
    transaction: String,
}

#[derive(Debug, Deserialize)]
struct SubmitTransactions {
    transactions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SubmitTransactionResponse {
    accepted: bool,
    digest: String,
    mempool_len: usize,
}

#[derive(Debug, Serialize)]
struct SubmitTransactionsResponse {
    accepted: bool,
    accepted_count: usize,
    digests: Vec<String>,
    mempool_len: usize,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    public_key: String,
    height: u64,
    block_digest: String,
    state_root: String,
    finalized_blocks: u64,
    token_factory_nonce: u64,
    mempool_len: usize,
}

#[derive(Debug, Serialize)]
struct AccountResponse {
    account: String,
    nonce: u64,
}

#[derive(Debug, Serialize)]
struct CoinResponse {
    coin: String,
    issuer: String,
    symbol: String,
    name: String,
    decimals: u8,
    total_supply: u128,
    max_supply: Option<u128>,
}

#[derive(Debug, Serialize)]
struct BalanceResponse {
    account: String,
    coin: String,
    balance: u128,
}

#[derive(Debug, Deserialize)]
struct AccountsRequest {
    accounts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CoinsRequest {
    coins: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct BalanceRequest {
    account: String,
    coin: String,
}

#[derive(Debug, Deserialize)]
struct BalancesRequest {
    balances: Vec<BalanceRequest>,
}

fn main() {
    let args = Args::parse();

    let config_file = std::fs::read_to_string(&args.config).expect("could not read config file");
    let config: Config = serde_yaml::from_str(&config_file).expect("could not parse config file");
    let key = from_hex(&config.private_key).expect("could not parse private key");
    let signer = PrivateKey::decode(key.as_ref()).expect("private key is invalid");
    let public_key = signer.public_key();

    let runtime_cfg = cw_tokio::Config::default()
        .with_tcp_nodelay(Some(true))
        .with_worker_threads(config.worker_threads)
        .with_max_blocking_threads(config.blocking_threads)
        .with_storage_directory(PathBuf::from(&config.directory))
        .with_catch_panics(false);
    let executor = cw_tokio::Runner::new(runtime_cfg);

    executor.start(|context| async move {
        let log_level = Level::from_str(&config.log_level).expect("invalid log level");
        cw_tokio::telemetry::init(
            context.child("telemetry"),
            cw_tokio::telemetry::Logging {
                level: log_level,
                json: false,
            },
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                config.metrics_port,
            )),
            None,
        );

        let peers_file = std::fs::read_to_string(&args.peers).expect("could not read peers file");
        let peers: Peers = serde_yaml::from_str(&peers_file).expect("could not parse peers file");
        let peers: HashMap<PublicKey, SocketAddr> = peers
            .addresses
            .into_iter()
            .map(|(peer, socket)| {
                let key = from_hex(&peer).expect("could not parse peer public key");
                let key = PublicKey::decode(key.as_ref()).expect("peer public key is invalid");
                (key, socket)
            })
            .collect();
        let peer_keys = peers.keys().cloned().collect::<Vec<_>>();
        let mut bootstrappers = Vec::new();
        for bootstrapper in &config.bootstrappers {
            let key = from_hex(bootstrapper).expect("could not parse bootstrapper key");
            let key = PublicKey::decode(key.as_ref()).expect("bootstrapper key is invalid");
            let socket = peers
                .get(&key)
                .expect("bootstrapper not present in peers file");
            bootstrappers.push((key, Ingress::Socket(*socket)));
        }
        let ip = peers
            .get(&public_key)
            .expect("self public key not present in peers file")
            .ip();
        info!(peers = peer_keys.len(), ?ip, "loaded peers");

        let share = from_hex(&config.share).expect("could not parse share");
        let share = group::Share::decode(share.as_ref()).expect("share is invalid");
        let polynomial = from_hex(&config.polynomial).expect("could not parse polynomial");
        let polynomial = Sharing::<MinSig>::decode_cfg(
            polynomial.as_ref(),
            &(NZU32!(peer_keys.len() as u32), ModeVersion::v0()),
        )
        .expect("polynomial is invalid");

        let p2p_namespace = union_unique(NAMESPACE, b"_P2P");
        let mut p2p_cfg = if config.local {
            authenticated::Config::local(
                signer.clone(),
                &p2p_namespace,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port),
                SocketAddr::new(ip, config.port),
                bootstrappers,
                MAX_MESSAGE_SIZE,
            )
        } else {
            authenticated::Config::recommended(
                signer.clone(),
                &p2p_namespace,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.port),
                SocketAddr::new(ip, config.port),
                bootstrappers,
                MAX_MESSAGE_SIZE,
            )
        };
        p2p_cfg.mailbox_size = NZUsize!(config.mailbox_size);

        let (mut network, mut oracle) =
            authenticated::Network::new(context.child("network"), p2p_cfg);
        let participants: Set<PublicKey> = Set::from_iter_dedup(peer_keys.clone());
        oracle.track(EPOCH.get(), participants.clone());

        let message_quota = Quota::per_second(NonZeroU32::new(MESSAGE_RATE_PER_PEER).unwrap());
        let pending = network.register(PENDING_CHANNEL, message_quota, config.message_backlog);
        let recovered = network.register(RECOVERED_CHANNEL, message_quota, config.message_backlog);
        let resolver = network.register(RESOLVER_CHANNEL, message_quota, config.message_backlog);
        let broadcaster = network.register(
            BROADCASTER_CHANNEL,
            Quota::per_second(NonZeroU32::new(BROADCAST_RATE_PER_PEER).unwrap()),
            config.message_backlog,
        );
        let marshal = network.register(
            MARSHAL_CHANNEL,
            Quota::per_second(NonZeroU32::new(MARSHAL_RATE_PER_PEER).unwrap()),
            config.message_backlog,
        );
        let p2p = network.start();

        let strategy = context
            .create_strategy(NZUsize!(config.signature_threads))
            .unwrap();
        let mempool = Mempool::default();
        let chain_state = SharedState::default();

        let engine_cfg = engine::Config {
            blocker: oracle.clone(),
            provider: oracle.clone(),
            partition_prefix: "coinschain".to_string(),
            blocks_freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE,
            finalized_freezer_table_initial_size: FINALIZED_FREEZER_TABLE_INITIAL_SIZE,
            me: public_key.clone(),
            participants,
            mailbox_size: config.mailbox_size,
            deque_size: config.deque_size,
            leader_timeout: LEADER_TIMEOUT,
            certification_timeout: CERTIFICATION_TIMEOUT,
            nullify_retry: NULLIFY_RETRY,
            activity_timeout: ACTIVITY_TIMEOUT,
            skip_timeout: SKIP_TIMEOUT,
            fetch_timeout: FETCH_TIMEOUT,
            fetch_concurrent: FETCH_CONCURRENT,
            fetch_rate_per_peer: message_quota,
            polynomial,
            share,
            strategy,
            mempool: mempool.clone(),
            state: chain_state.clone(),
        };
        let engine = engine::Engine::new(context.child("engine"), engine_cfg).await;

        let marshal_resolver_cfg = marshal::resolver::p2p::Config {
            public_key: public_key.clone(),
            peer_provider: oracle.clone(),
            blocker: oracle,
            mailbox_size: NZUsize!(config.mailbox_size),
            initial: Duration::from_secs(1),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        };
        let marshal_resolver = marshal::resolver::p2p::init(
            context.child("marshal_resolver"),
            marshal_resolver_cfg,
            marshal,
        );

        let engine = engine.start(pending, recovered, resolver, broadcaster, marshal_resolver);
        let rpc = spawn_rpc(
            context.child("rpc"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.rpc_port),
            RpcState {
                public_key,
                mempool,
                chain: chain_state,
            },
        );

        if let Err(e) = try_join_all(vec![p2p, engine, rpc]).await {
            error!(?e, "coinschain validator task failed");
        }
    });
}

fn spawn_rpc(
    context: impl commonware_runtime::Spawner,
    bind: SocketAddr,
    state: RpcState,
) -> commonware_runtime::Handle<()> {
    context.spawn(move |_| async move {
        let app = Router::new()
            .route("/status", get(status))
            .route("/tx", post(submit_transaction))
            .route("/txs", post(submit_transactions))
            .route("/accounts", post(accounts))
            .route("/accounts/{account}", get(account))
            .route("/coins", post(coins))
            .route("/coins/{coin}", get(coin))
            .route("/balances", post(balances))
            .route("/coins/{coin}/balances/{account}", get(balance))
            .layer(DefaultBodyLimit::max(MAX_MESSAGE_SIZE as usize))
            .layer(CorsLayer::permissive())
            .with_state(state);
        let listener = TcpListener::bind(bind)
            .await
            .expect("failed to bind coinschain RPC");
        info!(%bind, "started coinschain RPC");
        axum::serve(listener, app)
            .await
            .expect("coinschain RPC server failed");
    })
}

async fn status(State(state): State<RpcState>) -> Json<StatusResponse> {
    let chain = state.chain.status();
    let ledger = state.chain.finalized_ledger();
    Json(StatusResponse {
        public_key: state.public_key.to_string(),
        height: chain.height,
        block_digest: chain.block_digest,
        state_root: chain.state_root,
        finalized_blocks: chain.finalized_blocks,
        token_factory_nonce: ledger.factory().next_nonce(),
        mempool_len: state.mempool.len(),
    })
}

async fn submit_transaction(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTransaction>,
) -> Result<Json<SubmitTransactionResponse>, (StatusCode, String)> {
    let transaction = decode_transaction(&request.transaction)?;
    let digest = transaction.digest().to_string();
    state.mempool.push_verified(transaction);
    Ok(Json(SubmitTransactionResponse {
        accepted: true,
        digest,
        mempool_len: state.mempool.len(),
    }))
}

async fn submit_transactions(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTransactions>,
) -> Result<Json<SubmitTransactionsResponse>, (StatusCode, String)> {
    if request.transactions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "empty transaction batch".to_string(),
        ));
    }
    if request.transactions.len() > MAX_SUBMIT_BATCH {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "transaction batch too large: max={}, actual={}",
                MAX_SUBMIT_BATCH,
                request.transactions.len()
            ),
        ));
    }

    let mut transactions = Vec::with_capacity(request.transactions.len());
    let mut digests = Vec::with_capacity(request.transactions.len());
    for encoded in &request.transactions {
        let transaction = decode_transaction(encoded)?;
        digests.push(transaction.digest().to_string());
        transactions.push(transaction);
    }
    let accepted_count = transactions.len();
    let mempool_len = state.mempool.extend_verified(transactions);
    Ok(Json(SubmitTransactionsResponse {
        accepted: true,
        accepted_count,
        digests,
        mempool_len,
    }))
}

fn decode_transaction(encoded: &str) -> Result<Transaction, (StatusCode, String)> {
    let bytes = from_hex(encoded).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "invalid transaction hex".to_string(),
        )
    })?;
    let transaction = Transaction::decode(bytes.as_ref()).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid transaction encoding: {error}"),
        )
    })?;
    if !transaction.verify() {
        return Err((
            StatusCode::BAD_REQUEST,
            "bad transaction signature".to_string(),
        ));
    }
    Ok(transaction)
}

async fn accounts(
    State(state): State<RpcState>,
    Json(request): Json<AccountsRequest>,
) -> Result<Json<Vec<AccountResponse>>, (StatusCode, String)> {
    ensure_read_batch("accounts", request.accounts.len())?;
    let ledger = state.chain.finalized_ledger();
    let mut responses = Vec::with_capacity(request.accounts.len());
    for account in request.accounts {
        let account = parse_account(&account)?;
        responses.push(AccountResponse {
            account: account.to_string(),
            nonce: ledger.nonce(&account),
        });
    }
    Ok(Json(responses))
}

async fn account(
    State(state): State<RpcState>,
    Path(account): Path<String>,
) -> Result<Json<AccountResponse>, (StatusCode, String)> {
    let account = parse_account(&account)?;
    let ledger = state.chain.finalized_ledger();
    Ok(Json(AccountResponse {
        account: account.to_string(),
        nonce: ledger.nonce(&account),
    }))
}

async fn coins(
    State(state): State<RpcState>,
    Json(request): Json<CoinsRequest>,
) -> Result<Json<Vec<CoinResponse>>, (StatusCode, String)> {
    ensure_read_batch("coins", request.coins.len())?;
    let ledger = state.chain.finalized_ledger();
    let mut responses = Vec::with_capacity(request.coins.len());
    for coin in request.coins {
        let coin = parse_coin(&coin)?;
        responses.push(coin_response(&ledger, coin)?);
    }
    Ok(Json(responses))
}

async fn coin(
    State(state): State<RpcState>,
    Path(coin): Path<String>,
) -> Result<Json<CoinResponse>, (StatusCode, String)> {
    let coin = parse_coin(&coin)?;
    let ledger = state.chain.finalized_ledger();
    Ok(Json(coin_response(&ledger, coin)?))
}

async fn balances(
    State(state): State<RpcState>,
    Json(request): Json<BalancesRequest>,
) -> Result<Json<Vec<BalanceResponse>>, (StatusCode, String)> {
    ensure_read_batch("balances", request.balances.len())?;
    let ledger = state.chain.finalized_ledger();
    let mut responses = Vec::with_capacity(request.balances.len());
    for balance in request.balances {
        let account = parse_account(&balance.account)?;
        let coin = parse_coin(&balance.coin)?;
        responses.push(balance_response(&ledger, coin, account));
    }
    Ok(Json(responses))
}

fn coin_response(ledger: &Ledger, coin: CoinId) -> Result<CoinResponse, (StatusCode, String)> {
    let token = ledger.token(&coin).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("unknown coin {}", coin.digest()),
        )
    })?;
    Ok(CoinResponse {
        coin: coin.digest().to_string(),
        issuer: token.issuer.to_string(),
        symbol: token.symbol.clone(),
        name: token.name.clone(),
        decimals: token.decimals,
        total_supply: token.total_supply,
        max_supply: token.max_supply,
    })
}

async fn balance(
    State(state): State<RpcState>,
    Path((coin, account)): Path<(String, String)>,
) -> Result<Json<BalanceResponse>, (StatusCode, String)> {
    let coin = parse_coin(&coin)?;
    let account = parse_account(&account)?;
    let ledger = state.chain.finalized_ledger();
    Ok(Json(balance_response(&ledger, coin, account)))
}

fn balance_response(ledger: &Ledger, coin: CoinId, account: AccountId) -> BalanceResponse {
    BalanceResponse {
        account: account.to_string(),
        coin: coin.digest().to_string(),
        balance: ledger.balance(&account, &coin),
    }
}

fn ensure_read_batch(kind: &str, len: usize) -> Result<(), (StatusCode, String)> {
    if len > MAX_READ_BATCH {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("{kind} batch too large: max={MAX_READ_BATCH}, actual={len}"),
        ));
    }
    Ok(())
}

fn parse_account(encoded: &str) -> Result<AccountId, (StatusCode, String)> {
    let bytes = from_hex(encoded)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid account hex".to_string()))?;
    AccountId::decode(bytes.as_ref())
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid account: {error}")))
}

fn parse_coin(encoded: &str) -> Result<CoinId, (StatusCode, String)> {
    let bytes = from_hex(encoded)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid coin hex".to_string()))?;
    CoinId::decode(bytes.as_ref())
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid coin: {error}")))
}
