use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub private_key: String,
    pub share: String,
    pub polynomial: String,

    pub port: u16,
    pub rpc_port: u16,
    pub metrics_port: u16,
    pub directory: String,
    pub worker_threads: usize,
    pub blocking_threads: usize,
    pub log_level: String,

    pub local: bool,
    pub bootstrappers: Vec<String>,

    pub message_backlog: usize,
    pub mailbox_size: usize,
    pub deque_size: usize,
    pub signature_threads: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Peers {
    pub addresses: HashMap<String, SocketAddr>,
}
