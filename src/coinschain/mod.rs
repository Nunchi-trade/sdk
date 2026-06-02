//! A Commonware Simplex chain that exercises the foundational [`crate::coins`] module.

pub mod application;
pub mod block;
pub mod config;
pub mod engine;
pub mod mempool;
pub mod state;
pub mod types;

pub use application::Application;
pub use block::Block;
pub use config::{Config, Peers};
pub use mempool::Mempool;
pub use state::{ChainStatus, SharedState};
pub use types::{
    Activity, Context, Finalization, Identity, Notarization, PublicKey, Scheme, Seed, Seedable,
    Signature, EPOCH, EPOCH_LENGTH, NAMESPACE,
};
