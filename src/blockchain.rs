use crate::coins::{Ledger, LedgerError, Transaction};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{types::Height, Heightable};
use commonware_cryptography::{sha256::Digest, Digest as _, Digestible, Hasher, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_BLOCK_TRANSACTIONS: usize = 10_000;

/// A minimal Commonware-compatible block carrying signed coin transactions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub parent: Digest,
    pub height: Height,
    pub timestamp_ms: u64,
    pub transactions: Vec<Transaction>,
    pub state_root: Digest,
    digest: Digest,
}

impl Block {
    pub fn new(
        parent: Digest,
        height: Height,
        timestamp_ms: u64,
        transactions: Vec<Transaction>,
        state_root: Digest,
    ) -> Self {
        let digest =
            Self::compute_digest(&parent, height, timestamp_ms, &transactions, &state_root);
        Self {
            parent,
            height,
            timestamp_ms,
            transactions,
            state_root,
            digest,
        }
    }

    pub fn genesis(state_root: Digest) -> Self {
        Self::new(Digest::EMPTY, Height::zero(), 0, Vec::new(), state_root)
    }

    fn compute_digest(
        parent: &Digest,
        height: Height,
        timestamp_ms: u64,
        transactions: &[Transaction],
        state_root: &Digest,
    ) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"NUNCHI_BLOCK_V1");
        hasher.update(&parent.encode());
        hasher.update(&height.encode());
        hasher.update(&timestamp_ms.encode());
        hasher.update(&transactions.to_vec().encode());
        hasher.update(&state_root.encode());
        hasher.finalize()
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp_ms.write(buf);
        self.transactions.write(buf);
        self.state_root.write(buf);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let timestamp_ms = u64::read(buf)?;
        let transactions =
            Vec::<Transaction>::read_cfg(buf, &(RangeCfg::new(0..=MAX_BLOCK_TRANSACTIONS), ()))?;
        let state_root = Digest::read(buf)?;
        Ok(Self::new(
            parent,
            height,
            timestamp_ms,
            transactions,
            state_root,
        ))
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp_ms.encode_size()
            + self.transactions.encode_size()
            + self.state_root.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        self.digest
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ChainError {
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error("timestamp must increase: parent {parent}, child {child}")]
    NonIncreasingTimestamp { parent: u64, child: u64 },
    #[error("missing parent block")]
    MissingParent,
}

/// A tiny in-memory blockchain for exercising the foundational coin module.
#[derive(Clone, Debug)]
pub struct Chain {
    ledger: Ledger,
    blocks: BTreeMap<Height, Block>,
    tip: Height,
}

impl Default for Chain {
    fn default() -> Self {
        Self::genesis()
    }
}

impl Chain {
    pub fn genesis() -> Self {
        let ledger = Ledger::default();
        let genesis = Block::genesis(ledger.state_root());
        let tip = genesis.height;
        let mut blocks = BTreeMap::new();
        blocks.insert(tip, genesis);
        Self {
            ledger,
            blocks,
            tip,
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn tip(&self) -> &Block {
        self.blocks
            .get(&self.tip)
            .expect("genesis block is always present")
    }

    pub fn block(&self, height: Height) -> Option<&Block> {
        self.blocks.get(&height)
    }

    pub fn append_block(
        &mut self,
        transactions: Vec<Transaction>,
        timestamp_ms: u64,
    ) -> Result<&Block, ChainError> {
        let parent = self.tip().clone();
        if timestamp_ms <= parent.timestamp_ms {
            return Err(ChainError::NonIncreasingTimestamp {
                parent: parent.timestamp_ms,
                child: timestamp_ms,
            });
        }

        let mut ledger = self.ledger.clone();
        for tx in &transactions {
            ledger.apply_transaction(tx)?;
        }

        let block = Block::new(
            parent.digest(),
            parent.height.next(),
            timestamp_ms,
            transactions,
            ledger.state_root(),
        );
        self.tip = block.height;
        self.ledger = ledger;
        self.blocks.insert(block.height, block);
        Ok(self.tip())
    }
}
