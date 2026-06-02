use super::types::Context;
use crate::coins::Transaction;
use commonware_codec::{Encode, EncodeSize, Error, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::{types::Height, CertifiableBlock, Heightable};
use commonware_cryptography::{sha256::Digest, Digestible, Hasher, Sha256};

pub const MAX_BLOCK_TRANSACTIONS: usize = 50_000;
pub const MAX_BLOCK_BYTES: usize = 3 * 1024 * 1024;

/// A coinschain block certified by threshold Simplex.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub context: Context,
    pub parent: Digest,
    pub height: Height,
    pub timestamp_ms: u64,
    pub transactions: Vec<Transaction>,
    pub state_root: Digest,
    digest: Digest,
}

impl Block {
    pub fn new(
        context: Context,
        parent: Digest,
        height: Height,
        timestamp_ms: u64,
        transactions: Vec<Transaction>,
        state_root: Digest,
    ) -> Self {
        let digest = Self::compute_digest(
            &context,
            &parent,
            height,
            timestamp_ms,
            &transactions,
            &state_root,
        );
        Self {
            context,
            parent,
            height,
            timestamp_ms,
            transactions,
            state_root,
            digest,
        }
    }

    fn compute_digest(
        context: &Context,
        parent: &Digest,
        height: Height,
        timestamp_ms: u64,
        transactions: &[Transaction],
        state_root: &Digest,
    ) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"NUNCHI_COINSCHAIN_BLOCK_V1");
        hasher.update(&context.encode());
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
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp_ms.write(buf);
        self.transactions.write(buf);
        self.state_root.write(buf);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let context = Context::read(buf)?;
        let parent = Digest::read(buf)?;
        let height = Height::read(buf)?;
        let timestamp_ms = u64::read(buf)?;
        let transactions =
            Vec::<Transaction>::read_cfg(buf, &(RangeCfg::new(0..=MAX_BLOCK_TRANSACTIONS), ()))?;
        let state_root = Digest::read(buf)?;
        Ok(Self::new(
            context,
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
        self.context.encode_size()
            + self.parent.encode_size()
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

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Self::Digest {
        self.parent
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl CertifiableBlock for Block {
    type Context = Context;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}
