use super::{AccountId, CoinId, CoinSpec, PrivateKey, Signature, COINS_NAMESPACE};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256, Signer, Verifier};

const OP_CREATE_TOKEN: u8 = 0;
const OP_MINT: u8 = 1;
const OP_BURN: u8 = 2;
const OP_TRANSFER: u8 = 3;

/// A ledger operation authorized by a signed transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoinOperation {
    CreateToken {
        spec: CoinSpec,
    },
    Mint {
        coin: CoinId,
        to: AccountId,
        amount: u128,
    },
    Burn {
        coin: CoinId,
        from: AccountId,
        amount: u128,
    },
    Transfer {
        coin: CoinId,
        from: AccountId,
        to: AccountId,
        amount: u128,
    },
}

impl Write for CoinOperation {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        match self {
            Self::CreateToken { spec } => {
                OP_CREATE_TOKEN.write(buf);
                spec.write(buf);
            }
            Self::Mint { coin, to, amount } => {
                OP_MINT.write(buf);
                coin.write(buf);
                to.write(buf);
                amount.write(buf);
            }
            Self::Burn { coin, from, amount } => {
                OP_BURN.write(buf);
                coin.write(buf);
                from.write(buf);
                amount.write(buf);
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => {
                OP_TRANSFER.write(buf);
                coin.write(buf);
                from.write(buf);
                to.write(buf);
                amount.write(buf);
            }
        }
    }
}

impl Read for CoinOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(buf)? {
            OP_CREATE_TOKEN => Ok(Self::CreateToken {
                spec: CoinSpec::read(buf)?,
            }),
            OP_MINT => Ok(Self::Mint {
                coin: CoinId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_BURN => Ok(Self::Burn {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            OP_TRANSFER => Ok(Self::Transfer {
                coin: CoinId::read(buf)?,
                from: AccountId::read(buf)?,
                to: AccountId::read(buf)?,
                amount: u128::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl EncodeSize for CoinOperation {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::CreateToken { spec } => spec.encode_size(),
            Self::Mint { coin, to, amount } => {
                coin.encode_size() + to.encode_size() + amount.encode_size()
            }
            Self::Burn { coin, from, amount } => {
                coin.encode_size() + from.encode_size() + amount.encode_size()
            }
            Self::Transfer {
                coin,
                from,
                to,
                amount,
            } => coin.encode_size() + from.encode_size() + to.encode_size() + amount.encode_size(),
        }
    }
}

/// Signable transaction payload. The nonce is scoped to the signer account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload {
    pub nonce: u64,
    pub operation: CoinOperation,
}

impl TransactionPayload {
    pub fn new(nonce: u64, operation: CoinOperation) -> Self {
        Self { nonce, operation }
    }
}

impl Write for TransactionPayload {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.nonce.write(buf);
        self.operation.write(buf);
    }
}

impl Read for TransactionPayload {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            operation: CoinOperation::read(buf)?,
        })
    }
}

impl EncodeSize for TransactionPayload {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size() + self.operation.encode_size()
    }
}

/// A signed coin transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Transaction {
    pub signer: AccountId,
    pub payload: TransactionPayload,
    pub signature: Signature,
}

impl Transaction {
    pub fn sign(signer: &PrivateKey, nonce: u64, operation: CoinOperation) -> Self {
        let payload = TransactionPayload::new(nonce, operation);
        let signature = signer.sign(COINS_NAMESPACE, &payload.encode());
        Self {
            signer: signer.public_key(),
            payload,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        self.signer
            .verify(COINS_NAMESPACE, &self.payload.encode(), &self.signature)
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signer.write(buf);
        self.payload.write(buf);
        self.signature.write(buf);
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            signer: AccountId::read(buf)?,
            payload: TransactionPayload::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.payload.encode_size() + self.signature.encode_size()
    }
}
