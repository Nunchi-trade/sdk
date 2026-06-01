//! Shared signed transaction primitives.

use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    sha256::Digest, Hasher, PublicKey, Sha256, Signature as CryptoSignature, Signer,
};

/// Module-specific operation carried by a signed transaction.
///
/// Each operation type owns its signature namespace so signatures cannot be
/// replayed across modules that use the same account keys.
pub trait TransactionOperation: Read<Cfg = ()> + Write + EncodeSize {
    const NAMESPACE: &'static [u8];
}

/// Signable transaction payload. The nonce is scoped to the signer account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload<Operation> {
    pub nonce: u64,
    pub operation: Operation,
}

impl<Operation> TransactionPayload<Operation> {
    pub fn new(nonce: u64, operation: Operation) -> Self {
        Self { nonce, operation }
    }
}

impl<Operation> Write for TransactionPayload<Operation>
where
    Operation: TransactionOperation,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.nonce.write(buf);
        self.operation.write(buf);
    }
}

impl<Operation> Read for TransactionPayload<Operation>
where
    Operation: TransactionOperation,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            operation: Operation::read(buf)?,
        })
    }
}

impl<Operation> EncodeSize for TransactionPayload<Operation>
where
    Operation: TransactionOperation,
{
    fn encode_size(&self) -> usize {
        self.nonce.encode_size() + self.operation.encode_size()
    }
}

/// A signed transaction envelope reusable across SDK modules.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTransaction<Account, Signature, Operation> {
    pub signer: Account,
    pub payload: TransactionPayload<Operation>,
    pub signature: Signature,
}

impl<Account, Signature, Operation> SignedTransaction<Account, Signature, Operation>
where
    Account: PublicKey<Signature = Signature>,
    Signature: CryptoSignature,
    Operation: TransactionOperation,
{
    pub fn sign<S>(signer: &S, nonce: u64, operation: Operation) -> Self
    where
        S: Signer<PublicKey = Account, Signature = Signature>,
    {
        let payload = TransactionPayload::new(nonce, operation);
        let signature = signer.sign(Operation::NAMESPACE, &payload.encode());
        Self {
            signer: signer.public_key(),
            payload,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        self.signer.verify(
            Operation::NAMESPACE,
            &self.payload.encode(),
            &self.signature,
        )
    }

    pub fn digest(&self) -> Digest {
        Sha256::hash(&self.encode())
    }

    pub fn nonce(&self) -> u64 {
        self.payload.nonce
    }

    pub fn operation(&self) -> &Operation {
        &self.payload.operation
    }
}

impl<Account, Signature, Operation> Write for SignedTransaction<Account, Signature, Operation>
where
    Account: PublicKey<Signature = Signature>,
    Signature: CryptoSignature,
    Operation: TransactionOperation,
{
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.signer.write(buf);
        self.payload.write(buf);
        self.signature.write(buf);
    }
}

impl<Account, Signature, Operation> Read for SignedTransaction<Account, Signature, Operation>
where
    Account: PublicKey<Signature = Signature>,
    Signature: CryptoSignature,
    Operation: TransactionOperation,
{
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            signer: Account::read(buf)?,
            payload: TransactionPayload::read(buf)?,
            signature: Signature::read(buf)?,
        })
    }
}

impl<Account, Signature, Operation> EncodeSize for SignedTransaction<Account, Signature, Operation>
where
    Account: PublicKey<Signature = Signature>,
    Signature: CryptoSignature,
    Operation: TransactionOperation,
{
    fn encode_size(&self) -> usize {
        self.signer.encode_size() + self.payload.encode_size() + self.signature.encode_size()
    }
}

/// Common behavior expected from signed transactions.
pub trait Transaction: Read<Cfg = ()> + Write + EncodeSize {
    type Account: PublicKey<Signature = Self::Signature>;
    type Signature: CryptoSignature;
    type Operation: TransactionOperation;

    fn signer(&self) -> &Self::Account;
    fn payload(&self) -> &TransactionPayload<Self::Operation>;
    fn signature(&self) -> &Self::Signature;

    fn nonce(&self) -> u64 {
        self.payload().nonce
    }

    fn operation(&self) -> &Self::Operation {
        &self.payload().operation
    }

    fn verify(&self) -> bool;
    fn digest(&self) -> Digest;
}

impl<Account, Signature, Operation> Transaction for SignedTransaction<Account, Signature, Operation>
where
    Account: PublicKey<Signature = Signature>,
    Signature: CryptoSignature,
    Operation: TransactionOperation,
{
    type Account = Account;
    type Signature = Signature;
    type Operation = Operation;

    fn signer(&self) -> &Self::Account {
        &self.signer
    }

    fn payload(&self) -> &TransactionPayload<Self::Operation> {
        &self.payload
    }

    fn signature(&self) -> &Self::Signature {
        &self.signature
    }

    fn verify(&self) -> bool {
        Self::verify(self)
    }

    fn digest(&self) -> Digest {
        Self::digest(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{ed25519, Signer};

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestOperation {
        value: u64,
    }

    impl Write for TestOperation {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.value.write(buf);
        }
    }

    impl Read for TestOperation {
        type Cfg = ();

        fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, Error> {
            Ok(Self {
                value: u64::read(buf)?,
            })
        }
    }

    impl EncodeSize for TestOperation {
        fn encode_size(&self) -> usize {
            self.value.encode_size()
        }
    }

    impl TransactionOperation for TestOperation {
        const NAMESPACE: &'static [u8] = b"_NUNCHI_TEST_TRANSACTION";
    }

    type TestTransaction = SignedTransaction<ed25519::PublicKey, ed25519::Signature, TestOperation>;

    #[test]
    fn signed_transaction_supports_module_specific_operations() {
        let signer = ed25519::PrivateKey::from_seed(42);
        let transaction = TestTransaction::sign(&signer, 7, TestOperation { value: 99 });

        assert_eq!(transaction.signer, signer.public_key());
        assert_eq!(transaction.nonce(), 7);
        assert_eq!(transaction.operation().value, 99);
        assert!(transaction.verify());

        let decoded = TestTransaction::decode(transaction.encode()).unwrap();
        assert_eq!(transaction, decoded);
        assert_eq!(transaction.digest(), decoded.digest());
    }
}
