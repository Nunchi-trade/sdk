use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{
            Activity as CActivity, Context as CContext, Finalization as CFinalization,
            Notarization as CNotarization,
        },
    },
    types::Epoch,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinSig, Variant},
    ed25519,
    sha256::Digest,
};
use commonware_utils::NZU64;
use std::num::NonZero;

pub type Context = CContext<Digest, PublicKey>;

pub type Scheme = vrf::Scheme<PublicKey, MinSig>;
pub type Seed = vrf::Seed<MinSig>;
pub use vrf::Seedable;
pub type Notarization = CNotarization<Scheme, Digest>;
pub type Finalization = CFinalization<Scheme, Digest>;
pub type Activity = CActivity<Scheme, Digest>;

pub type PublicKey = ed25519::PublicKey;
pub type Identity = <MinSig as Variant>::Public;
pub type Signature = <MinSig as Variant>::Signature;

pub const NAMESPACE: &[u8] = b"_NUNCHI_COINSCHAIN";
pub const EPOCH: Epoch = Epoch::zero();
pub const EPOCH_LENGTH: NonZero<u64> = NZU64!(u64::MAX);
