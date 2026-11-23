//! Authenticated object encryption. Formats are experimental, not security audited.
pub mod encryption;
pub mod kdf;
pub mod naming;
pub mod objects;

use crate::format::header::FormatError;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub enum Error {
    Format(FormatError),
    UnsupportedAlgorithm(u16),
    Invalid(&'static str),
    Authentication,
    Random,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(e) => e.fmt(f),
            Self::UnsupportedAlgorithm(id) => write!(f, "unsupported algorithm {id}"),
            Self::Invalid(s) => write!(f, "invalid crypto input: {s}"),
            Self::Authentication => write!(f, "authentication failed"),
            Self::Random => write!(f, "operating system randomness unavailable"),
        }
    }
}
impl std::error::Error for Error {}
impl From<FormatError> for Error {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}

/// Not Clone/Debug/Serialize: callers must explicitly manage key copies.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub(crate) [u8; 32]);
impl SecretKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(random_array()?))
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    getrandom::getrandom(&mut bytes).map_err(|_| Error::Random)?;
    Ok(bytes)
}
