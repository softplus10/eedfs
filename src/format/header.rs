//! Serde/Postcard header codec. See `docs/header-format.md` for the wire schema.
//! Decoding does not authenticate ciphertext or validate algorithm-specific parameters.

use std::collections::BTreeSet;
use std::fmt;

use super::codec::{
    bounded, bounded_bytes, decode_value, encode_value, object_key as root_key, serialize_bytes,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

const MAGIC: &[u8; 8] = b"EEDFSHDR";
const CONFIG_MAGIC: &[u8; 8] = b"EEDFSCFG";
/// Version 3 adds protected naming configuration to the Postcard schema.
pub const VERSION: u16 = 3;
pub const MAX_SIZE: usize = 1024 * 1024;
pub const MAX_KEYSLOTS: usize = 64;
pub const MAX_PARAMETERS: usize = 4096;
pub const MAX_EXTENSIONS: usize = 64;
const MAX_NONCE: usize = 64;

/// Nonzero numeric ID plus parameters serialized using that algorithm's schema.
/// KDF, AEAD and naming-scheme IDs have separate namespaces. Never use a Rust enum's position as an ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm {
    pub id: u16,
    #[serde(deserialize_with = "bounded::<_, _, MAX_PARAMETERS>")]
    pub parameters: Vec<u8>,
}

/// Ciphertext includes the authentication tag. Nonces belong here, not in defaults.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRegion<const MAX_CIPHERTEXT: usize = MAX_SIZE> {
    pub algorithm: Algorithm,
    #[serde(deserialize_with = "bounded::<_, _, MAX_NONCE>")]
    pub nonce: Vec<u8>,
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "bounded_bytes::<_, MAX_CIPHERTEXT>"
    )]
    pub ciphertext: Vec<u8>,
}

/// Forward-compatible record, distinct from an algorithm's required parameters.
/// Unknown optional records are preserved; unknown required records are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extension {
    pub kind: u16,
    pub required: bool,
    #[serde(deserialize_with = "bounded::<_, _, MAX_SIZE>")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: [u8; 16],
    pub kdf: Algorithm,
    pub wrapped_master_key: SealedRegion,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub filesystem_id: [u8; 16],
    #[serde(deserialize_with = "bounded::<_, _, MAX_KEYSLOTS>")]
    pub keyslots: Vec<Keyslot>,
    pub protected: SealedRegion,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}

/// Secret naming configuration stored only in the encrypted protected payload.
/// Key generation and HMAC evaluation are implemented by the future crypto layer.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingConfig {
    pub algorithm: Algorithm,
    pub key: [u8; 32],
}

impl fmt::Debug for NamingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamingConfig")
            .field("algorithm", &self.algorithm)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// Plaintext to encrypt into the protected region; never upload it directly.
/// The root inode will carry its own wrapped inode key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedConfig {
    #[serde(deserialize_with = "root_key")]
    pub root_inode: String,
    pub inode_encryption: Algorithm,
    pub data_encryption: Algorithm,
    pub naming: NamingConfig,
    #[serde(deserialize_with = "bounded::<_, _, MAX_EXTENSIONS>")]
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    TooLarge,
    Invalid(&'static str),
    UnsupportedVersion(u16),
    RequiredExtension(u16),
    Codec(postcard::Error),
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated storage object"),
            Self::TooLarge => write!(f, "storage format limit exceeded"),
            Self::Invalid(reason) => write!(f, "invalid storage object: {reason}"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported storage format version {version}")
            }
            Self::RequiredExtension(kind) => {
                write!(f, "unsupported required extension {kind:#06x}")
            }
            Self::Codec(error) => write!(f, "invalid Postcard encoding: {error}"),
        }
    }
}
impl std::error::Error for FormatError {}
impl From<postcard::Error> for FormatError {
    fn from(error: postcard::Error) -> Self {
        Self::Codec(error)
    }
}
type Result<T> = std::result::Result<T, FormatError>;

impl Algorithm {
    pub(super) fn validate(&self) -> Result<()> {
        if self.id == 0 || self.parameters.len() > MAX_PARAMETERS {
            return Err(FormatError::Invalid("algorithm descriptor"));
        }
        Ok(())
    }

    /// Serialize a typed parameter structure without introducing a global union.
    /// The algorithm module defines/validates T and assigns a stable numeric ID.
    pub fn from_parameters<T: Serialize>(
        id: u16,
        schema_version: u16,
        parameters: &T,
    ) -> Result<Self> {
        if schema_version == 0 {
            return Err(FormatError::Invalid("parameter schema version"));
        }
        let algorithm = Self {
            id,
            parameters: encode_value(&(schema_version, parameters), MAX_PARAMETERS)?,
        };
        algorithm.validate()?;
        Ok(algorithm)
    }

    /// Decode only when the caller recognizes this ID and its parameter schema.
    /// Resource/cryptographic constraints still need algorithm-specific validation.
    pub fn decode_parameters<T: DeserializeOwned + Serialize>(
        &self,
        expected_id: u16,
        expected_schema_version: u16,
    ) -> Result<T> {
        self.validate()?;
        if self.id != expected_id {
            return Err(FormatError::Invalid("unexpected algorithm ID"));
        }
        let (version, rest): (u16, _) = postcard::take_from_bytes(&self.parameters)?;
        if version == 0 || version != expected_schema_version {
            return Err(FormatError::Invalid("unexpected parameter schema version"));
        }
        let parameters: T = decode_value(rest)?;
        if encode_value(&(version, &parameters), MAX_PARAMETERS)? != self.parameters {
            return Err(FormatError::Invalid("noncanonical parameter encoding"));
        }
        Ok(parameters)
    }
}
impl<const MAX_CIPHERTEXT: usize> SealedRegion<MAX_CIPHERTEXT> {
    pub(super) fn validate_descriptor(&self) -> Result<()> {
        self.algorithm.validate()?;
        if self.nonce.len() > MAX_NONCE {
            return Err(FormatError::Invalid("nonce length"));
        }
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<()> {
        self.validate_descriptor()?;
        if self.ciphertext.len() < 16 {
            return Err(FormatError::Invalid("ciphertext/tag length"));
        }
        if self.ciphertext.len() > MAX_CIPHERTEXT {
            return Err(FormatError::TooLarge);
        }
        Ok(())
    }
}
impl Keyslot {
    fn validate(&self) -> Result<()> {
        self.kdf.validate()?;
        self.wrapped_master_key.validate()?;
        validate_extensions(&self.extensions)
    }

    /// Canonical AAD for the wrapped key, excluding its own ciphertext. Not a MAC.
    pub fn wrapping_aad(&self, filesystem_id: &[u8; 16]) -> Result<Vec<u8>> {
        self.kdf.validate()?;
        self.wrapped_master_key.validate_descriptor()?;
        validate_extensions(&self.extensions)?;
        aad(
            b"EEDFS/keyslot\0",
            &(
                VERSION,
                filesystem_id,
                self.id,
                &self.kdf,
                &self.wrapped_master_key.algorithm,
                &self.wrapped_master_key.nonce,
                &self.extensions,
            ),
        )
    }
}
impl Header {
    fn validate_public(&self) -> Result<()> {
        if self.keyslots.is_empty() || self.keyslots.len() > MAX_KEYSLOTS {
            return Err(FormatError::Invalid("keyslot count"));
        }
        let mut ids = BTreeSet::new();
        for slot in &self.keyslots {
            if !ids.insert(slot.id) {
                return Err(FormatError::Invalid("duplicate keyslot ID"));
            }
            slot.validate()?;
        }
        self.protected.validate_descriptor()?;
        validate_extensions(&self.extensions)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_public()?;
        self.protected.validate()?;
        frame(MAGIC, self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header: Self = unframe(MAGIC, bytes)?;
        header.validate_public()?;
        header.protected.validate()?;
        Ok(header)
    }
    /// Canonical AAD, excluding this region's own ciphertext. Not a MAC.
    /// Slot edits require fresh protected-region encryption/authentication.
    pub fn protected_aad(&self) -> Result<Vec<u8>> {
        self.validate_public()?;
        aad(
            b"EEDFS/header-config\0",
            &(
                VERSION,
                self.filesystem_id,
                &self.keyslots,
                &self.protected.algorithm,
                &self.protected.nonce,
                &self.extensions,
            ),
        )
    }
}
impl ProtectedConfig {
    fn validate(&self) -> Result<()> {
        validate_root(&self.root_inode)?;
        self.inode_encryption.validate()?;
        self.data_encryption.validate()?;
        self.naming.algorithm.validate()?;
        validate_extensions(&self.extensions)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        frame(CONFIG_MAGIC, self)
    }
    /// Use only after authenticating/decrypting the protected region.
    pub fn decode(plaintext: &[u8]) -> Result<Self> {
        let config: Self = unframe(CONFIG_MAGIC, plaintext)?;
        config.validate()?;
        Ok(config)
    }
}
fn validate_root(root: &str) -> Result<()> {
    if root.is_empty() || root.len() > 1024 {
        return Err(FormatError::Invalid("root inode object key length"));
    }
    Ok(())
}
pub(super) fn validate_extensions(extensions: &[Extension]) -> Result<()> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(FormatError::TooLarge);
    }
    let mut previous = 0x7fff;
    for extension in extensions {
        if extension.required {
            return Err(FormatError::RequiredExtension(extension.kind));
        }
        if extension.kind <= previous {
            return Err(FormatError::Invalid("extension order or type"));
        }
        if extension.value.len() > MAX_SIZE {
            return Err(FormatError::TooLarge);
        }
        previous = extension.kind;
    }
    Ok(())
}

// Header v3 keeps its original framing and byte layout.
fn frame<T: Serialize>(magic: &[u8; 8], value: &T) -> Result<Vec<u8>> {
    super::codec::frame(magic, VERSION, MAX_SIZE, value)
}
fn unframe<T: DeserializeOwned + Serialize>(magic: &[u8; 8], bytes: &[u8]) -> Result<T> {
    super::codec::unframe(magic, VERSION, MAX_SIZE, bytes)
}
fn aad<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let mut out = domain.to_vec();
    out.extend_from_slice(&encode_value(value, MAX_SIZE - domain.len())?);
    Ok(out)
}
