//! Dependency-free header codec. See `docs/header-format.md` for the wire format.
//!
//! This module never derives keys or encrypts/decrypts data. A decoded header is
//! untrusted until a cryptographic implementation authenticates it.

use std::collections::BTreeSet;
use std::fmt;

const MAGIC: &[u8; 8] = b"EEDFSHDR";
const CONFIG_MAGIC: &[u8; 8] = b"EEDFSCFG";
pub const VERSION: u16 = 1;
pub const MAX_SIZE: usize = 1024 * 1024;
pub const MAX_KEYSLOTS: usize = 64;
pub const MAX_PARAMETERS: usize = 4096;
pub const MAX_EXTENSIONS: usize = 64;
const EXTENSION_MIN: u16 = 0x8000;
const REQUIRED: u16 = 1;

/// Algorithm IDs have separate KDF and AEAD namespaces; zero is reserved.
/// Parameters are opaque here and must be validated by the algorithm implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Algorithm {
    pub id: u16,
    pub parameters: Vec<u8>,
}

/// Ciphertext includes the authentication tag. No plaintext key belongs here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRegion {
    pub algorithm: Algorithm,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Optional extension. Unknown optional fields survive decode/encode unchanged.
/// Types must be unique, increasing, and at least 0x8000.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub kind: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keyslot {
    pub id: [u8; 16],
    pub kdf: Algorithm,
    pub wrapped_master_key: SealedRegion,
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub filesystem_id: [u8; 16],
    pub keyslots: Vec<Keyslot>,
    pub protected: SealedRegion,
    pub extensions: Vec<Extension>,
}

/// Plaintext representation of the encrypted configuration, not a second S3 object.
/// The root inode carries its own wrapped inode key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedConfig {
    pub root_inode: String,
    pub inode_encryption: Algorithm,
    pub data_encryption: Algorithm,
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    TooLarge,
    Invalid(&'static str),
    UnsupportedVersion(u16),
    RequiredExtension(u16),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated header"),
            Self::TooLarge => write!(f, "header format limit exceeded"),
            Self::Invalid(reason) => write!(f, "invalid header: {reason}"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported header version {version}"),
            Self::RequiredExtension(kind) => {
                write!(f, "unsupported required extension {kind:#06x}")
            }
        }
    }
}
impl std::error::Error for FormatError {}
type Result<T> = std::result::Result<T, FormatError>;

impl Header {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut body = Writer::default();
        body.raw(&self.filesystem_id)?;
        body.field(1, REQUIRED, &self.slots_bytes()?)?;
        let mut protected = Writer::default();
        protected.sealed(&self.protected)?;
        body.field(2, REQUIRED, &protected.0)?;
        body.extensions(&self.extensions)?;
        frame(MAGIC, body.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut body = unframe(MAGIC, bytes)?;
        let filesystem_id = body.take(16)?.try_into().unwrap();
        let mut slots = body.required_field(1)?;
        let count = slots.u32()? as usize;
        if count == 0 || count > MAX_KEYSLOTS {
            return Err(FormatError::Invalid("keyslot count"));
        }
        let mut keyslots = Vec::with_capacity(count);
        let mut ids = BTreeSet::new();
        for _ in 0..count {
            let mut slot = Reader(slots.blob()?);
            let id = slot.take(16)?.try_into().unwrap();
            if !ids.insert(id) {
                return Err(FormatError::Invalid("duplicate keyslot ID"));
            }
            keyslots.push(Keyslot {
                id,
                kdf: slot.algorithm()?,
                wrapped_master_key: slot.sealed()?,
                extensions: slot.extensions()?,
            });
        }
        slots.end()?;
        let mut protected = body.required_field(2)?;
        let protected_region = protected.sealed()?;
        protected.end()?;
        Ok(Self {
            filesystem_id,
            keyslots,
            protected: protected_region,
            extensions: body.extensions()?,
        })
    }

    fn slots_bytes(&self) -> Result<Vec<u8>> {
        if self.keyslots.is_empty() || self.keyslots.len() > MAX_KEYSLOTS {
            return Err(FormatError::Invalid("keyslot count"));
        }
        let mut out = Writer::default();
        out.u32(self.keyslots.len() as u32)?;
        let mut ids = BTreeSet::new();
        for slot in &self.keyslots {
            if !ids.insert(slot.id) {
                return Err(FormatError::Invalid("duplicate keyslot ID"));
            }
            let mut encoded = Writer::default();
            encoded.raw(&slot.id)?;
            encoded.algorithm(&slot.kdf)?;
            encoded.sealed(&slot.wrapped_master_key)?;
            encoded.extensions(&slot.extensions)?;
            out.blob(&encoded.0)?;
        }
        Ok(out.0)
    }

    /// Canonical AAD for the protected configuration. This is NOT a MAC.
    /// Authenticate with the header key and this region's nonce/ciphertext.
    /// Keyslot edits require re-authenticating the protected configuration.
    pub fn protected_aad(&self) -> Result<Vec<u8>> {
        let mut out = Writer::default();
        out.raw(b"EEDFS/header-config\0")?;
        out.u16(VERSION)?;
        out.raw(&self.filesystem_id)?;
        out.blob(&self.slots_bytes()?)?;
        out.algorithm(&self.protected.algorithm)?;
        out.nonce(&self.protected.nonce)?;
        out.extensions(&self.extensions)?;
        Ok(out.0)
    }
}

impl Keyslot {
    /// Canonical AAD for wrapping this slot's master key. Ciphertext is excluded.
    pub fn wrapping_aad(&self, filesystem_id: &[u8; 16]) -> Result<Vec<u8>> {
        let mut out = Writer::default();
        out.raw(b"EEDFS/keyslot\0")?;
        out.u16(VERSION)?;
        out.raw(filesystem_id)?;
        out.raw(&self.id)?;
        out.algorithm(&self.kdf)?;
        out.algorithm(&self.wrapped_master_key.algorithm)?;
        out.nonce(&self.wrapped_master_key.nonce)?;
        out.extensions(&self.extensions)?;
        Ok(out.0)
    }
}

impl ProtectedConfig {
    /// Encode plaintext for subsequent AEAD encryption. Never upload this directly.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_root(&self.root_inode)?;
        let mut out = Writer::default();
        out.field(1, REQUIRED, self.root_inode.as_bytes())?;
        let mut algorithms = Writer::default();
        algorithms.algorithm(&self.inode_encryption)?;
        algorithms.algorithm(&self.data_encryption)?;
        out.field(2, REQUIRED, &algorithms.0)?;
        out.extensions(&self.extensions)?;
        frame(CONFIG_MAGIC, out.0)
    }

    /// Parse only AFTER successful authentication/decryption of the protected region.
    pub fn decode(plaintext: &[u8]) -> Result<Self> {
        let mut body = unframe(CONFIG_MAGIC, plaintext)?;
        let root = body.required_field(1)?;
        let root_inode = std::str::from_utf8(root.0)
            .map_err(|_| FormatError::Invalid("root inode key is not UTF-8"))?;
        validate_root(root_inode)?;
        let mut algorithms = body.required_field(2)?;
        let inode_encryption = algorithms.algorithm()?;
        let data_encryption = algorithms.algorithm()?;
        algorithms.end()?;
        Ok(Self {
            root_inode: root_inode.to_owned(),
            inode_encryption,
            data_encryption,
            extensions: body.extensions()?,
        })
    }
}

fn validate_root(root: &str) -> Result<()> {
    if root.is_empty() || root.len() > 1024 {
        return Err(FormatError::Invalid("root inode object key length"));
    }
    Ok(())
}

fn frame(magic: &[u8; 8], body: Vec<u8>) -> Result<Vec<u8>> {
    let mut out = Writer::default();
    out.raw(magic)?;
    out.u16(VERSION)?;
    out.u16(0)?; // Reserved flags must remain zero in v1.
    out.blob(&body)?;
    Ok(out.0)
}

fn unframe<'a>(magic: &[u8; 8], bytes: &'a [u8]) -> Result<Reader<'a>> {
    if bytes.len() > MAX_SIZE {
        return Err(FormatError::TooLarge);
    }
    let mut input = Reader(bytes);
    if input.take(8)? != magic {
        return Err(FormatError::Invalid("magic"));
    }
    let version = input.u16()?;
    if version != VERSION {
        return Err(FormatError::UnsupportedVersion(version));
    }
    if input.u16()? != 0 {
        return Err(FormatError::Invalid("reserved flags"));
    }
    let body = input.blob()?;
    input.end()?;
    Ok(Reader(body))
}

#[derive(Default)]
struct Writer(Vec<u8>);
impl Writer {
    fn raw(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_SIZE.saturating_sub(self.0.len()) {
            return Err(FormatError::TooLarge);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }
    fn u16(&mut self, value: u16) -> Result<()> {
        self.raw(&value.to_le_bytes())
    }
    fn u32(&mut self, value: u32) -> Result<()> {
        self.raw(&value.to_le_bytes())
    }
    fn blob(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_SIZE {
            return Err(FormatError::TooLarge);
        }
        self.u32(bytes.len() as u32)?;
        self.raw(bytes)
    }
    fn field(&mut self, kind: u16, flags: u16, value: &[u8]) -> Result<()> {
        self.u16(kind)?;
        self.u16(flags)?;
        self.blob(value)
    }
    fn algorithm(&mut self, value: &Algorithm) -> Result<()> {
        if value.id == 0 || value.parameters.len() > MAX_PARAMETERS {
            return Err(FormatError::Invalid("algorithm descriptor"));
        }
        self.u16(value.id)?;
        self.blob(&value.parameters)
    }
    fn nonce(&mut self, nonce: &[u8]) -> Result<()> {
        if nonce.len() > 64 {
            return Err(FormatError::Invalid("nonce length"));
        }
        self.blob(nonce)
    }
    fn sealed(&mut self, value: &SealedRegion) -> Result<()> {
        self.algorithm(&value.algorithm)?;
        self.nonce(&value.nonce)?;
        if value.ciphertext.len() < 16 {
            return Err(FormatError::Invalid("ciphertext/tag length"));
        }
        self.blob(&value.ciphertext)
    }
    fn extensions(&mut self, extensions: &[Extension]) -> Result<()> {
        if extensions.len() > MAX_EXTENSIONS {
            return Err(FormatError::TooLarge);
        }
        let mut previous = EXTENSION_MIN - 1;
        for extension in extensions {
            if extension.kind <= previous {
                return Err(FormatError::Invalid("extension order or type"));
            }
            previous = extension.kind;
            self.field(extension.kind, 0, &extension.value)?;
        }
        Ok(())
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.0.len() {
            return Err(FormatError::Truncated);
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn required_field(&mut self, expected: u16) -> Result<Reader<'a>> {
        if self.u16()? != expected || self.u16()? != REQUIRED {
            return Err(FormatError::Invalid("required field order, type or flags"));
        }
        Ok(Reader(self.blob()?))
    }
    fn algorithm(&mut self) -> Result<Algorithm> {
        let id = self.u16()?;
        let parameters = self.blob()?;
        if id == 0 || parameters.len() > MAX_PARAMETERS {
            return Err(FormatError::Invalid("algorithm descriptor"));
        }
        Ok(Algorithm {
            id,
            parameters: parameters.to_vec(),
        })
    }
    fn sealed(&mut self) -> Result<SealedRegion> {
        let algorithm = self.algorithm()?;
        let nonce = self.blob()?;
        if nonce.len() > 64 {
            return Err(FormatError::Invalid("nonce length"));
        }
        let ciphertext = self.blob()?;
        if ciphertext.len() < 16 {
            return Err(FormatError::Invalid("ciphertext/tag length"));
        }
        Ok(SealedRegion {
            algorithm,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
    fn extensions(&mut self) -> Result<Vec<Extension>> {
        let mut out = Vec::new();
        let mut previous = EXTENSION_MIN - 1;
        while !self.0.is_empty() {
            let kind = self.u16()?;
            let flags = self.u16()?;
            if flags & !REQUIRED != 0 {
                return Err(FormatError::Invalid("extension flags"));
            }
            if flags & REQUIRED != 0 {
                return Err(FormatError::RequiredExtension(kind));
            }
            if kind <= previous {
                return Err(FormatError::Invalid("extension order or type"));
            }
            if out.len() >= MAX_EXTENSIONS {
                return Err(FormatError::TooLarge);
            }
            previous = kind;
            let value = self.blob()?.to_vec();
            out.push(Extension { kind, value });
        }
        Ok(out)
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(FormatError::Invalid("trailing bytes"))
        }
    }
}
