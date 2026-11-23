use crate::crypto::{Result, SecretKey};
use hkdf::Hkdf;
use sha2::Sha256;

pub enum Purpose {
    Header,
    InodeWrapping,
    InodeBody,
    DataChunk,
}
impl Purpose {
    fn label(&self) -> &'static [u8] {
        match self {
            Self::Header => b"EEDFS/v1/header-config",
            Self::InodeWrapping => b"EEDFS/v1/inode-wrapping",
            Self::InodeBody => b"EEDFS/v1/inode-body",
            Self::DataChunk => b"EEDFS/v1/data-chunk",
        }
    }
}
/// HKDF-SHA256, filesystem ID as salt, fixed purpose label as info.
pub fn derive(key: &SecretKey, filesystem_id: &[u8; 16], purpose: Purpose) -> Result<SecretKey> {
    let mut out = SecretKey([0; 32]);
    Hkdf::<Sha256>::new(Some(filesystem_id), &key.0)
        .expand(purpose.label(), &mut out.0)
        .map_err(|_| crate::crypto::Error::Invalid("HKDF output length"))?;
    Ok(out)
}
