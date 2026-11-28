//! Names are 64 lowercase hex characters, without revealing object type.
pub mod hmac_sha256;
use crate::{
    crypto::{Error, Result},
    format::header::{Algorithm, NamingConfig},
};

pub const HMAC_SHA256: u16 = 1;
pub fn algorithm() -> Result<Algorithm> {
    Ok(Algorithm::from_parameters(HMAC_SHA256, 1, &())?)
}
fn validate(config: &NamingConfig) -> Result<()> {
    if config.algorithm.id != HMAC_SHA256 {
        return Err(Error::UnsupportedAlgorithm(config.algorithm.id));
    }
    config.algorithm.decode_parameters::<()>(HMAC_SHA256, 1)?;
    Ok(())
}
pub fn inode(
    config: &NamingConfig,
    filesystem_id: &[u8; 16],
    inode_id: &[u8; 16],
) -> Result<String> {
    validate(config)?;
    Ok(hmac_sha256::name(
        &config.key,
        &[b"CoCryptFS/inode-name/v1\0", filesystem_id, inode_id],
    ))
}
pub fn chunk(
    config: &NamingConfig,
    filesystem_id: &[u8; 16],
    allocation_id: &[u8; 16],
    index: u64,
) -> Result<String> {
    validate(config)?;
    Ok(hmac_sha256::name(
        &config.key,
        &[
            b"CoCryptFS/chunk-name/v1\0",
            filesystem_id,
            allocation_id,
            &index.to_le_bytes(),
        ],
    ))
}
