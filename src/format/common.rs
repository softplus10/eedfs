//! Shared metadata limits and authentication-context helpers.
use super::{
    codec,
    header::{Extension, FormatError, validate_extensions as validate_base_extensions},
};
use serde::Serialize;
type Result<T> = std::result::Result<T, FormatError>;
pub(super) const MAX_METADATA_SIZE: usize = 1024 * 1024;
pub const MAX_OBJECT_EXTENSION: usize = 4096;

pub(super) fn object_aad<T: Serialize>(
    domain: &[u8],
    version: u16,
    filesystem_id: &[u8; 16],
    key: &str,
    metadata: &T,
) -> Result<Vec<u8>> {
    codec::validate_object_key(key)?;
    let mut out = domain.to_vec();
    out.extend_from_slice(&codec::encode_value(
        &(version, filesystem_id, key, metadata),
        MAX_METADATA_SIZE + 2048 - domain.len(),
    )?);
    Ok(out)
}

pub(super) fn validate_extensions(extensions: &[Extension]) -> Result<()> {
    validate_base_extensions(extensions)?;
    if extensions
        .iter()
        .any(|extension| extension.value.len() > MAX_OBJECT_EXTENSION)
    {
        return Err(FormatError::TooLarge);
    }
    Ok(())
}
