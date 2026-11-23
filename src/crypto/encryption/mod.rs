//! AEAD namespace: 1 = XChaCha20-Poly1305, 2 = AES-256-GCM-SIV.
//! Both suites are allowed for key wrapping, inode bodies and data chunks.
mod aes256_gcm_siv;
mod xchacha20_poly1305;

use super::{Error, Result, SecretKey, random_array};
use crate::format::header::{Algorithm, SealedRegion};
use chacha20poly1305::aead::AeadInPlace;

pub const XCHACHA20_POLY1305: u16 = 1;
pub const AES256_GCM_SIV: u16 = 2;
pub const TAG_SIZE: usize = 16;

pub fn algorithm(id: u16) -> Result<Algorithm> {
    let value = Algorithm::from_parameters(id, 1, &())?;
    nonce_size(&value)?;
    Ok(value)
}
pub fn nonce_size(algorithm: &Algorithm) -> Result<usize> {
    match algorithm.id {
        XCHACHA20_POLY1305 | AES256_GCM_SIV => {
            algorithm.decode_parameters::<()>(algorithm.id, 1)?;
            Ok(if algorithm.id == XCHACHA20_POLY1305 {
                24
            } else {
                12
            })
        }
        id => Err(Error::UnsupportedAlgorithm(id)),
    }
}
pub fn nonce(algorithm: &Algorithm) -> Result<Vec<u8>> {
    Ok(random_array::<24>()?[..nonce_size(algorithm)?].to_vec())
}
/// Construct metadata before calculating the object's AAD.
pub fn region(algorithm: Algorithm) -> Result<SealedRegion> {
    Ok(SealedRegion {
        nonce: nonce(&algorithm)?,
        algorithm,
        ciphertext: Vec::new(),
    })
}
/// In-place fast path. Nonces must be fresh; object-level helpers generate them.
pub fn encrypt_in_place(
    algorithm: &Algorithm,
    key: &SecretKey,
    nonce: &[u8],
    aad: &[u8],
    bytes: &mut Vec<u8>,
) -> Result<()> {
    if nonce.len() != nonce_size(algorithm)? {
        return Err(Error::Invalid("nonce length"));
    }
    match algorithm.id {
        XCHACHA20_POLY1305 => {
            xchacha20_poly1305::cipher(key).encrypt_in_place(nonce.into(), aad, bytes)
        }
        AES256_GCM_SIV => aes256_gcm_siv::cipher(key).encrypt_in_place(nonce.into(), aad, bytes),
        _ => unreachable!(),
    }
    .map_err(|_| Error::Authentication)
}
/// Encrypt a slice without allocating a second payload-sized buffer.
pub(crate) fn encrypt_detached(
    algorithm: &Algorithm,
    key: &SecretKey,
    nonce: &[u8],
    aad: &[u8],
    bytes: &mut [u8],
) -> Result<[u8; TAG_SIZE]> {
    if nonce.len() != nonce_size(algorithm)? {
        return Err(Error::Invalid("nonce length"));
    }
    let tag = match algorithm.id {
        XCHACHA20_POLY1305 => {
            xchacha20_poly1305::cipher(key).encrypt_in_place_detached(nonce.into(), aad, bytes)
        }
        AES256_GCM_SIV => {
            aes256_gcm_siv::cipher(key).encrypt_in_place_detached(nonce.into(), aad, bytes)
        }
        _ => unreachable!(),
    }
    .map_err(|_| Error::Authentication)?;
    Ok(tag.into())
}
pub fn decrypt_in_place(
    algorithm: &Algorithm,
    key: &SecretKey,
    nonce: &[u8],
    aad: &[u8],
    bytes: &mut Vec<u8>,
) -> Result<()> {
    if nonce.len() != nonce_size(algorithm)? || bytes.len() < TAG_SIZE {
        return Err(Error::Invalid("nonce or ciphertext length"));
    }
    let result = match algorithm.id {
        XCHACHA20_POLY1305 => {
            xchacha20_poly1305::cipher(key).decrypt_in_place(nonce.into(), aad, bytes)
        }
        AES256_GCM_SIV => aes256_gcm_siv::cipher(key).decrypt_in_place(nonce.into(), aad, bytes),
        _ => unreachable!(),
    };
    if result.is_err() {
        use zeroize::Zeroize;
        bytes.zeroize();
        return Err(Error::Authentication);
    }
    Ok(())
}
pub fn seal(
    region: &mut SealedRegion,
    key: &SecretKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<()> {
    // A region is single-use to prevent accidental nonce reuse.
    if !region.ciphertext.is_empty() {
        return Err(Error::Invalid("region already sealed"));
    }
    let mut bytes = plaintext.to_vec();
    encrypt_in_place(&region.algorithm, key, &region.nonce, aad, &mut bytes)?;
    region.ciphertext = bytes;
    Ok(())
}
pub fn open(
    region: &SealedRegion,
    key: &SecretKey,
    aad: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(region.ciphertext.clone());
    decrypt_in_place(&region.algorithm, key, &region.nonce, aad, &mut bytes)?;
    Ok(bytes)
}
