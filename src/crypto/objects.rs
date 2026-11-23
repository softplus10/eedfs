//! Object-level create/unlock helpers. No storage I/O or concurrency policy.
use super::{Error, Result, SecretKey, encryption as enc, kdf, naming, random_array};
use crate::format::{
    data_chunk::{self, DataChunkObject, MAX_CHUNK_PLAINTEXT},
    header::{Algorithm, Header, Keyslot, NamingConfig, ProtectedConfig},
    inode::{InodeBody, InodeObject},
};
use zeroize::Zeroizing;

pub struct UnlockedHeader {
    pub master_key: SecretKey,
    pub config: ProtectedConfig,
}
/// Create a single password slot. Callers persist only Header, never UnlockedHeader.
pub fn create_header(
    password: &[u8],
    root_inode: [u8; 16],
    suite: &Algorithm,
    parameters: &kdf::argon2id::Parameters,
) -> Result<(Header, UnlockedHeader)> {
    let fs = random_array()?;
    let master_key = SecretKey::generate()?;
    let config = ProtectedConfig {
        root_inode,
        naming: NamingConfig {
            algorithm: naming::algorithm()?,
            key: random_array()?,
        },
        extensions: Vec::new(),
    };
    let kdf = parameters.algorithm()?;
    let kek = kdf::argon2id::derive(password, &kdf)?;
    let mut slot = Keyslot {
        id: random_array()?,
        kdf,
        wrapped_master_key: enc::region(suite.clone())?,
        extensions: Vec::new(),
    };
    let aad = slot.wrapping_aad(&fs)?;
    enc::seal(&mut slot.wrapped_master_key, &kek, &aad, &master_key.0)?;
    let mut header = Header {
        filesystem_id: fs,
        keyslots: vec![slot],
        protected: enc::region(suite.clone())?,
        extensions: Vec::new(),
    };
    let key = kdf::derive(&master_key, &fs, kdf::Purpose::Header)?;
    let aad = header.protected_aad()?;
    enc::seal(
        &mut header.protected,
        &key,
        &aad,
        &Zeroizing::new(config.encode()?),
    )?;
    header.encode()?;
    Ok((header, UnlockedHeader { master_key, config }))
}
/// Explicit slot selection avoids executing every attacker-provided KDF.
pub fn unlock_header(
    header: &Header,
    password: &[u8],
    slot_id: &[u8; 16],
) -> Result<UnlockedHeader> {
    header.encode()?;
    let slot = header
        .keyslots
        .iter()
        .find(|s| &s.id == slot_id)
        .ok_or(Error::Invalid("unknown keyslot"))?;
    let kek = kdf::argon2id::derive(password, &slot.kdf)?;
    let bytes = enc::open(
        &slot.wrapped_master_key,
        &kek,
        &slot.wrapping_aad(&header.filesystem_id)?,
    )?;
    let master_key = SecretKey(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("master key length"))?,
    );
    let key = kdf::derive(&master_key, &header.filesystem_id, kdf::Purpose::Header)?;
    let bytes = enc::open(&header.protected, &key, &header.protected_aad()?)?;
    let config = ProtectedConfig::decode(&bytes)?;
    naming::inode(&config.naming, &header.filesystem_id, &config.root_inode)?;
    Ok(UnlockedHeader { master_key, config })
}

pub fn seal_inode(
    master_key: &SecretKey,
    inode_key: &SecretKey,
    fs: &[u8; 16],
    object_key: &str,
    suite: &Algorithm,
    body: &InodeBody,
) -> Result<InodeObject> {
    let plaintext = Zeroizing::new(body.encode()?);
    let wrap_key = kdf::derive(master_key, fs, kdf::Purpose::InodeWrapping)?;
    let body_key = kdf::derive(inode_key, fs, kdf::Purpose::InodeBody)?;
    let mut object = InodeObject {
        wrapped_inode_key: enc::region(suite.clone())?,
        protected: enc::region(suite.clone())?,
        extensions: Vec::new(),
    };
    let aad = object.wrapping_aad(fs, object_key)?;
    enc::seal(&mut object.wrapped_inode_key, &wrap_key, &aad, &inode_key.0)?;
    let aad = object.protected_aad(fs, object_key)?;
    enc::seal(&mut object.protected, &body_key, &aad, &plaintext)?;
    object.encode()?;
    Ok(object)
}
pub fn open_inode(
    master_key: &SecretKey,
    fs: &[u8; 16],
    object_key: &str,
    expected_id: &[u8; 16],
    object: &InodeObject,
) -> Result<(SecretKey, InodeBody)> {
    object.encode()?;
    let wrap_key = kdf::derive(master_key, fs, kdf::Purpose::InodeWrapping)?;
    let bytes = enc::open(
        &object.wrapped_inode_key,
        &wrap_key,
        &object.wrapping_aad(fs, object_key)?,
    )?;
    let key = SecretKey(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Invalid("inode key length"))?,
    );
    let body = open_shared_inode(&key, fs, object_key, expected_id, object)?;
    Ok((key, body))
}
/// A recipient can open with a separately granted inode key without the master key.
pub fn open_shared_inode(
    inode_key: &SecretKey,
    fs: &[u8; 16],
    object_key: &str,
    expected_id: &[u8; 16],
    object: &InodeObject,
) -> Result<InodeBody> {
    object.encode()?;
    let key = kdf::derive(inode_key, fs, kdf::Purpose::InodeBody)?;
    let bytes = enc::open(
        &object.protected,
        &key,
        &object.protected_aad(fs, object_key)?,
    )?;
    let body = InodeBody::decode(&bytes)?;
    if &body.id != expected_id {
        return Err(Error::Invalid("inode ID mismatch"));
    }
    Ok(body)
}

/// The inode's shared encryption profile must remain unchanged while old chunks
/// are referenced. Fresh random nonce on every call, fresh allocation ID per run.
pub fn seal_chunk(
    inode_key: &SecretKey,
    fs: &[u8; 16],
    object_key: &str,
    suite: &Algorithm,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_CHUNK_PLAINTEXT {
        return Err(Error::Invalid("chunk length"));
    }
    let key = kdf::derive(inode_key, fs, kdf::Purpose::DataChunk)?;
    let nonce = enc::nonce(suite)?;
    let aad = data_chunk::aad(fs, object_key, suite, &nonce, plaintext.len() as u32)?;
    let mut out = Vec::with_capacity(nonce.len() + plaintext.len() + enc::TAG_SIZE);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = enc::encrypt_detached(suite, &key, &nonce, &aad, &mut out[nonce.len()..])?;
    out.extend_from_slice(&tag);
    Ok(out)
}
pub fn open_chunk(
    inode_key: &SecretKey,
    fs: &[u8; 16],
    object_key: &str,
    suite: &Algorithm,
    expected_len: u32,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let chunk = DataChunkObject::decode(bytes, suite, expected_len)?;
    let key = kdf::derive(inode_key, fs, kdf::Purpose::DataChunk)?;
    let aad = data_chunk::aad(fs, object_key, suite, chunk.nonce, expected_len)?;
    let mut plaintext = Zeroizing::new(chunk.ciphertext.to_vec());
    enc::decrypt_in_place(suite, &key, chunk.nonce, &aad, &mut plaintext)?;
    Ok(plaintext)
}
