use crate::{
    crypto::{Error, Result, SecretKey, random_array},
    format::header::Algorithm,
};
use argon2::{Argon2, Params, Version};
use serde::{Deserialize, Serialize};

pub const ID: u16 = 1;
/// Argon2id v19. Resource caps are enforced before allocating memory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Parameters {
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}
impl Parameters {
    pub fn recommended() -> Result<Self> {
        Ok(Self {
            salt: random_array()?,
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        })
    }
    pub fn algorithm(&self) -> Result<Algorithm> {
        self.validate()?;
        Ok(Algorithm::from_parameters(ID, 1, self)?)
    }
    fn validate(&self) -> Result<Params> {
        if !(8192..=262144).contains(&self.memory_kib)
            || !(1..=10).contains(&self.iterations)
            || !(1..=16).contains(&self.parallelism)
        {
            return Err(Error::Invalid("Argon2 resource policy"));
        }
        Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| Error::Invalid("Argon2 parameters"))
    }
}
pub fn derive(password: &[u8], algorithm: &Algorithm) -> Result<SecretKey> {
    if algorithm.id != ID {
        return Err(Error::UnsupportedAlgorithm(algorithm.id));
    }
    let p: Parameters = algorithm.decode_parameters(ID, 1)?;
    let params = p.validate()?;
    let mut key = SecretKey([0; 32]);
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, &p.salt, &mut key.0)
        .map_err(|_| Error::Invalid("Argon2 input"))?;
    Ok(key)
}
