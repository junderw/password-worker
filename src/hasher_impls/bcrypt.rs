use crate::Hasher;

/// Use this type in the generic constructor to use bcrypt
#[derive(Clone, Copy, Debug)]
pub enum Bcrypt {}

impl Hasher for Bcrypt {
    type Config = BcryptConfig;
    type Error = bcrypt::BcryptError;

    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error> {
        bcrypt::hash(data, config.cost)
    }

    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error> {
        bcrypt::verify(data, hash)
    }
}

/// The configuration attributes needed to perform bcrypt hashing
#[derive(Clone, Copy)]
pub struct BcryptConfig {
    pub cost: u32,
}
