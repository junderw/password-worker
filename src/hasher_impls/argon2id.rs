use argon2::{Variant, Version};

use crate::{Hasher, PasswordWorker, PasswordWorkerError};

/// Use this type in the generic constructor to use argon2id
#[derive(Clone, Copy, Debug)]
pub enum Argon2id {}

impl Hasher for Argon2id {
    type Config = Argon2idConfig;
    type Error = argon2::Error;

    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error> {
        let mut argon_config = argon2::Config::default();

        // Change defaults
        argon_config.variant = Variant::Argon2id;
        argon_config.version = Version::Version13;

        argon_config.time_cost = config.time_cost;
        argon_config.mem_cost = config.mem_cost;
        argon_config.lanes = config.lanes;
        argon_config.hash_length = config.hash_length;

        argon2::hash_encoded(data.as_ref(), config.salt.as_bytes(), &argon_config)
    }

    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error> {
        argon2::verify_encoded(hash, data.as_ref())
    }
}

/// The configuration attributes needed to perform argon2id hashing
///
/// This implements Default using the default values from the rust-argon2 crate
/// with the salt being an empty String.
///
/// ```
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use axum_password_worker::{Argon2id, Argon2idConfig, PasswordWorker};
///
/// let password = "hunter2";
/// let salt = "deadbeef".into();
/// let max_threads = 4;
/// let password_worker = PasswordWorker::<Argon2id>::new(max_threads)?;
///
/// let hashed_password = password_worker
///     .hash(
///         password,
///         Argon2idConfig {
///             salt,
///             ..Default::default()
///         },
///     )
///     .await?;
/// println!("Hashed password: {:?}", hashed_password);
///
/// let is_valid = password_worker.verify(password, hashed_password).await?;
/// println!("Verification result: {:?}", is_valid);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Argon2idConfig {
    pub salt: String,
    pub time_cost: u32,
    pub mem_cost: u32,
    pub lanes: u32,
    pub hash_length: u32,
}

impl Default for Argon2idConfig {
    fn default() -> Self {
        Self {
            salt: String::new(),
            time_cost: 3,
            mem_cost: 4096,
            lanes: 1,
            hash_length: 32,
        }
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "rust-argon2")))]
impl PasswordWorker<Argon2id> {
    /// This constructor creates a new argon2id instance
    pub fn new_argon2id(max_threads: usize) -> Result<Self, PasswordWorkerError<Argon2id>> {
        PasswordWorker::<Argon2id>::new(max_threads)
    }
}
