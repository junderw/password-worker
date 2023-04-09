use argon2::{Variant, Version};

use crate::{Hasher, PasswordWorker, PasswordWorkerError};

/// Use this type in the generic constructor to use argon2id
///
/// ```
/// # fn get_rand() -> Vec<u8> { vec![1, 2, 3, 4, 5, 6, 7, 8] }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use axum_password_worker::{Argon2id, Argon2idConfig, PasswordWorker};
///
/// let password = "hunter2";
/// let salt: Vec<u8> = get_rand(); // Min length 8 bytes
/// let max_threads = 4;
/// let password_worker = PasswordWorker::<Argon2id>::new(max_threads)?;
/// // let password_worker = PasswordWorker::new_argon2id(max_threads)?;
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
        argon_config.hash_length = config.hash_length;

        argon2::hash_encoded(data.as_ref(), &config.salt, &argon_config)
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
/// # fn get_rand() -> Vec<u8> { vec![1, 2, 3, 4, 5, 6, 7, 8] }
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use axum_password_worker::Argon2idConfig;
///
/// let salt: Vec<u8> = get_rand(); // Min length 8 bytes
/// let config = Argon2idConfig {
///     salt,
///     ..Default::default()
/// };
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Argon2idConfig {
    /// The salt for the password hash (Minimum length 8 bytes)
    pub salt: Vec<u8>,
    /// The time cost (higher takes longer)
    pub time_cost: u32,
    /// Memory cost (higher takes longer)
    pub mem_cost: u32,
    /// Length of hash output
    pub hash_length: u32,
}

impl Default for Argon2idConfig {
    fn default() -> Self {
        Self {
            salt: Vec::new(),
            time_cost: 3,
            mem_cost: 4096,
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
