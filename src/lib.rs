//! A module providing a password hashing and verification worker.
//!
//! This module contains the `PasswordWorker` struct, which manages bcrypt hashing and verification
//! operations using a combination of a `rayon` thread pool and `crossbeam-channel` to efficiently
//! handle these operations asynchronously.
//!
//! The methods will not block the tokio runtime. All await operations do not block. They use
//! non-blocking channel implementations to send and receive passwords and hashes to the rayon thread
//! pool.
//!
//! `PasswordWorker` is `Send + Sync + Clone` and contains no lifetimes, so it can be used as axum
//! state without an Arc.
//!
//! # Example
//!
//! ```
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use axum_password_worker::{Bcrypt, BcryptConfig, PasswordWorker};
//!
//! let password = "hunter2";
//! let cost = 12; // bcrypt cost value
//! let max_threads = 4; // rayon thread pool max threads
//! let password_worker = PasswordWorker::<Bcrypt>::new(max_threads)?;
//!
//! let hashed_password = password_worker.hash(password, BcryptConfig { cost }).await?;
//! println!("Hashed password: {:?}", hashed_password);
//!
//! let is_valid = password_worker.verify(password, hashed_password).await?;
//! println!("Verification result: {:?}", is_valid);
//! # Ok(())
//! # }
//! ```
use bcrypt::{hash, verify};
use rayon::ThreadPoolBuilder;
use thiserror::Error;
use tokio::sync::oneshot;

/// Errors that can occur in the `PasswordWorker`.
#[derive(Debug, Error)]
pub enum PasswordWorkerError<H: Hasher> {
    #[error("Hashing error: {0}")]
    Hashing(String),
    #[error("Channel send error: {0}")]
    ChannelSend(#[from] crossbeam_channel::SendError<WorkerCommand<H>>),
    #[error("Channel receive error: {0}")]
    ChannelRecv(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("ThreadPool build error: {0}")]
    ThreadPool(#[from] rayon::ThreadPoolBuildError),
    #[error("No tokio runtime error: {0}")]
    Runtime(#[from] tokio::runtime::TryCurrentError),
}

impl<H: Hasher> From<String> for PasswordWorkerError<H> {
    fn from(s: String) -> Self {
        Self::Hashing(s)
    }
}

#[derive(Debug)]
pub enum WorkerCommand<H: Hasher> {
    Hash(
        String,
        H::Config,
        oneshot::Sender<Result<String, PasswordWorkerError<H>>>,
    ),
    Verify(
        String,
        String,
        oneshot::Sender<Result<bool, PasswordWorkerError<H>>>,
    ),
}

pub trait Hasher: 'static {
    type Config: Send + Sync + 'static;
    type Error: core::fmt::Display + Send + Sync + 'static;
    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error>;
    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error>;
}

#[derive(Clone, Copy, Debug)]
pub enum Bcrypt {}

impl Hasher for Bcrypt {
    type Config = BcryptConfig;
    type Error = PasswordWorkerError<Self>;

    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error> {
        Ok(hash(data, config.cost).map_err(|e| e.to_string())?)
    }

    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error> {
        Ok(verify(data, hash).map_err(|e| e.to_string())?)
    }
}

#[derive(Clone, Copy)]
pub struct BcryptConfig {
    pub cost: u32,
}

/// A worker that handles password hashing and verification using a `rayon` thread pool
/// and `crossbeam-channel`.
///
/// The `PasswordWorker` struct provides asynchronous password hashing and verification
/// operations.
#[derive(Debug, Clone)]
pub struct PasswordWorker<H: Hasher> {
    sender: crossbeam_channel::Sender<WorkerCommand<H>>,
}

impl<H: Hasher> PasswordWorker<H> {
    /// Creates a new `PasswordWorker` with the given bcrypt cost and maximum number of threads.
    ///
    /// The `cost` parameter determines the computational cost of the bcrypt hashing algorithm.
    /// The `max_threads` parameter specifies the maximum number of threads the worker can use.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use axum_password_worker::{Bcrypt, PasswordWorker};
    ///
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker: PasswordWorker<Bcrypt> = PasswordWorker::new(max_threads)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(max_threads: usize) -> Result<Self, PasswordWorkerError<H>> {
        let (sender, receiver) = crossbeam_channel::unbounded::<WorkerCommand<H>>();

        let thread_pool = ThreadPoolBuilder::new().num_threads(max_threads).build()?;

        tokio::runtime::Handle::try_current()?.spawn_blocking(move || {
            while let Ok(command) = receiver.recv() {
                match command {
                    WorkerCommand::Hash(password, cost, result_sender) => {
                        let result = thread_pool.install(|| H::hash(&password, &cost));
                        result_sender
                            .send(result.map_err(|e| e.to_string().into()))
                            .ok()?;
                    }
                    WorkerCommand::Verify(password, hash, result_sender) => {
                        let result = thread_pool.install(|| H::verify(&password, &hash));
                        result_sender
                            .send(result.map_err(|e| e.to_string().into()))
                            .ok()?;
                    }
                }
            }
            Some(())
        });

        Ok(PasswordWorker { sender })
    }

    /// Asynchronously hashes the given password using bcrypt.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use axum_password_worker::{Bcrypt, BcryptConfig, PasswordWorker};
    ///
    /// let password = "hunter2";
    /// let cost = 12; // bcrypt cost value
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker = PasswordWorker::<Bcrypt>::new(max_threads)?;
    ///
    /// let hashed_password = password_worker.hash(password, BcryptConfig { cost }).await?;
    /// println!("Hashed password: {:?}", hashed_password);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn hash(
        &self,
        password: impl Into<String>,
        cost: H::Config,
    ) -> Result<String, PasswordWorkerError<H>> {
        let (tx, rx) = oneshot::channel();

        self.sender
            .send(WorkerCommand::Hash(password.into(), cost, tx))?;

        rx.await?
    }

    /// Asynchronously verifies a password against a bcrypt hash.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use axum_password_worker::{Bcrypt, BcryptConfig, PasswordWorker};
    ///
    /// let password = "hunter2";
    /// let cost = 12; // bcrypt cost value
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker = PasswordWorker::<Bcrypt>::new(max_threads)?;
    /// let hashed_password = password_worker.hash(password, BcryptConfig { cost }).await?;
    ///
    /// let is_valid = password_worker.verify(password, hashed_password).await?;
    /// println!("Verification result: {:?}", is_valid);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify(
        &self,
        password: impl Into<String>,
        hash: impl Into<String>,
    ) -> Result<bool, PasswordWorkerError<H>> {
        let (tx, rx) = oneshot::channel();

        self.sender
            .send(WorkerCommand::Verify(password.into(), hash.into(), tx))?;

        rx.await?
    }
}
