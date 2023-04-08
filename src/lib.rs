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
//! use axum_password_worker::PasswordWorker;
//!
//! let password = "hunter2";
//! let cost = 12; // bcrypt cost value
//! let max_threads = 4; // rayon thread pool max threads
//! let password_worker = PasswordWorker::new(max_threads)?;
//!
//! let hashed_password = password_worker.hash(password, cost).await?;
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
pub enum PasswordWorkerError {
    #[error("Bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("Channel send error: {0}")]
    ChannelSend(#[from] crossbeam_channel::SendError<WorkerCommand>),
    #[error("Channel receive error: {0}")]
    ChannelRecv(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("ThreadPool build error: {0}")]
    ThreadPool(#[from] rayon::ThreadPoolBuildError),
    #[error("No tokio runtime error: {0}")]
    Runtime(#[from] tokio::runtime::TryCurrentError),
}

#[derive(Debug)]
pub enum WorkerCommand {
    Hash(
        String,
        u32,
        oneshot::Sender<Result<String, PasswordWorkerError>>,
    ),
    Verify(
        String,
        String,
        oneshot::Sender<Result<bool, PasswordWorkerError>>,
    ),
}

/// A worker that handles password hashing and verification using a `rayon` thread pool
/// and `crossbeam-channel`.
///
/// The `PasswordWorker` struct provides asynchronous password hashing and verification
/// operations.
#[derive(Debug, Clone)]
pub struct PasswordWorker {
    sender: crossbeam_channel::Sender<WorkerCommand>,
}

impl PasswordWorker {
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
    /// use axum_password_worker::PasswordWorker;
    ///
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker = PasswordWorker::new(max_threads)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(max_threads: usize) -> Result<Self, PasswordWorkerError> {
        let (sender, receiver) = crossbeam_channel::unbounded::<WorkerCommand>();

        let thread_pool = ThreadPoolBuilder::new().num_threads(max_threads).build()?;

        tokio::runtime::Handle::try_current()?.spawn_blocking(move || {
            while let Ok(command) = receiver.recv() {
                match command {
                    WorkerCommand::Hash(password, cost, result_sender) => {
                        let result = thread_pool.install(|| hash(&password, cost));
                        result_sender
                            .send(result.map_err(PasswordWorkerError::Bcrypt))
                            .ok()?;
                    }
                    WorkerCommand::Verify(password, hash, result_sender) => {
                        let result = thread_pool.install(|| verify(&password, &hash));
                        result_sender
                            .send(result.map_err(PasswordWorkerError::Bcrypt))
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
    /// use axum_password_worker::PasswordWorker;
    ///
    /// let password = "hunter2";
    /// let cost = 12; // bcrypt cost value
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker = PasswordWorker::new(max_threads)?;
    ///
    /// let hashed_password = password_worker.hash(password, cost).await?;
    /// println!("Hashed password: {:?}", hashed_password);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn hash(
        &self,
        password: impl Into<String>,
        cost: u32,
    ) -> Result<String, PasswordWorkerError> {
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
    /// use axum_password_worker::PasswordWorker;
    ///
    /// let password = "hunter2";
    /// let cost = 12; // bcrypt cost value
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker = PasswordWorker::new(max_threads)?;
    /// let hashed_password = password_worker.hash(password, cost).await?;
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
    ) -> Result<bool, PasswordWorkerError> {
        let (tx, rx) = oneshot::channel();

        self.sender
            .send(WorkerCommand::Verify(password.into(), hash.into(), tx))?;

        rx.await?
    }
}
