use crate::Hasher;
use rayon::ThreadPoolBuilder;
use tokio::sync::oneshot;

/// Errors that can occur in the `PasswordWorker`.
#[derive(Debug, thiserror::Error)]
pub enum PasswordWorkerError<H: Hasher> {
    /// An error from the Hashing operation
    #[error("Hashing error: {0}")]
    Hashing(H::Error),
    /// The worker thread must have died
    #[error("Channel send error: {0}")]
    ChannelSend(#[from] crossbeam_channel::SendError<WorkerCommand<H>>),
    /// The worker thread must have died
    #[error("Channel receive error: {0}")]
    ChannelRecv(#[from] tokio::sync::oneshot::error::RecvError),
    /// Couldn't create the rayon threadpool
    #[error("ThreadPool build error: {0}")]
    ThreadPool(#[from] rayon::ThreadPoolBuildError),
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
    /// Creates a new `PasswordWorker` with the given maximum number of threads.
    ///
    /// The `max_threads` parameter specifies the maximum number of threads the worker can use.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use password_worker::{Bcrypt, PasswordWorker};
    ///
    /// let max_threads = 4; // rayon thread pool max threads
    /// let password_worker: PasswordWorker<Bcrypt> = PasswordWorker::new(max_threads)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(max_threads: usize) -> Result<Self, PasswordWorkerError<H>> {
        let (sender, receiver) = crossbeam_channel::unbounded::<WorkerCommand<H>>();

        let thread_pool = ThreadPoolBuilder::new().num_threads(max_threads).build()?;

        std::thread::spawn(move || {
            while let Ok(command) = receiver.recv() {
                match command {
                    WorkerCommand::Hash(password, cost, result_sender) => {
                        let result = thread_pool.install(|| H::hash(&password, &cost));
                        result_sender
                            .send(result.map_err(PasswordWorkerError::Hashing))
                            .ok()?;
                    }
                    WorkerCommand::Verify(password, hash, result_sender) => {
                        let result = thread_pool.install(|| H::verify(&password, &hash));
                        result_sender
                            .send(result.map_err(PasswordWorkerError::Hashing))
                            .ok()?;
                    }
                }
            }
            Some(())
        });

        Ok(PasswordWorker { sender })
    }

    /// Asynchronously hashes the given password using its hashing algorithm.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use password_worker::{Bcrypt, BcryptConfig, PasswordWorker};
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

    /// Asynchronously verifies a password against a hash string.
    ///
    /// # Example
    ///
    /// ```
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use password_worker::{Bcrypt, BcryptConfig, PasswordWorker};
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
