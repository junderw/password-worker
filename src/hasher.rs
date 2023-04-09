/// Implement this to use your own hashing algorithm with this library
pub trait Hasher: 'static {
    /// The Config type for your hash algorithm
    type Config: Send + Sync + 'static;
    /// This is the Error you return from your hash library
    type Error: std::error::Error + Send + Sync + 'static;
    /// Use your hasher to create a hash from the password (data) and a Config instance.
    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error>;
    /// Verify whether the password (data) and hash match.
    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error>;
}
