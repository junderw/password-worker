/// Implement this to use your own hashing algorithm with this library
pub trait Hasher: 'static {
    type Config: Send + Sync + 'static;
    type Error: std::error::Error + Send + Sync + 'static;
    fn hash(data: impl AsRef<[u8]>, config: &Self::Config) -> Result<String, Self::Error>;
    fn verify(data: impl AsRef<[u8]>, hash: &str) -> Result<bool, Self::Error>;
}
