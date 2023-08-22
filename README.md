# axum-password-worker [![Latest Version](https://img.shields.io/crates/v/axum-password-worker.svg)](https://crates.io/crates/axum-password-worker)

A module providing a password hashing and verification worker.

This module contains the `PasswordWorker` struct, which manages hashing and verification
operations using a combination of a `rayon` thread pool and `crossbeam-channel` to efficiently
handle these operations asynchronously. It also makes use of a `tokio::sync::oneshot` channel
but does not require the tokio runtime to be present.

The methods will not block the async runtime. All await operations do not block. They use
non-blocking channel implementations to send and receive passwords and hashes to the rayon thread
pool.

`PasswordWorker` is `Send + Sync + Clone`, and contains no lifetimes. The Clone implementation
is a shallow copy that "points" to the same thread pool. It can be used as shared state without
an Arc. All methods take `&self` so a `Mutex` is also not necessary.

# Add as Dependency

<!-- If you use `text` or `bash` etc. on the code block it won't get run as a doctest -->
```bash
cargo add axum-password-worker

## OR if you want to also add argon2 support

cargo add axum-password-worker -F rust-argon2
```

# Example

```rust
use axum_password_worker::{BcryptConfig, PasswordWorker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "hunter2";
    let cost = 12; // bcrypt cost value
    let max_threads = 4; // rayon thread pool max threads
    let password_worker = PasswordWorker::new_bcrypt(max_threads)?;

    let hashed_password = password_worker.hash(password, BcryptConfig { cost }).await?;
    println!("Hashed password: {:?}", hashed_password);

    let is_valid = password_worker.verify(password, hashed_password).await?;
    println!("Verification result: {:?}", is_valid);

    Ok(())
}
```

# Available feature flags

There are some implementations included in the library. Each is tied to optional dependency features.
* `bcrypt` - (default) (dependency), exports the Bcrypt and BcryptConfig types.
* `rust-argon2` - (dependency), exports the Argon2id and Argon2idConfig types.
