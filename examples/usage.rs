use axum_password_worker::{Argon2idConfig, BcryptConfig, PasswordWorker};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = "hunter2";
    // bcrypt cost
    let cost = 12;
    // max threads rayon may use
    // higher = less threads for tokio I/O to use handling requests to axum
    // lower = longer waits for password results when high volume of login requests
    let max_threads = 8;

    // Store the PasswordWorker in your axum state so that the login methods can access it.
    // The hash/verify methods only need &Self so no need to wrap it in a Mutex.
    let password_worker = PasswordWorker::new_bcrypt(max_threads)?;
    let hashed_password = password_worker
        .hash(password, BcryptConfig { cost })
        .await?;
    println!("Hashed password: {:?}", hashed_password);

    let is_valid = password_worker.verify(password, hashed_password).await?;
    println!("Verification result: {:?}", is_valid);
    drop(password_worker);

    // Argon2id requires a salt
    let salt = "deadbeef".into();
    let password_worker = PasswordWorker::new_argon2id(max_threads)?;

    let hashed_password = password_worker
        .hash(
            password,
            Argon2idConfig {
                salt,
                ..Default::default()
            },
        )
        .await?;
    println!("Hashed password: {:?}", hashed_password);

    let is_valid = password_worker.verify(password, hashed_password).await?;
    println!("Verification result: {:?}", is_valid);
    Ok(())
}
