#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs)]

mod hasher;
mod hasher_impls;
mod worker;

pub use hasher::Hasher;
pub use worker::{PasswordWorker, PasswordWorkerError};

#[cfg(feature = "bcrypt")]
pub use hasher_impls::bcrypt::{Bcrypt, BcryptConfig};

#[cfg(feature = "rust-argon2")]
pub use hasher_impls::argon2id::{Argon2id, Argon2idConfig};
