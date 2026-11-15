//! KeyAlibi injects phantom credentials into a child process and swaps the
//! real secret back only at an allowlisted upstream.
//!
//! The real plaintext stays in the supervisor. The child receives a
//! session-scoped stand-in that satisfies client-side SDK validators, and the
//! egress proxy is the only component that can turn that stand-in into a
//! usable credential.

pub mod audit;
pub mod cli;
pub mod harden;
pub mod jail;
pub mod mint;
pub mod policy;
pub mod proxy;
pub mod tui;
pub mod verify;

use std::fmt;

/// Recoverable failure. Display text is safe to print: it never includes a
/// secret value.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<hyper::Error> for Error {
    fn from(value: hyper::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<http::Error> for Error {
    fn from(value: http::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<toml::de::Error> for Error {
    fn from(value: toml::de::Error) -> Self {
        Self::new(value.to_string())
    }
}

impl From<toml::ser::Error> for Error {
    fn from(value: toml::ser::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
