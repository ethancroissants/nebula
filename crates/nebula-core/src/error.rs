//! Error type shared by nebula-core.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(String),
    Json(String),
    Process(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(s) => write!(f, "io: {s}"),
            Error::Json(s) => write!(f, "json: {s}"),
            Error::Process(s) => write!(f, "process: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
