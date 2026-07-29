//! The error type shared by every fallible operation in this crate.
//!
//! Keeping all of them in one enum, rather than per-module error types,
//! means callers of [`crate::app::AppHandler::express_interest`] and
//! [`crate::app::App::start`] can match on the same [`enum@Error`]
//! regardless of which layer produced it.

use thiserror::Error;

/// Failure modes that can occur while running an [`crate::app::App`] or
/// expressing an Interest through an [`crate::app::AppHandler`].
#[derive(Debug, Error)]
pub enum Error {
    /// Connecting to the local NFD forwarder failed, e.g. the Unix
    /// socket doesn't exist or NFD isn't running.
    #[error("Connection failed")]
    ConnectionFailed,
    /// The connection to NFD was closed, either by NFD or because a
    /// background task exited. The app cannot continue after this.
    #[error("Connection closed")]
    ConnectionClosed,
    /// An expressed Interest didn't receive a Data or NACK before its
    /// `InterestLifetime` elapsed.
    #[error("Operation timed out")]
    Timeout,
    /// The producer (or forwarder) NACKed the Interest, e.g. because it
    /// failed the producer's verifier or no route matched.
    #[error("Received a NACK for Interest")]
    NackReceived,
    /// A Data packet was received but rejected by the caller-supplied
    /// [`crate::verifier::DataVerifier`].
    #[error("Verification failed")]
    VerificationFailed,
    /// Reading from or writing to the NFD connection failed at the OS
    /// level.
    #[error("IO Error")]
    IOError(std::io::Error),
    /// A catch-all for errors that don't fit the other variants.
    #[error("Other error")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<tokio::time::error::Elapsed> for Error {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
    }
}
