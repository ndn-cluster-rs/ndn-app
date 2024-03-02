use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error("Operation timed out")]
    Timeout,
    #[error("Received a NACK for Interest")]
    NackReceived,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("IO Error")]
    IOError(std::io::Error),
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
