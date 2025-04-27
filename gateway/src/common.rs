use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum GatewayError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Service timeout")]
    ServiceTimeout,
    #[error("Service connection failed: {0}")]
    ServiceConnectionError(String),
    #[error("Service not found: {0}")]
    ServiceNotFoundError(String),
    #[error("Missing Authorization header")]
    NoAuthHeaderError,
    #[error("Invalid Authorization header")]
    InvalidAuthHeaderError,
    #[error("Failed to connect to auth agent: {0}")]
    AuthAgentConnectionError(String),
    #[error("Failed to authenticate")]
    AuthenticationFailed,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Error while waiting for termination signal: {0}")]
    TerminationError(String),
}
