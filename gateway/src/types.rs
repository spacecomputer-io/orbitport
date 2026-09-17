use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum GatewayError {
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Service connection failed: {0}")]
    ServiceConnectionError(String),
    #[error("Missing Authorization header")]
    NoAuthHeaderError,
    #[error("Invalid Authorization header")]
    InvalidAuthHeaderError,
    #[error("Failed to connect to auth plugin: {0}")]
    AuthPluginConnectionError(String),
    #[error("Failed to authenticate")]
    AuthenticationFailed,
    #[error("Service token lacks required authorization")]
    ServiceAuthorizationDenied,
    #[error("Personal access token expired")]
    PatExpired,
    #[error("Unknown or revoked credential")]
    InvalidCredential,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Insufficient credits")]
    InsufficientCredits,
    #[error("Account plugin unavailable: {0}")]
    AccountPluginUnavailable(String),
    #[error("Error while waiting for termination signal: {0}")]
    TerminationError(String),
}
