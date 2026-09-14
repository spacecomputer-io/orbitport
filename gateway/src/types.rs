use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum GatewayError {
    #[error("Invalid request: {0}")]
    BadRequest(String),
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
    #[error("Invalid encryption key")]
    InvalidEncryptionKey,
    #[error("Invalid encryption scheme: {0}")]
    InvalidEncryptionScheme(String),
}

/// A config value that must never reach the logs. `Args` is dumped with `{:?}`
/// at startup, so anything secret needs a `Debug` that redacts itself.
#[derive(Clone)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_string())
    }
}
