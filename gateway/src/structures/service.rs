use serde::{Deserialize, Serialize};

/// Signature contains the signature, the public key, and the algorithm used for verification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signature {
    /// The signature bytes.
    pub value: String,
    /// The public key used to verify the signature.
    pub pk: String,
    /// The algorithm used for signing (e.g., "ed25519", "rsa", "ecdsa").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algo: Option<String>,
}

/// ServiceResult is the result of a service call.
/// It contains the source of the service, the data returned by the service,
/// and the signature of the service.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceResult {
    /// The service that was called.
    pub service: String,
    /// The source of the service.
    /// This is the service provider that provided the data.
    pub src: String,
    /// The data returned by the service.
    pub data: String,
    /// The signature is used to verify the authenticity of the data.
    pub signature: Signature,
    /// Derived results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bulk: Option<Vec<ServiceResult>>,
}
