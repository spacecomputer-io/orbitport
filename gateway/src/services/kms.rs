use serde::Serialize;
use tonic::transport::Channel;

use crate::proto::plugins::kms::{
    CreateKeyRequest as PluginCreateKeyRequest, CreateKeyResponse as PluginCreateKeyResponse,
    DecapsulateRequest as PluginDecapsulateRequest,
    DecapsulateResponse as PluginDecapsulateResponse, DecryptRequest as PluginDecryptRequest,
    DecryptResponse as PluginDecryptResponse, EncapsulateRequest as PluginEncapsulateRequest,
    EncapsulateResponse as PluginEncapsulateResponse, EncryptRequest as PluginEncryptRequest,
    EncryptResponse as PluginEncryptResponse,
    GenerateDataKeyRequest as PluginGenerateDataKeyRequest,
    GenerateDataKeyResponse as PluginGenerateDataKeyResponse,
    RotateKeyRequest as PluginRotateKeyRequest, RotateKeyResponse as PluginRotateKeyResponse,
    SignRequest as PluginSignRequest, SignResponse as PluginSignResponse, Tag as PluginTag,
    kms_plugin_client::KmsPluginClient,
};
use crate::proto::services::kms::{
    CreateKeyRequest, CreateKeyResponse, DecapsulateRequest, DecapsulateResponse, DecryptRequest,
    DecryptResponse, EncapsulateRequest, EncapsulateResponse, EncryptRequest, EncryptResponse,
    GenerateDataKeyRequest, GenerateDataKeyResponse, GetCapabilitiesResponse,
    KeyAgreementCapability, RotateKeyRequest, RotateKeyResponse, SchemeCapability, SignRequest,
    SignResponse, SigningCapability, Tag,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Transit,
    Ethereum,
    Pqc,
}

impl Scheme {
    fn parse_optional(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None | Some("TRANSIT") => Ok(Self::Transit),
            Some("ETHEREUM") => Ok(Self::Ethereum),
            Some("PQC") => Ok(Self::Pqc),
            Some(_) => Err("Scheme is not supported".to_string()),
        }
    }

    fn supports_key_spec(self, key_spec: KeySpec) -> bool {
        key_spec.requires_scheme() == self
    }

    fn supports_signing_algorithm(self, signing_algorithm: SigningAlgorithm) -> bool {
        matches!(
            (self, signing_algorithm),
            (Self::Transit, SigningAlgorithm::EcdsaSha256)
                | (Self::Transit, SigningAlgorithm::EcdsaSha384)
                | (Self::Transit, SigningAlgorithm::Ed25519)
                | (Self::Transit, SigningAlgorithm::RsassaPkcs1V15Sha256)
                | (Self::Transit, SigningAlgorithm::RsassaPssSha256)
                | (Self::Ethereum, SigningAlgorithm::EthereumSecp256k1)
                | (Self::Pqc, SigningAlgorithm::MlDsa)
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Transit => "TRANSIT",
            Self::Ethereum => "ETHEREUM",
            Self::Pqc => "PQC",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySpec {
    Aes256Gcm96,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    Rsa4096,
    EccSecgP256k1,
    MlKem768,
    MlKem1024,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl KeySpec {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_256_GCM96" => Ok(Self::Aes256Gcm96),
            "ECDSA_P256" => Ok(Self::EcdsaP256),
            "ECDSA_P384" => Ok(Self::EcdsaP384),
            "ED25519" => Ok(Self::Ed25519),
            "RSA_4096" => Ok(Self::Rsa4096),
            "ECC_SECG_P256K1" => Ok(Self::EccSecgP256k1),
            "ML_KEM_768" => Ok(Self::MlKem768),
            "ML_KEM_1024" => Ok(Self::MlKem1024),
            "ML_DSA_44" => Ok(Self::MlDsa44),
            "ML_DSA_65" => Ok(Self::MlDsa65),
            "ML_DSA_87" => Ok(Self::MlDsa87),
            _ => Err("KeySpec is not supported".to_string()),
        }
    }

    fn allowed_usage(self) -> KeyUsage {
        match self {
            Self::Aes256Gcm96 => KeyUsage::EncryptDecrypt,
            Self::MlKem768 | Self::MlKem1024 => KeyUsage::KeyAgreement,
            Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096
            | Self::EccSecgP256k1
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => KeyUsage::SignVerify,
        }
    }

    fn requires_scheme(self) -> Scheme {
        match self {
            Self::EccSecgP256k1 => Scheme::Ethereum,
            Self::MlKem768 | Self::MlKem1024 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => {
                Scheme::Pqc
            }
            Self::Aes256Gcm96
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096 => Scheme::Transit,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm96 => "AES_256_GCM96",
            Self::EcdsaP256 => "ECDSA_P256",
            Self::EcdsaP384 => "ECDSA_P384",
            Self::Ed25519 => "ED25519",
            Self::Rsa4096 => "RSA_4096",
            Self::EccSecgP256k1 => "ECC_SECG_P256K1",
            Self::MlKem768 => "ML_KEM_768",
            Self::MlKem1024 => "ML_KEM_1024",
            Self::MlDsa44 => "ML_DSA_44",
            Self::MlDsa65 => "ML_DSA_65",
            Self::MlDsa87 => "ML_DSA_87",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyUsage {
    EncryptDecrypt,
    KeyAgreement,
    SignVerify,
}

impl KeyUsage {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ENCRYPT_DECRYPT" => Ok(Self::EncryptDecrypt),
            "KEY_AGREEMENT" => Ok(Self::KeyAgreement),
            "SIGN_VERIFY" => Ok(Self::SignVerify),
            _ => Err("KeyUsage must be ENCRYPT_DECRYPT, KEY_AGREEMENT, or SIGN_VERIFY".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EncryptDecrypt => "ENCRYPT_DECRYPT",
            Self::KeyAgreement => "KEY_AGREEMENT",
            Self::SignVerify => "SIGN_VERIFY",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncryptionAlgorithm {
    Aes256Gcm96,
}

impl EncryptionAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_256_GCM96" => Ok(Self::Aes256Gcm96),
            _ => Err("EncryptionAlgorithm must be AES_256_GCM96".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes256Gcm96 => "AES_256_GCM96",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigningAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    Ed25519,
    EthereumSecp256k1,
    MlDsa,
    RsassaPkcs1V15Sha256,
    RsassaPssSha256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyAgreementAlgorithm {
    MlKem,
}

impl KeyAgreementAlgorithm {
    fn as_str(self) -> &'static str {
        match self {
            Self::MlKem => "ML_KEM",
        }
    }
}

impl SigningAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ECDSA_SHA_256" => Ok(Self::EcdsaSha256),
            "ECDSA_SHA_384" => Ok(Self::EcdsaSha384),
            "ED25519" => Ok(Self::Ed25519),
            "ETHEREUM_SECP256K1" => Ok(Self::EthereumSecp256k1),
            "ML_DSA" => Ok(Self::MlDsa),
            "RSASSA_PKCS1_V1_5_SHA_256" => Ok(Self::RsassaPkcs1V15Sha256),
            "RSASSA_PSS_SHA_256" => Ok(Self::RsassaPssSha256),
            _ => Err("SigningAlgorithm is not supported".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaSha256 => "ECDSA_SHA_256",
            Self::EcdsaSha384 => "ECDSA_SHA_384",
            Self::Ed25519 => "ED25519",
            Self::EthereumSecp256k1 => "ETHEREUM_SECP256K1",
            Self::MlDsa => "ML_DSA",
            Self::RsassaPkcs1V15Sha256 => "RSASSA_PKCS1_V1_5_SHA_256",
            Self::RsassaPssSha256 => "RSASSA_PSS_SHA_256",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessageType {
    Raw,
    Digest,
    Eip191,
}

impl MessageType {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "RAW" => Ok(Self::Raw),
            "DIGEST" => Ok(Self::Digest),
            "EIP191" => Ok(Self::Eip191),
            _ => Err("MessageType must be RAW, DIGEST, or EIP191".to_string()),
        }
    }

    fn allowed_for(self, signing_algorithm: SigningAlgorithm) -> bool {
        match (self, signing_algorithm) {
            (Self::Raw, _) => true,
            (Self::Digest, SigningAlgorithm::MlDsa) => false,
            (Self::Digest, _) => true,
            (Self::Eip191, _) => Scheme::Ethereum.supports_signing_algorithm(signing_algorithm),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "RAW",
            Self::Digest => "DIGEST",
            Self::Eip191 => "EIP191",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DataKeySpec {
    Aes128,
    Aes256,
}

impl DataKeySpec {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "AES_128" => Ok(Self::Aes128),
            "AES_256" => Ok(Self::Aes256),
            _ => Err("DataKeySpec must be AES_128 or AES_256".to_string()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Aes128 => "AES_128",
            Self::Aes256 => "AES_256",
        }
    }
}

const MAX_ALIAS_LEN: usize = 128;
const KEY_ID_PREFIX: &str = "kms:";

#[derive(Debug)]
pub enum KmsRpcCall {
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
    Sign(SignRequest),
    Encapsulate(EncapsulateRequest),
    Decapsulate(DecapsulateRequest),
    CreateKey(CreateKeyRequest),
    GenerateDataKey(GenerateDataKeyRequest),
    RotateKey(RotateKeyRequest),
}

impl KmsRpcCall {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Encrypt(req) => KmsService::validate_encrypt(req),
            Self::Decrypt(req) => KmsService::validate_decrypt(req),
            Self::Sign(req) => KmsService::validate_sign(req),
            Self::Encapsulate(req) => KmsService::validate_encapsulate(req),
            Self::Decapsulate(req) => KmsService::validate_decapsulate(req),
            Self::CreateKey(req) => KmsService::validate_create_key(req),
            Self::GenerateDataKey(req) => KmsService::validate_generate_data_key(req),
            Self::RotateKey(req) => KmsService::validate_rotate_key(req),
        }
    }

    fn log_start(&self, req_id: u64) {
        match self {
            Self::Encrypt(req) => tracing::debug!(
                "Executing KMS Encrypt RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::Decrypt(req) => tracing::debug!(
                "Executing KMS Decrypt RPC [id={} key_id={}]",
                req_id,
                req.key_id.as_deref().unwrap_or("<blob>")
            ),
            Self::Sign(req) => tracing::debug!(
                "Executing KMS Sign RPC [id={} key_id={} signing_algorithm={}]",
                req_id,
                req.key_id,
                req.signing_algorithm
            ),
            Self::Encapsulate(req) => tracing::debug!(
                "Executing KMS Encapsulate RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::Decapsulate(req) => tracing::debug!(
                "Executing KMS Decapsulate RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::CreateKey(req) => tracing::debug!(
                "Executing KMS CreateKey RPC [id={} scheme={} key_spec={} key_usage={}]",
                req_id,
                req.scheme.as_deref().unwrap_or("TRANSIT"),
                req.key_spec,
                req.key_usage
            ),
            Self::GenerateDataKey(req) => tracing::debug!(
                "Executing KMS GenerateDataKey RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
            Self::RotateKey(req) => tracing::debug!(
                "Executing KMS RotateKey RPC [id={} key_id={}]",
                req_id,
                req.key_id
            ),
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum KmsRpcResult {
    Encrypt(EncryptResponse),
    Decrypt(DecryptResponse),
    Sign(SignResponse),
    Encapsulate(EncapsulateResponse),
    Decapsulate(DecapsulateResponse),
    CreateKey(CreateKeyResponse),
    GenerateDataKey(GenerateDataKeyResponse),
    RotateKey(RotateKeyResponse),
}

impl KmsRpcResult {
    fn log_success(&self, req_id: u64) {
        match self {
            Self::Encrypt(result) => tracing::debug!(
                "KMS Encrypt RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::Decrypt(result) => tracing::debug!(
                "KMS Decrypt RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::Sign(result) => tracing::debug!(
                "KMS Sign RPC succeeded [id={} key_id={} signing_algorithm={}]",
                req_id,
                result.key_id,
                result.signing_algorithm
            ),
            Self::Encapsulate(result) => tracing::debug!(
                "KMS Encapsulate RPC succeeded [id={} key_id={} key_agreement_algorithm={}]",
                req_id,
                result.key_id,
                result.key_agreement_algorithm
            ),
            Self::Decapsulate(result) => tracing::debug!(
                "KMS Decapsulate RPC succeeded [id={} key_id={} key_agreement_algorithm={}]",
                req_id,
                result.key_id,
                result.key_agreement_algorithm
            ),
            Self::CreateKey(result) => {
                if let Some(metadata) = result.key_metadata.as_ref() {
                    tracing::debug!(
                        "KMS CreateKey RPC succeeded [id={} key_id={} scheme={}]",
                        req_id,
                        metadata.key_id,
                        metadata.scheme
                    );
                }
            }
            Self::GenerateDataKey(result) => tracing::debug!(
                "KMS GenerateDataKey RPC succeeded [id={} key_id={}]",
                req_id,
                result.key_id
            ),
            Self::RotateKey(result) => {
                if let Some(metadata) = result.key_metadata.as_ref() {
                    tracing::debug!(
                        "KMS RotateKey RPC succeeded [id={} key_id={} primary_version={}]",
                        req_id,
                        metadata.key_id,
                        metadata.primary_version
                    );
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct KmsService {
    client: KmsPluginClient<Channel>,
}

impl KmsService {
    pub fn new(client: KmsPluginClient<Channel>) -> Self {
        Self { client }
    }

    pub fn validate_encrypt(req: &EncryptRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Plaintext", &req.plaintext)?;

        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_decrypt(req: &DecryptRequest) -> Result<(), String> {
        validate_required("CiphertextBlob", &req.ciphertext_blob)?;
        if let Some(key_id) = req.key_id.as_ref() {
            validate_key_reference("KeyId", key_id)?;
        }
        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_sign(req: &SignRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Message", &req.message)?;
        let signing_algorithm = validate_signing_algorithm(&req.signing_algorithm)?;
        if let Some(message_type) = req.message_type.as_ref() {
            let message_type = MessageType::parse(message_type)?;
            if !message_type.allowed_for(signing_algorithm) {
                return Err(format!(
                    "MessageType {} is not supported for SigningAlgorithm {}",
                    message_type.as_str(),
                    signing_algorithm.as_str()
                ));
            }
        }
        Ok(())
    }

    pub fn validate_encapsulate(req: &EncapsulateRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)
    }

    pub fn validate_decapsulate(req: &DecapsulateRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        validate_required("Ciphertext", &req.ciphertext)?;
        Ok(())
    }

    pub fn validate_create_key(req: &CreateKeyRequest) -> Result<(), String> {
        let scheme = Scheme::parse_optional(req.scheme.as_deref())?;
        let key_spec = validate_key_spec(&req.key_spec, scheme)?;
        let key_usage = validate_key_usage(&req.key_usage)?;

        validate_required("Alias", &req.alias)?;
        validate_alias(&req.alias)?;

        if key_usage != key_spec.allowed_usage() {
            return Err(match (scheme, key_spec) {
                (_, KeySpec::Aes256Gcm96) => {
                    "AES_256_GCM96 keys must use ENCRYPT_DECRYPT".to_string()
                }
                (_, KeySpec::MlKem768 | KeySpec::MlKem1024) => {
                    "PQC ML-KEM keys must use KEY_AGREEMENT".to_string()
                }
                (Scheme::Ethereum, _) => "ETHEREUM keys must use SIGN_VERIFY".to_string(),
                (Scheme::Pqc, _) => "PQC keys must use SIGN_VERIFY".to_string(),
                (Scheme::Transit, _) => "Asymmetric KMS keys must use SIGN_VERIFY".to_string(),
            });
        }

        for tag in &req.tags {
            validate_required("TagKey", &tag.tag_key)?;
        }
        Ok(())
    }

    pub fn validate_generate_data_key(req: &GenerateDataKeyRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)?;
        let has_spec = req
            .data_key_spec
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        let has_size = req.number_of_bytes.is_some();
        if has_spec == has_size {
            return Err("Exactly one of DataKeySpec or NumberOfBytes must be provided".to_string());
        }
        if let Some(spec) = req.data_key_spec.as_ref() {
            DataKeySpec::parse(spec)?;
        }
        if let Some(bytes) = req.number_of_bytes
            && bytes == 0
        {
            return Err("NumberOfBytes must be greater than 0".to_string());
        }
        Ok(())
    }

    pub fn validate_rotate_key(req: &RotateKeyRequest) -> Result<(), String> {
        validate_key_reference("KeyId", &req.key_id)
    }

    pub fn get_capabilities() -> GetCapabilitiesResponse {
        GetCapabilitiesResponse {
            schemes: vec![
                transit_capability(),
                ethereum_capability(),
                pqc_capability(),
            ],
        }
    }

    pub async fn execute(
        &mut self,
        client_id: &str,
        req_id: u64,
        call: KmsRpcCall,
    ) -> Result<KmsRpcResult, tonic::Status> {
        call.log_start(req_id);

        let result = match call {
            KmsRpcCall::Encrypt(req) => KmsRpcResult::Encrypt(self.encrypt(client_id, req).await?),
            KmsRpcCall::Decrypt(req) => KmsRpcResult::Decrypt(self.decrypt(client_id, req).await?),
            KmsRpcCall::Sign(req) => KmsRpcResult::Sign(self.sign(client_id, req).await?),
            KmsRpcCall::Encapsulate(req) => {
                KmsRpcResult::Encapsulate(self.encapsulate(client_id, req).await?)
            }
            KmsRpcCall::Decapsulate(req) => {
                KmsRpcResult::Decapsulate(self.decapsulate(client_id, req).await?)
            }
            KmsRpcCall::CreateKey(req) => {
                KmsRpcResult::CreateKey(self.create_key(client_id, req).await?)
            }
            KmsRpcCall::GenerateDataKey(req) => {
                KmsRpcResult::GenerateDataKey(self.generate_data_key(client_id, req).await?)
            }
            KmsRpcCall::RotateKey(req) => {
                KmsRpcResult::RotateKey(self.rotate_key(client_id, req).await?)
            }
        };

        result.log_success(req_id);
        Ok(result)
    }

    pub async fn encrypt(
        &mut self,
        client_id: &str,
        req: EncryptRequest,
    ) -> Result<EncryptResponse, tonic::Status> {
        let response: PluginEncryptResponse = self
            .client
            .encrypt(tonic::Request::new(PluginEncryptRequest {
                key_id: req.key_id,
                plaintext: req.plaintext,
                encryption_algorithm: req.encryption_algorithm,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(EncryptResponse {
            ciphertext_blob: response.ciphertext_blob,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn decrypt(
        &mut self,
        client_id: &str,
        req: DecryptRequest,
    ) -> Result<DecryptResponse, tonic::Status> {
        let response: PluginDecryptResponse = self
            .client
            .decrypt(tonic::Request::new(PluginDecryptRequest {
                ciphertext_blob: req.ciphertext_blob,
                key_id: req.key_id,
                encryption_algorithm: req.encryption_algorithm,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(DecryptResponse {
            plaintext: response.plaintext,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn sign(
        &mut self,
        client_id: &str,
        req: SignRequest,
    ) -> Result<SignResponse, tonic::Status> {
        let response: PluginSignResponse = self
            .client
            .sign(tonic::Request::new(PluginSignRequest {
                key_id: req.key_id,
                message: req.message,
                signing_algorithm: req.signing_algorithm,
                message_type: req.message_type,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(SignResponse {
            key_id: response.key_id,
            signature: response.signature,
            signing_algorithm: response.signing_algorithm,
        })
    }

    pub async fn encapsulate(
        &mut self,
        client_id: &str,
        req: EncapsulateRequest,
    ) -> Result<EncapsulateResponse, tonic::Status> {
        let response: PluginEncapsulateResponse = self
            .client
            .encapsulate(tonic::Request::new(PluginEncapsulateRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(EncapsulateResponse {
            key_id: response.key_id,
            ciphertext: response.ciphertext,
            shared_key: response.shared_key,
            key_agreement_algorithm: response.key_agreement_algorithm,
        })
    }

    pub async fn decapsulate(
        &mut self,
        client_id: &str,
        req: DecapsulateRequest,
    ) -> Result<DecapsulateResponse, tonic::Status> {
        let response: PluginDecapsulateResponse = self
            .client
            .decapsulate(tonic::Request::new(PluginDecapsulateRequest {
                key_id: req.key_id,
                ciphertext: req.ciphertext,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(DecapsulateResponse {
            key_id: response.key_id,
            key_agreement_algorithm: response.key_agreement_algorithm,
        })
    }

    pub async fn create_key(
        &mut self,
        client_id: &str,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, tonic::Status> {
        let response: PluginCreateKeyResponse = self
            .client
            .create_key(tonic::Request::new(PluginCreateKeyRequest {
                description: req.description,
                key_spec: req.key_spec,
                key_usage: req.key_usage,
                scheme: req.scheme,
                alias: req.alias,
                tags: req
                    .tags
                    .into_iter()
                    .map(|tag| PluginTag {
                        tag_key: tag.tag_key,
                        tag_value: tag.tag_value,
                    })
                    .collect(),
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(CreateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }

    pub async fn generate_data_key(
        &mut self,
        client_id: &str,
        req: GenerateDataKeyRequest,
    ) -> Result<GenerateDataKeyResponse, tonic::Status> {
        let response: PluginGenerateDataKeyResponse = self
            .client
            .generate_data_key(tonic::Request::new(PluginGenerateDataKeyRequest {
                key_id: req.key_id,
                data_key_spec: req.data_key_spec,
                number_of_bytes: req.number_of_bytes,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(GenerateDataKeyResponse {
            key_id: response.key_id,
            plaintext: response.plaintext,
            ciphertext_blob: response.ciphertext_blob,
        })
    }

    pub async fn rotate_key(
        &mut self,
        client_id: &str,
        req: RotateKeyRequest,
    ) -> Result<RotateKeyResponse, tonic::Status> {
        let response: PluginRotateKeyResponse = self
            .client
            .rotate_key(tonic::Request::new(PluginRotateKeyRequest {
                key_id: req.key_id,
                client_id: client_id.to_string(),
            }))
            .await?
            .into_inner();

        Ok(RotateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }
}

fn transit_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Transit.as_str().to_string(),
        key_specs: vec![
            KeySpec::Aes256Gcm96,
            KeySpec::EcdsaP256,
            KeySpec::EcdsaP384,
            KeySpec::Ed25519,
            KeySpec::Rsa4096,
        ]
        .into_iter()
        .map(|spec| spec.as_str().to_string())
        .collect(),
        key_usages: vec![KeyUsage::EncryptDecrypt, KeyUsage::SignVerify]
            .into_iter()
            .map(|usage| usage.as_str().to_string())
            .collect(),
        encryption_algorithms: vec![EncryptionAlgorithm::Aes256Gcm96.as_str().to_string()],
        data_key_specs: vec![DataKeySpec::Aes128, DataKeySpec::Aes256]
            .into_iter()
            .map(|spec| spec.as_str().to_string())
            .collect(),
        signing_capabilities: vec![
            signing_capability(
                SigningAlgorithm::EcdsaSha256,
                &[MessageType::Raw, MessageType::Digest],
            ),
            signing_capability(
                SigningAlgorithm::EcdsaSha384,
                &[MessageType::Raw, MessageType::Digest],
            ),
            signing_capability(
                SigningAlgorithm::Ed25519,
                &[MessageType::Raw, MessageType::Digest],
            ),
            signing_capability(
                SigningAlgorithm::RsassaPkcs1V15Sha256,
                &[MessageType::Raw, MessageType::Digest],
            ),
            signing_capability(
                SigningAlgorithm::RsassaPssSha256,
                &[MessageType::Raw, MessageType::Digest],
            ),
        ],
        supports_encrypt: true,
        supports_decrypt: true,
        supports_generate_data_key: true,
        supports_rotate_key: true,
        key_agreement_capabilities: vec![],
        supports_encapsulate: false,
        supports_decapsulate: false,
    }
}

fn ethereum_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Ethereum.as_str().to_string(),
        key_specs: vec![KeySpec::EccSecgP256k1.as_str().to_string()],
        key_usages: vec![KeyUsage::SignVerify.as_str().to_string()],
        encryption_algorithms: vec![],
        data_key_specs: vec![],
        signing_capabilities: vec![signing_capability(
            SigningAlgorithm::EthereumSecp256k1,
            &[MessageType::Raw, MessageType::Digest, MessageType::Eip191],
        )],
        supports_encrypt: false,
        supports_decrypt: false,
        supports_generate_data_key: false,
        supports_rotate_key: false,
        key_agreement_capabilities: vec![],
        supports_encapsulate: false,
        supports_decapsulate: false,
    }
}

fn pqc_capability() -> SchemeCapability {
    SchemeCapability {
        scheme: Scheme::Pqc.as_str().to_string(),
        key_specs: vec![
            KeySpec::MlDsa44,
            KeySpec::MlDsa65,
            KeySpec::MlDsa87,
            KeySpec::MlKem768,
            KeySpec::MlKem1024,
        ]
        .into_iter()
        .map(|spec| spec.as_str().to_string())
        .collect(),
        key_usages: vec![KeyUsage::SignVerify, KeyUsage::KeyAgreement]
            .into_iter()
            .map(|usage| usage.as_str().to_string())
            .collect(),
        encryption_algorithms: vec![],
        data_key_specs: vec![],
        signing_capabilities: vec![signing_capability(
            SigningAlgorithm::MlDsa,
            &[MessageType::Raw],
        )],
        supports_encrypt: false,
        supports_decrypt: false,
        supports_generate_data_key: false,
        supports_rotate_key: false,
        key_agreement_capabilities: vec![key_agreement_capability(KeyAgreementAlgorithm::MlKem)],
        supports_encapsulate: true,
        supports_decapsulate: true,
    }
}

fn key_agreement_capability(
    key_agreement_algorithm: KeyAgreementAlgorithm,
) -> KeyAgreementCapability {
    KeyAgreementCapability {
        key_agreement_algorithm: key_agreement_algorithm.as_str().to_string(),
    }
}

fn signing_capability(
    signing_algorithm: SigningAlgorithm,
    message_types: &[MessageType],
) -> SigningCapability {
    SigningCapability {
        signing_algorithm: signing_algorithm.as_str().to_string(),
        message_types: message_types
            .iter()
            .map(|message_type| message_type.as_str().to_string())
            .collect(),
    }
}

fn validate_required(field_name: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{field_name} is required"));
    }
    Ok(())
}

fn validate_key_spec(value: &str, scheme: Scheme) -> Result<KeySpec, String> {
    let key_spec = KeySpec::parse(value).map_err(|_| match scheme {
        Scheme::Transit => "KeySpec is not supported".to_string(),
        Scheme::Ethereum => "ETHEREUM keys must use ECC_SECG_P256K1".to_string(),
        Scheme::Pqc => {
            "PQC keys must use ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_768, or ML_KEM_1024"
                .to_string()
        }
    })?;

    if scheme.supports_key_spec(key_spec) {
        Ok(key_spec)
    } else {
        Err(match scheme {
            Scheme::Transit => "KeySpec is not supported".to_string(),
            Scheme::Ethereum => "ETHEREUM keys must use ECC_SECG_P256K1".to_string(),
            Scheme::Pqc => {
                "PQC keys must use ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_768, or ML_KEM_1024"
                    .to_string()
            }
        })
    }
}

fn validate_key_usage(value: &str) -> Result<KeyUsage, String> {
    KeyUsage::parse(value)
}

fn validate_encryption_algorithm(value: &str) -> Result<EncryptionAlgorithm, String> {
    EncryptionAlgorithm::parse(value)
}

fn validate_signing_algorithm(value: &str) -> Result<SigningAlgorithm, String> {
    SigningAlgorithm::parse(value)
}

fn validate_alias(value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.len() > MAX_ALIAS_LEN {
        return Err(format!("alias must be at most {MAX_ALIAS_LEN} characters"));
    }
    if trimmed.starts_with(KEY_ID_PREFIX) {
        return Err("alias must not use the reserved kms:<alias> format".to_string());
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'))
    {
        return Err("alias contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_key_reference(field_name: &str, value: &str) -> Result<(), String> {
    validate_required(field_name, value)?;
    let trimmed = value.trim();
    let alias = trimmed.strip_prefix(KEY_ID_PREFIX).unwrap_or(trimmed);
    if alias.is_empty() {
        return Err(format!("{field_name} is required"));
    }
    validate_alias(alias)
}

fn map_key_metadata(
    metadata: crate::proto::plugins::kms::KeyMetadata,
) -> crate::proto::services::kms::KeyMetadata {
    crate::proto::services::kms::KeyMetadata {
        key_id: metadata.key_id,
        description: metadata.description,
        key_spec: metadata.key_spec,
        key_usage: metadata.key_usage,
        enabled: metadata.enabled,
        primary_version: metadata.primary_version,
        creation_date: metadata.creation_date,
        scheme: metadata.scheme,
        alias: metadata.alias,
        public_key: metadata.public_key,
        address: metadata.address,
        tags: metadata
            .tags
            .into_iter()
            .map(|tag| Tag {
                tag_key: tag.tag_key,
                tag_value: tag.tag_value,
            })
            .collect(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_validate_create_key_usage() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: None,
            alias: "transit-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("ENCRYPT_DECRYPT"));
    }

    #[test]
    fn test_validate_create_key_ethereum_scheme() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ECC_SECG_P256K1".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("ETHEREUM".to_string()),
            alias: "eth-main".to_string(),
            tags: vec![],
        };
        KmsService::validate_create_key(&req).unwrap();
    }

    #[test]
    fn test_validate_create_key_pqc_scheme() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ML_DSA_65".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-main".to_string(),
            tags: vec![],
        };
        KmsService::validate_create_key(&req).unwrap();
    }

    #[test]
    fn test_validate_create_key_pqc_kem_scheme() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ML_KEM_768".to_string(),
            key_usage: "KEY_AGREEMENT".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-kem-main".to_string(),
            tags: vec![],
        };
        KmsService::validate_create_key(&req).unwrap();
    }

    #[test]
    fn test_validate_create_key_pqc_kem_rejects_sign_usage() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ML_KEM_768".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-kem-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("KEY_AGREEMENT"));
    }

    #[test]
    fn test_validate_create_key_pqc_rejects_transit_spec() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "ECDSA_P256".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: Some("PQC".to_string()),
            alias: "pqc-main".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("ML_DSA_44"));
    }

    #[test]
    fn test_validate_create_key_alias() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "ENCRYPT_DECRYPT".to_string(),
            scheme: None,
            alias: "kms:11111111-1111-1111-1111-111111111111".to_string(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.contains("reserved kms:<alias> format"));
    }

    #[test]
    fn test_validate_create_key_alias_required() {
        let req = CreateKeyRequest {
            description: String::new(),
            key_spec: "AES_256_GCM96".to_string(),
            key_usage: "ENCRYPT_DECRYPT".to_string(),
            scheme: None,
            alias: String::new(),
            tags: vec![],
        };
        let err = KmsService::validate_create_key(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("alias is required"));
    }

    #[test]
    fn test_validate_generate_data_key_xor() {
        let req = GenerateDataKeyRequest {
            key_id: "kms:abc".to_string(),
            data_key_spec: Some("AES_256".to_string()),
            number_of_bytes: Some(32),
        };
        let err = KmsService::validate_generate_data_key(&req).unwrap_err();
        assert!(err.contains("Exactly one"));
    }

    #[test]
    fn test_validate_decapsulate_requires_ciphertext() {
        let req = DecapsulateRequest {
            key_id: "kms:abc".to_string(),
            ciphertext: "".to_string(),
        };
        let err = KmsService::validate_decapsulate(&req).unwrap_err();
        assert!(err.to_ascii_lowercase().contains("ciphertext is required"));
    }

    #[test]
    fn test_validate_sign_message_type() {
        let req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ETHEREUM_SECP256K1".to_string(),
            message_type: Some("INVALID".to_string()),
        };
        let err = KmsService::validate_sign(&req).unwrap_err();
        assert!(err.contains("MessageType"));
    }

    #[test]
    fn test_get_capabilities_includes_transit_and_ethereum() {
        let capabilities = KmsService::get_capabilities();

        let transit = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "TRANSIT")
            .expect("missing TRANSIT capability");
        assert!(transit.key_specs.contains(&"AES_256_GCM96".to_string()));
        assert!(
            transit
                .encryption_algorithms
                .contains(&"AES_256_GCM96".to_string())
        );
        assert!(transit.supports_encrypt);
        assert!(transit.supports_decrypt);
        assert!(transit.supports_generate_data_key);
        assert!(transit.supports_rotate_key);

        let ethereum = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "ETHEREUM")
            .expect("missing ETHEREUM capability");
        assert!(ethereum.key_specs.contains(&"ECC_SECG_P256K1".to_string()));
        assert!(ethereum.signing_capabilities.iter().any(|capability| {
            capability.signing_algorithm == "ETHEREUM_SECP256K1"
                && capability.message_types.contains(&"EIP191".to_string())
        }));
        assert!(!ethereum.supports_encrypt);
        assert!(!ethereum.supports_generate_data_key);
        assert!(!ethereum.supports_rotate_key);

        let pqc = capabilities
            .schemes
            .iter()
            .find(|scheme| scheme.scheme == "PQC")
            .expect("missing PQC capability");
        assert!(pqc.key_specs.contains(&"ML_DSA_65".to_string()));
        assert!(pqc.key_specs.contains(&"ML_KEM_768".to_string()));
        assert!(pqc.key_usages.contains(&"SIGN_VERIFY".to_string()));
        assert!(pqc.key_usages.contains(&"KEY_AGREEMENT".to_string()));
        assert!(pqc.signing_capabilities.iter().any(|capability| {
            capability.signing_algorithm == "ML_DSA"
                && capability.message_types == vec!["RAW".to_string()]
        }));
        assert!(
            pqc.key_agreement_capabilities
                .iter()
                .any(|capability| capability.key_agreement_algorithm == "ML_KEM")
        );
        assert!(!pqc.supports_encrypt);
        assert!(!pqc.supports_generate_data_key);
        assert!(!pqc.supports_rotate_key);
        assert!(pqc.supports_encapsulate);
        assert!(pqc.supports_decapsulate);
    }

    #[test]
    fn test_validate_sign_rejects_unsupported_message_type_for_algorithm() {
        let req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ECDSA_SHA_256".to_string(),
            message_type: Some("EIP191".to_string()),
        };
        let err = KmsService::validate_sign(&req).unwrap_err();
        assert_eq!(
            err,
            "MessageType EIP191 is not supported for SigningAlgorithm ECDSA_SHA_256"
        );
    }

    #[test]
    fn test_validate_sign_mldsa_raw_only() {
        let raw_req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ML_DSA".to_string(),
            message_type: Some("RAW".to_string()),
        };
        KmsService::validate_sign(&raw_req).unwrap();

        let digest_req = SignRequest {
            message_type: Some("DIGEST".to_string()),
            ..raw_req
        };
        let err = KmsService::validate_sign(&digest_req).unwrap_err();
        assert!(err.contains("ML_DSA"));
    }
}
