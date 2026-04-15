use tonic::transport::Channel;

use crate::proto::plugins::kms::{
    CreateKeyRequest as PluginCreateKeyRequest, CreateKeyResponse as PluginCreateKeyResponse,
    DecryptRequest as PluginDecryptRequest, DecryptResponse as PluginDecryptResponse,
    EncryptRequest as PluginEncryptRequest, EncryptResponse as PluginEncryptResponse,
    GenerateDataKeyRequest as PluginGenerateDataKeyRequest,
    GenerateDataKeyResponse as PluginGenerateDataKeyResponse,
    RotateKeyRequest as PluginRotateKeyRequest, RotateKeyResponse as PluginRotateKeyResponse,
    SignRequest as PluginSignRequest, SignResponse as PluginSignResponse, Tag as PluginTag,
    kms_plugin_client::KmsPluginClient,
};
use crate::proto::services::kms::{
    CreateKeyRequest, CreateKeyResponse, DecryptRequest, DecryptResponse, EncryptRequest,
    EncryptResponse, GenerateDataKeyRequest, GenerateDataKeyResponse, RotateKeyRequest,
    RotateKeyResponse, SignRequest, SignResponse, Tag,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scheme {
    Transit,
    Ethereum,
}

impl Scheme {
    fn parse_optional(value: Option<&str>) -> Result<Self, String> {
        match value.map(str::trim).filter(|v| !v.is_empty()) {
            None | Some("TRANSIT") => Ok(Self::Transit),
            Some("ETHEREUM") => Ok(Self::Ethereum),
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
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeySpec {
    SymmetricDefault,
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    Rsa4096,
    EccSecgP256k1,
}

impl KeySpec {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "SYMMETRIC_DEFAULT" => Ok(Self::SymmetricDefault),
            "ECDSA_P256" => Ok(Self::EcdsaP256),
            "ECDSA_P384" => Ok(Self::EcdsaP384),
            "ED25519" => Ok(Self::Ed25519),
            "RSA_4096" => Ok(Self::Rsa4096),
            "ECC_SECG_P256K1" => Ok(Self::EccSecgP256k1),
            _ => Err("KeySpec is not supported".to_string()),
        }
    }

    fn allowed_usage(self) -> KeyUsage {
        match self {
            Self::SymmetricDefault => KeyUsage::EncryptDecrypt,
            Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096
            | Self::EccSecgP256k1 => KeyUsage::SignVerify,
        }
    }

    fn requires_scheme(self) -> Scheme {
        match self {
            Self::EccSecgP256k1 => Scheme::Ethereum,
            Self::SymmetricDefault
            | Self::EcdsaP256
            | Self::EcdsaP384
            | Self::Ed25519
            | Self::Rsa4096 => Scheme::Transit,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyUsage {
    EncryptDecrypt,
    SignVerify,
}

impl KeyUsage {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ENCRYPT_DECRYPT" => Ok(Self::EncryptDecrypt),
            "SIGN_VERIFY" => Ok(Self::SignVerify),
            _ => Err("KeyUsage must be ENCRYPT_DECRYPT or SIGN_VERIFY".to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EncryptionAlgorithm {
    SymmetricDefault,
}

impl EncryptionAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "SYMMETRIC_DEFAULT" => Ok(Self::SymmetricDefault),
            _ => Err("EncryptionAlgorithm must be SYMMETRIC_DEFAULT".to_string()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SigningAlgorithm {
    EcdsaSha256,
    EcdsaSha384,
    Ed25519,
    EthereumSecp256k1,
    RsassaPkcs1V15Sha256,
    RsassaPssSha256,
}

impl SigningAlgorithm {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "ECDSA_SHA_256" => Ok(Self::EcdsaSha256),
            "ECDSA_SHA_384" => Ok(Self::EcdsaSha384),
            "ED25519" => Ok(Self::Ed25519),
            "ETHEREUM_SECP256K1" => Ok(Self::EthereumSecp256k1),
            "RSASSA_PKCS1_V1_5_SHA_256" => Ok(Self::RsassaPkcs1V15Sha256),
            "RSASSA_PSS_SHA_256" => Ok(Self::RsassaPssSha256),
            _ => Err("SigningAlgorithm is not supported".to_string()),
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
        match self {
            Self::Raw | Self::Digest => true,
            Self::Eip191 => Scheme::Ethereum.supports_signing_algorithm(signing_algorithm),
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
        validate_required("KeyId", &req.key_id)?;
        validate_required("Plaintext", &req.plaintext)?;

        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_decrypt(req: &DecryptRequest) -> Result<(), String> {
        validate_required("CiphertextBlob", &req.ciphertext_blob)?;
        if let Some(key_id) = req.key_id.as_ref() {
            validate_required("KeyId", key_id)?;
        }
        if let Some(algorithm) = req.encryption_algorithm.as_ref() {
            validate_encryption_algorithm(algorithm)?;
        }
        Ok(())
    }

    pub fn validate_sign(req: &SignRequest) -> Result<(), String> {
        validate_required("KeyId", &req.key_id)?;
        validate_required("Message", &req.message)?;
        let signing_algorithm = validate_signing_algorithm(&req.signing_algorithm)?;
        if let Some(message_type) = req.message_type.as_ref() {
            let message_type = MessageType::parse(message_type)?;
            if !message_type.allowed_for(signing_algorithm) {
                return Err(
                    "MessageType EIP191 requires SigningAlgorithm ETHEREUM_SECP256K1".to_string(),
                );
            }
        }
        Ok(())
    }

    pub fn validate_create_key(req: &CreateKeyRequest) -> Result<(), String> {
        let scheme = Scheme::parse_optional(req.scheme.as_deref())?;
        let key_spec = validate_key_spec(&req.key_spec, scheme)?;
        let key_usage = validate_key_usage(&req.key_usage)?;

        if key_usage != key_spec.allowed_usage() {
            return Err(match (scheme, key_spec) {
                (_, KeySpec::SymmetricDefault) => {
                    "SYMMETRIC_DEFAULT keys must use ENCRYPT_DECRYPT".to_string()
                }
                (Scheme::Ethereum, _) => "ETHEREUM keys must use SIGN_VERIFY".to_string(),
                (Scheme::Transit, _) => "Asymmetric KMS keys must use SIGN_VERIFY".to_string(),
            });
        }

        for tag in &req.tags {
            validate_required("TagKey", &tag.tag_key)?;
        }
        Ok(())
    }

    pub fn validate_generate_data_key(req: &GenerateDataKeyRequest) -> Result<(), String> {
        validate_required("KeyId", &req.key_id)?;
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
        validate_required("KeyId", &req.key_id)
    }

    pub async fn encrypt(&mut self, req: EncryptRequest) -> Result<EncryptResponse, tonic::Status> {
        let response: PluginEncryptResponse = self
            .client
            .encrypt(tonic::Request::new(PluginEncryptRequest {
                key_id: req.key_id,
                plaintext: req.plaintext,
                encryption_algorithm: req.encryption_algorithm,
            }))
            .await?
            .into_inner();

        Ok(EncryptResponse {
            ciphertext_blob: response.ciphertext_blob,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn decrypt(&mut self, req: DecryptRequest) -> Result<DecryptResponse, tonic::Status> {
        let response: PluginDecryptResponse = self
            .client
            .decrypt(tonic::Request::new(PluginDecryptRequest {
                ciphertext_blob: req.ciphertext_blob,
                key_id: req.key_id,
                encryption_algorithm: req.encryption_algorithm,
            }))
            .await?
            .into_inner();

        Ok(DecryptResponse {
            plaintext: response.plaintext,
            key_id: response.key_id,
            encryption_algorithm: response.encryption_algorithm,
        })
    }

    pub async fn sign(&mut self, req: SignRequest) -> Result<SignResponse, tonic::Status> {
        let response: PluginSignResponse = self
            .client
            .sign(tonic::Request::new(PluginSignRequest {
                key_id: req.key_id,
                message: req.message,
                signing_algorithm: req.signing_algorithm,
                message_type: req.message_type,
            }))
            .await?
            .into_inner();

        Ok(SignResponse {
            key_id: response.key_id,
            signature: response.signature,
            signing_algorithm: response.signing_algorithm,
        })
    }

    pub async fn create_key(
        &mut self,
        req: CreateKeyRequest,
    ) -> Result<CreateKeyResponse, tonic::Status> {
        let response: PluginCreateKeyResponse = self
            .client
            .create_key(tonic::Request::new(PluginCreateKeyRequest {
                description: req.description,
                key_spec: req.key_spec,
                key_usage: req.key_usage,
                scheme: req.scheme,
                tags: req
                    .tags
                    .into_iter()
                    .map(|tag| PluginTag {
                        tag_key: tag.tag_key,
                        tag_value: tag.tag_value,
                    })
                    .collect(),
            }))
            .await?
            .into_inner();

        Ok(CreateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
    }

    pub async fn generate_data_key(
        &mut self,
        req: GenerateDataKeyRequest,
    ) -> Result<GenerateDataKeyResponse, tonic::Status> {
        let response: PluginGenerateDataKeyResponse = self
            .client
            .generate_data_key(tonic::Request::new(PluginGenerateDataKeyRequest {
                key_id: req.key_id,
                data_key_spec: req.data_key_spec,
                number_of_bytes: req.number_of_bytes,
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
        req: RotateKeyRequest,
    ) -> Result<RotateKeyResponse, tonic::Status> {
        let response: PluginRotateKeyResponse = self
            .client
            .rotate_key(tonic::Request::new(PluginRotateKeyRequest {
                key_id: req.key_id,
            }))
            .await?
            .into_inner();

        Ok(RotateKeyResponse {
            key_metadata: response.key_metadata.map(map_key_metadata),
        })
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
    })?;

    if scheme.supports_key_spec(key_spec) {
        Ok(key_spec)
    } else {
        Err(match scheme {
            Scheme::Transit => "KeySpec is not supported".to_string(),
            Scheme::Ethereum => "ETHEREUM keys must use ECC_SECG_P256K1".to_string(),
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
            key_spec: "SYMMETRIC_DEFAULT".to_string(),
            key_usage: "SIGN_VERIFY".to_string(),
            scheme: None,
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
            tags: vec![],
        };
        KmsService::validate_create_key(&req).unwrap();
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
    fn test_validate_sign_eip191_requires_ethereum_algorithm() {
        let req = SignRequest {
            key_id: "kms:abc".to_string(),
            message: "YWJj".to_string(),
            signing_algorithm: "ECDSA_SHA_256".to_string(),
            message_type: Some("EIP191".to_string()),
        };
        let err = KmsService::validate_sign(&req).unwrap_err();
        assert!(err.contains("ETHEREUM_SECP256K1"));
    }
}
