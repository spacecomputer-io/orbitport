use orbitport_kms_api::{
    CreateKeyRequest, CreateKeyResponse, DecapsulateRequest, DecapsulateResponse, DecryptRequest,
    DecryptResponse, EncapsulateRequest, EncapsulateResponse, EncryptRequest, EncryptResponse,
    GenerateDataKeyRequest, GenerateDataKeyResponse, GetCapabilitiesRequest,
    GetCapabilitiesResponse, GetKeyMetadataRequest, GetKeyMetadataResponse, GetPublicKeyRequest,
    GetPublicKeyResponse, KeyStoreDeleteRequest, KeyStoreDeleteResponse, KeyStoreGetRequest,
    KeyStoreGetResponse, KeyStoreListRequest, KeyStoreListResponse, KeyStorePutRequest,
    KeyStorePutResponse, KmsValidation, RotateKeyRequest, RotateKeyResponse, SignRequest,
    SignResponse,
};
use schemars::JsonSchema;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, value::RawValue};
use std::collections::{BTreeSet, HashMap};

pub struct ToolSpec {
    pub name: &'static str,
    pub method: &'static str,
    pub allow: Option<&'static str>,
    description: &'static str,
    read_only: bool,
    destructive: bool,
    input: fn() -> Value,
    output: fn() -> Value,
    validate: fn(&str) -> Result<(), String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    output_schema: Value,
    annotations: Annotations,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Annotations {
    read_only_hint: bool,
    destructive_hint: bool,
    idempotent_hint: bool,
    open_world_hint: bool,
}

#[derive(Default)]
pub struct ToolPolicy {
    allowed: BTreeSet<&'static str>,
}

impl ToolPolicy {
    pub fn new(csv: &str) -> Result<Self, String> {
        let registry = registry();
        let mut allowed = BTreeSet::new();
        for name in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let value = registry
                .iter()
                .filter_map(|tool| tool.allow)
                .find(|value| *value == name)
                .ok_or_else(|| {
                    "Unknown --allow value; see --help for supported tools".to_string()
                })?;
            allowed.insert(value);
        }
        Ok(Self { allowed })
    }

    fn permits(&self, spec: &ToolSpec) -> bool {
        spec.allow.is_none_or(|name| self.allowed.contains(name))
    }

    pub fn definitions(&self) -> Vec<ToolDefinition> {
        registry()
            .into_iter()
            .filter(|spec| self.permits(spec))
            .map(|spec| ToolDefinition {
                name: spec.name,
                description: spec.description,
                input_schema: (spec.input)(),
                output_schema: (spec.output)(),
                annotations: Annotations {
                    read_only_hint: spec.read_only,
                    destructive_hint: spec.destructive,
                    idempotent_hint: spec.read_only,
                    open_world_hint: false,
                },
            })
            .collect()
    }

    pub fn prepare(&self, name: &str, arguments: &str) -> Result<PreparedCall, String> {
        let spec = registry()
            .into_iter()
            .find(|spec| spec.name == name && self.permits(spec))
            .ok_or_else(|| {
                "Unknown or disabled tool; enable sensitive tools in your harness configuration with --allow"
                    .to_string()
            })?;
        let fields: HashMap<String, Box<RawValue>> =
            serde_json::from_str(arguments).map_err(|_| "Tool arguments must be a JSON object")?;
        for identity in ["ClientId", "client_id", "KmsTenant", "kms_tenant"] {
            if fields.contains_key(identity) {
                return Err(
                    "Identity fields are controlled by Orbitport and must not be provided"
                        .to_string(),
                );
            }
        }
        (spec.validate)(arguments)?;
        Ok(PreparedCall {
            method: spec.method,
            arguments: RawValue::from_string(arguments.to_string())
                .map_err(|_| "Invalid tool arguments")?,
        })
    }
}

pub struct PreparedCall {
    pub method: &'static str,
    pub arguments: Box<RawValue>,
}

impl std::fmt::Debug for PreparedCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedCall")
            .field("method", &self.method)
            .field("arguments", &"<redacted>")
            .finish()
    }
}

fn schema<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).expect("generated schema is JSON")
}

fn validate<T: DeserializeOwned>(
    raw: &str,
    validate: fn(&T) -> Result<(), String>,
) -> Result<(), String> {
    let req = serde_json::from_str(raw)
        .map_err(|_| "Invalid tool arguments: missing field or incorrect type")?;
    validate(&req)
}

pub fn registry() -> Vec<ToolSpec> {
    macro_rules! tool {
        (
            $name:literal, $method:literal, $input:ty, $output:ty, $validator:expr,
            allow: $allow:expr, read_only: $read:expr, destructive: $destroy:expr,
            description: $description:literal
        ) => {
            ToolSpec {
                name: $name,
                method: $method,
                allow: $allow,
                read_only: $read,
                destructive: $destroy,
                description: $description,
                input: schema::<$input>,
                output: schema::<$output>,
                validate: |raw| validate::<$input>(raw, $validator),
            }
        };
    }
    vec![
        tool!(
            "kms_get_capabilities",
            "kms.GetCapabilities",
            GetCapabilitiesRequest,
            GetCapabilitiesResponse,
            |_| Ok(()),
            allow: None,
            read_only: true,
            destructive: false,
            description: "Discover supported KMS schemes, key specs and algorithms."
        ),
        tool!(
            "kms_create_key",
            "kms.CreateKey",
            CreateKeyRequest,
            CreateKeyResponse,
            KmsValidation::validate_create_key,
            allow: None,
            read_only: false,
            destructive: false,
            description: "Create a tenant-scoped cryptographic key. Orbitport resolves tenancy from authentication."
        ),
        tool!(
            "kms_get_key_metadata",
            "kms.GetKeyMetadata",
            GetKeyMetadataRequest,
            GetKeyMetadataResponse,
            KmsValidation::validate_get_key_metadata,
            allow: None,
            read_only: true,
            destructive: false,
            description: "Read metadata for a tenant-scoped KMS key."
        ),
        tool!(
            "kms_get_public_key",
            "kms.GetPublicKey",
            GetPublicKeyRequest,
            GetPublicKeyResponse,
            KmsValidation::validate_get_public_key,
            allow: None,
            read_only: true,
            destructive: false,
            description: "Read an asymmetric public key, optionally at a historical version."
        ),
        tool!(
            "kms_encrypt",
            "kms.Encrypt",
            EncryptRequest,
            EncryptResponse,
            KmsValidation::validate_encrypt,
            allow: None,
            read_only: false,
            destructive: false,
            description: "Encrypt base64 plaintext. Inputs are sensitive; do not log them."
        ),
        tool!(
            "kms_decrypt",
            "kms.Decrypt",
            DecryptRequest,
            DecryptResponse,
            KmsValidation::validate_decrypt,
            allow: Some("decrypt"),
            read_only: false,
            destructive: false,
            description: "Decrypt a KMS ciphertext. Plaintext output is sensitive; do not log it."
        ),
        tool!(
            "kms_sign",
            "kms.Sign",
            SignRequest,
            SignResponse,
            KmsValidation::validate_sign,
            allow: None,
            read_only: false,
            destructive: false,
            description: "Sign a base64 message with a KMS key. Message inputs may be sensitive; do not log them."
        ),
        tool!(
            "kms_encapsulate",
            "kms.Encapsulate",
            EncapsulateRequest,
            EncapsulateResponse,
            KmsValidation::validate_encapsulate,
            allow: Some("encapsulate"),
            read_only: false,
            destructive: false,
            description: "Encapsulate a shared key. Currently disabled with ML-KEM. Key material is sensitive."
        ),
        tool!(
            "kms_decapsulate",
            "kms.Decapsulate",
            DecapsulateRequest,
            DecapsulateResponse,
            KmsValidation::validate_decapsulate,
            allow: Some("decapsulate"),
            read_only: false,
            destructive: false,
            description: "Decapsulate a shared key. Currently disabled with ML-KEM. Key material is sensitive."
        ),
        tool!(
            "kms_generate_data_key",
            "kms.GenerateDataKey",
            GenerateDataKeyRequest,
            GenerateDataKeyResponse,
            KmsValidation::validate_generate_data_key,
            allow: Some("generate-data-key"),
            read_only: false,
            destructive: false,
            description: "Generate plaintext and encrypted data keys. Plaintext output is sensitive; do not log it."
        ),
        tool!(
            "kms_rotate_key",
            "kms.RotateKey",
            RotateKeyRequest,
            RotateKeyResponse,
            KmsValidation::validate_rotate_key,
            allow: None,
            read_only: false,
            destructive: false,
            description: "Rotate a tenant-scoped KMS key."
        ),
        tool!(
            "kms_keystore_put",
            "kms_keystore.Put",
            KeyStorePutRequest,
            KeyStorePutResponse,
            KmsValidation::validate_key_store_put,
            allow: None,
            read_only: false,
            destructive: true,
            description: "Store an opaque JSON object, replacing an existing entry with the same name. Secret values are sensitive; do not log them."
        ),
        tool!(
            "kms_keystore_get",
            "kms_keystore.Get",
            KeyStoreGetRequest,
            KeyStoreGetResponse,
            KmsValidation::validate_key_store_get,
            allow: Some("keystore-get"),
            read_only: true,
            destructive: false,
            description: "Read an opaque JSON secret object. Secret output is sensitive; do not log it."
        ),
        tool!(
            "kms_keystore_list",
            "kms_keystore.List",
            KeyStoreListRequest,
            KeyStoreListResponse,
            KmsValidation::validate_key_store_list,
            allow: None,
            read_only: true,
            destructive: false,
            description: "List immediate key-store entries and folders under an optional prefix."
        ),
        tool!(
            "kms_keystore_delete",
            "kms_keystore.Delete",
            KeyStoreDeleteRequest,
            KeyStoreDeleteResponse,
            KmsValidation::validate_key_store_delete,
            allow: Some("keystore-delete"),
            read_only: false,
            destructive: true,
            description: "Permanently delete a key-store entry and all its versions."
        ),
    ]
}
