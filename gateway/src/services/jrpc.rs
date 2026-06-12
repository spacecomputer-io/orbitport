use crate::{plugins::PluginCatalog, proto::services::ctrng::CTrngResponse};
use serde::{Deserialize, Serialize};

use crate::proto::services::ctrng::CTrngRequest;
use crate::proto::services::kms::{
    CreateKeyRequest, DecryptRequest, EncryptRequest, GenerateDataKeyRequest,
    GetCapabilitiesRequest, RotateKeyRequest, SignRequest,
};
use crate::proto::services::threshold::DkgRequest;

use crate::services::ctrng::{CTrngService, MAX_CHUNKS};
use crate::services::kms::{KmsRpcCall, KmsService};
use crate::services::threshold::{ThresholdRpcCall, ThresholdService};

#[derive(Serialize)]
pub struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// Struct representing a JSON-RPC request, which includes the JSON-RPC version,
/// an ID for correlating requests and responses, and the RPC call details.
#[derive(Deserialize, Debug)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    pub id: u64,
    #[serde(flatten)]
    pub call: RpcCall,
}
/// Struct representing a JSON-RPC response.
/// It can be either a success with a result or an error with a message.
/// The `id` field is used to correlate the response with the original request.
#[derive(Serialize)]
pub struct JsonRpcResponse<T> {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    pub id: u64,
}

impl<T> JsonRpcResponse<T> {
    pub fn success(id: u64, result: T) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn error(id: u64, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
            id,
        }
    }
}

/// Enum representing the different RPC calls that the gateway can handle.
/// Each variant corresponds to a specific RPC method and contains the parameters for that method.
/// The "method" format is `{service}.{method}`, where the service is always lowercase and the method is in CamelCase.
/// This allows for easy routing of RPC calls to the appropriate service handlers.
#[derive(Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
pub enum RpcCall {
    #[serde(rename = "ctrng.Get")]
    GetCTRNG(CTrngRequest),
    #[serde(rename = "kms.GetCapabilities")]
    GetCapabilities(GetCapabilitiesRequest),
    #[serde(rename = "kms.CreateKey")]
    CreateKey(CreateKeyRequest),
    #[serde(rename = "kms.Decrypt")]
    Decrypt(DecryptRequest),
    #[serde(rename = "kms.Encrypt")]
    Encrypt(EncryptRequest),
    #[serde(rename = "kms.GenerateDataKey")]
    GenerateDataKey(GenerateDataKeyRequest),
    #[serde(rename = "kms.RotateKey")]
    RotateKey(RotateKeyRequest),
    #[serde(rename = "kms.Sign")]
    Sign(SignRequest),
    #[serde(rename = "kms_threshold.CoordinateDKG")]
    CoordinateDKG(DkgRequest),
}

impl RpcCall {
    /// Validates the parameters of the RPC call.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            RpcCall::GetCTRNG(req) => {
                if let Some(chunks) = req.chunks {
                    if chunks > MAX_CHUNKS {
                        return Err("Max chunks exceeded".to_string());
                    }
                    if chunks < 1 {
                        return Err("Chunks must be at least 1".to_string());
                    }
                }
            }
            RpcCall::GetCapabilities(_) => {}
            RpcCall::Encrypt(req) => KmsService::validate_encrypt(req)?,
            RpcCall::Decrypt(req) => KmsService::validate_decrypt(req)?,
            RpcCall::Sign(req) => KmsService::validate_sign(req)?,
            RpcCall::CreateKey(req) => KmsService::validate_create_key(req)?,
            RpcCall::GenerateDataKey(req) => KmsService::validate_generate_data_key(req)?,
            RpcCall::RotateKey(req) => KmsService::validate_rotate_key(req)?,
            RpcCall::CoordinateDKG(req) => {
                ThresholdService::validate_coordinate_dkg(req).map_err(|e| e.to_string())?
            }
        }
        Ok(())
    }

    /// Executes the RPC call using the provided plugin catalog.
    pub async fn execute(
        self,
        req_id: u64,
        client_id: &str,
        plugin_catalog: &PluginCatalog,
    ) -> Result<serde_json::Value, tonic::Status> {
        match self {
            RpcCall::GetCTRNG(req) => {
                let grpc_client = plugin_catalog
                    .get_masterseed_client()
                    .await
                    .map_err(|_| tonic::Status::unavailable("Masterseed plugin unavailable"))?;
                let mut svc = CTrngService::new(grpc_client);
                let results: CTrngResponse = svc.get_values(req).await.map_err(|e| {
                    // We can log _e here for debugging, but we don't want to expose internal errors to the client
                    tracing::warn!("Failed to get mixed cTRNG: {:?}", e);
                    tonic::Status::internal("Failed to get mixed cTRNG")
                })?;
                serialize_success_response(req_id, results)
            }
            RpcCall::GetCapabilities(_) => {
                serialize_success_response(req_id, KmsService::get_capabilities())
            }
            RpcCall::Encrypt(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Encrypt(req)).await
            }
            RpcCall::Decrypt(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Decrypt(req)).await
            }
            RpcCall::Sign(req) => {
                execute_kms(req_id, client_id, plugin_catalog, KmsRpcCall::Sign(req)).await
            }
            RpcCall::CreateKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::CreateKey(req),
                )
                .await
            }
            RpcCall::GenerateDataKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::GenerateDataKey(req),
                )
                .await
            }
            RpcCall::RotateKey(req) => {
                execute_kms(
                    req_id,
                    client_id,
                    plugin_catalog,
                    KmsRpcCall::RotateKey(req),
                )
                .await
            }
            RpcCall::CoordinateDKG(req) => {
                execute_threshold(
                    req_id,
                    client_id,
                    plugin_catalog,
                    ThresholdRpcCall::CoordinateDkg(req),
                )
                .await
            }
        }
    }
}

fn serialize_success_response<T: Serialize>(
    req_id: u64,
    result: T,
) -> Result<serde_json::Value, tonic::Status> {
    let res = JsonRpcResponse::success(req_id, result);
    serde_json::to_value(res)
        .map_err(|e| tonic::Status::internal(format!("Failed to serialize response: {}", e)))
}

async fn execute_kms(
    req_id: u64,
    client_id: &str,
    plugin_catalog: &PluginCatalog,
    call: KmsRpcCall,
) -> Result<serde_json::Value, tonic::Status> {
    let grpc_client = plugin_catalog
        .get_kms_client()
        .await
        .map_err(|_| tonic::Status::unavailable("KMS plugin unavailable"))?;
    let mut svc = KmsService::new(grpc_client);
    let results = svc.execute(client_id, req_id, call).await?;
    serialize_success_response(req_id, results)
}

async fn execute_threshold(
    req_id: u64,
    client_id: &str,
    plugin_catalog: &PluginCatalog,
    call: ThresholdRpcCall,
) -> Result<serde_json::Value, tonic::Status> {
    let grpc_client = plugin_catalog
        .get_threshold_client()
        .await
        .map_err(|_| tonic::Status::unavailable("Threshold plugin unavailable"))?;
    let mut svc = ThresholdService::new(grpc_client, plugin_catalog.threshold_groups());
    let results = svc.execute(client_id, req_id, call).await?;
    serialize_success_response(req_id, results)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialize_kms_encrypt_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "kms.Encrypt",
            "params": {
                "KeyId": "kms:abc",
                "Plaintext": "Zm9v",
                "EncryptionAlgorithm": "AES_256_GCM96"
            }
        });

        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        match req.call {
            RpcCall::Encrypt(params) => {
                assert_eq!(params.key_id, "kms:abc");
                assert_eq!(params.plaintext, "Zm9v");
                assert_eq!(
                    params.encryption_algorithm.as_deref(),
                    Some("AES_256_GCM96")
                );
            }
            _ => panic!("expected kms.Encrypt"),
        }
    }

    #[test]
    fn test_deserialize_kms_get_capabilities_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "kms.GetCapabilities",
            "params": {}
        });

        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        match req.call {
            RpcCall::GetCapabilities(_) => {}
            _ => panic!("expected kms.GetCapabilities"),
        }
    }

    #[test]
    fn test_deserialize_threshold_coordinate_dkg_pascal_case() {
        let raw = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "kms_threshold.CoordinateDKG",
            "params": {
                "Alias": "key-1",
                "GroupName": "team-a"
            }
        });

        let req: JsonRpcRequest = serde_json::from_value(raw).unwrap();
        match req.call {
            RpcCall::CoordinateDKG(params) => {
                assert_eq!(params.alias, "key-1");
                assert_eq!(params.group_name, "team-a");
            }
            _ => panic!("expected kms_threshold.CoordinateDKG"),
        }
    }
}
