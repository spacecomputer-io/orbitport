use crate::{plugins::PluginCatalog, proto::services::ctrng::CTrngResponse};
use serde::{Deserialize, Serialize};

use crate::proto::services::ctrng::CTrngRequest;

use crate::services::ctrng::{CTrngService, MAX_CHUNKS};

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
    jsonrpc: String,
    result: Option<T>,
    error: Option<String>,
    pub id: u64,
}

impl JsonRpcResponse<()> {
    pub fn error(id: u64, message: String) -> Self {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(message),
            id,
        }
    }

    pub fn success<T>(id: u64, result: T) -> JsonRpcResponse<T> {
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
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
        }
        Ok(())
    }

    /// Executes the RPC call using the provided plugin catalog.
    pub async fn execute(
        self,
        req_id: u64,
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
                let res = JsonRpcResponse::success(req_id, results);
                let val = serde_json::to_value(res).map_err(|e| {
                    tonic::Status::internal(format!("Failed to serialize response: {}", e))
                })?;
                Ok(val)
            }
        }
    }
}
