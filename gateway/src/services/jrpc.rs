use crate::{plugins::PluginCatalog, proto::services::ctrng::CTrngResponse};
use serde::{Deserialize, Serialize};

use crate::proto::services::ctrng::CTrngRequest;

use crate::services::ctrng::CTrngService;

#[derive(Deserialize, Debug)]
pub struct JsonRpcRequest {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: String,
    pub id: u64,
    #[serde(flatten)]
    pub call: RpcCall, // This handles method + params mapping automatically
}

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
                if req.chunks.is_some() && req.chunks.unwrap() > 10 {
                    return Err("Max chunks exceeded".to_string());
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
                    .map_err(|_| tonic::Status::not_found("Masterseed plugin not found"))?;
                let mut svc = CTrngService::new(grpc_client);
                let count = req.chunks.unwrap_or(1);
                let results: CTrngResponse = svc.get_mixed(count).await.map_err(|e| {
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
