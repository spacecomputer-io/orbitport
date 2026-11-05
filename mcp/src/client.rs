use crate::types::McpError;
use kms_mcp_core::PreparedCall;
use reqwest::{
    Client, StatusCode, Url,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: &'a RawValue,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: u64,
    #[serde(default)]
    result: Option<Box<RawValue>>,
    #[serde(default)]
    error: Option<Box<RawValue>>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    code: i64,
}

#[derive(Deserialize)]
struct GatewayErrorResponse {
    error: Option<String>,
}

pub struct GatewayClient {
    client: Client,
    endpoint: Url,
    next_id: AtomicU64,
}

impl GatewayClient {
    pub fn new(base: &str, pat: &str) -> Result<Self, McpError> {
        Self::with_timeout(base, pat, Duration::from_secs(30))
    }

    pub fn with_timeout(base: &str, pat: &str, timeout: Duration) -> Result<Self, McpError> {
        let mut endpoint = Url::parse(base).map_err(|_| McpError::InvalidGatewayUrl)?;
        let loopback = endpoint.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_matches(['[', ']'])
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        });
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback) {
            return Err(McpError::InsecureGatewayUrl);
        }
        if endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(McpError::InvalidGatewayBaseUrl);
        }
        endpoint.set_path("/api/v1/rpc");
        if pat.trim().is_empty() {
            return Err(McpError::MissingPat);
        }
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {pat}")).map_err(|_| McpError::InvalidPat)?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .build()
            .map_err(|_| McpError::ClientInitialization)?;
        Ok(Self {
            client,
            endpoint,
            next_id: AtomicU64::new(1),
        })
    }

    pub async fn execute(&self, call: &PreparedCall) -> Result<Box<RawValue>, McpError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = serde_json::to_vec(&JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: call.method,
            params: &call.arguments,
        })
        .map_err(|_| McpError::RequestEncoding)?;
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .body(body)
            .send()
            .await
            .map_err(|_| McpError::GatewayRequest)?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| McpError::GatewayResponseInterrupted)?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(McpError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        if status != StatusCode::OK {
            return Err(http_error(status, &bytes));
        }
        let envelope: JsonRpcResponse =
            serde_json::from_slice(&bytes).map_err(|_| McpError::InvalidRpcResponse)?;
        if envelope.jsonrpc != "2.0"
            || envelope.id != id
            || envelope.result.is_some() == envelope.error.is_some()
        {
            return Err(McpError::InvalidRpcResponse);
        }
        if let Some(error) = envelope.error {
            return Err(
                match serde_json::from_str::<JsonRpcError>(error.get()).map(|e| e.code) {
                    Ok(-32602) => McpError::InvalidParameters,
                    _ => McpError::OperationFailed,
                },
            );
        }
        let result = envelope.result.ok_or(McpError::InvalidRpcResponse)?;
        if !result.get().trim_start().starts_with('{') {
            return Err(McpError::InvalidRpcResult);
        }
        Ok(result)
    }
}

fn http_error(status: StatusCode, bytes: &[u8]) -> McpError {
    let code = serde_json::from_slice::<GatewayErrorResponse>(bytes)
        .ok()
        .and_then(|e| e.error);
    match (status, code.as_deref()) {
        (StatusCode::UNAUTHORIZED, Some("token_expired")) => McpError::PatExpired,
        (StatusCode::UNAUTHORIZED, _) => McpError::InvalidCredential,
        (StatusCode::PAYMENT_REQUIRED, _) => McpError::InsufficientCredits,
        (StatusCode::FORBIDDEN, Some("account_inactive")) => McpError::AccountInactive,
        (StatusCode::FORBIDDEN, _) => McpError::PermissionDenied,
        (StatusCode::TOO_MANY_REQUESTS, _) => McpError::RateLimitExceeded,
        (StatusCode::PAYLOAD_TOO_LARGE, _) => McpError::RequestTooLarge,
        _ if status.is_server_error() => McpError::BackendUnavailable,
        _ if status.is_redirection() => McpError::Redirect,
        _ => McpError::GatewayRejected,
    }
}
