use crate::filters::{
    AuthContext, RateLimiter, account_hold, account_release, account_settle, with_auth,
    with_rate_limiter,
};
use crate::plugins::PluginCatalog;
use crate::proto::plugins::account::account_plugin_client::AccountPluginClient;
use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;
use crate::proto::services::kms::{
    CreateKeyRequest, DecapsulateRequest, DecryptRequest, EncapsulateRequest, EncryptRequest,
    GenerateDataKeyRequest, GetKeyMetadataRequest, GetPublicKeyRequest, RotateKeyRequest,
    SignRequest,
};
use crate::services::kms::{
    KeyStoreDeleteRequest, KeyStoreGetRequest, KeyStoreListRequest, KeyStorePutRequest, KmsRpcCall,
    KmsRpcResult, KmsService,
};
use crate::types::GatewayError;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json, value::RawValue};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tonic::transport::Channel;
use warp::filters::BoxedFilter;
use warp::http::StatusCode;
use warp::http::header::{HeaderMap, HeaderValue, WWW_AUTHENTICATE};
use warp::reply::Response;
use warp::{Filter, Rejection, Reply, reject::Reject};

const MCP_PROTOCOL_VERSION: &str = "2026-07-28";
const MCP_LEGACY_2025_11_25: &str = "2025-11-25";
const MCP_LEGACY_2025_06_18: &str = "2025-06-18";
const MCP_LEGACY_2025_03_26: &str = "2025-03-26";
const MCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct McpConfig {
    pub resource_url: String,
    pub authorization_servers: Vec<String>,
    pub allowed_origins: Vec<String>,
}

impl McpConfig {
    pub fn new(
        resource_url: impl Into<String>,
        authorization_servers: impl Into<String>,
        allowed_origins: impl Into<String>,
        http_port: u16,
    ) -> Self {
        let resource_url = normalize_resource_url(resource_url.into(), http_port);
        Self {
            resource_url,
            authorization_servers: split_csv(authorization_servers.into()),
            allowed_origins: split_csv(allowed_origins.into()),
        }
    }

    fn metadata_url(&self) -> String {
        let base = self
            .resource_url
            .strip_suffix("/mcp")
            .unwrap_or(&self.resource_url)
            .trim_end_matches('/');
        format!("{base}/.well-known/oauth-protected-resource/mcp")
    }
}

#[derive(Debug)]
struct McpOriginRejected;

impl Reject for McpOriginRejected {}

#[derive(Debug)]
struct McpProtocolRejected {
    id: Value,
    status: StatusCode,
    code: i32,
    message: String,
}

impl Reject for McpProtocolRejected {}

#[derive(Debug, Deserialize)]
struct McpRequest {
    #[serde(default)]
    jsonrpc: String,
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Option<Box<RawValue>>,
    #[serde(default, rename = "_meta")]
    _meta: Option<Value>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

#[derive(Serialize)]
struct JsonRpcResponse<T> {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Value,
}

#[derive(Serialize)]
struct TextContent {
    #[serde(rename = "type")]
    content_type: &'static str,
    text: String,
}

#[derive(Serialize)]
struct ToolCallResult {
    #[serde(rename = "resultType")]
    result_type: &'static str,
    content: Vec<TextContent>,
    #[serde(rename = "structuredContent", skip_serializing_if = "Option::is_none")]
    structured_content: Option<Box<RawValue>>,
    #[serde(rename = "isError", skip_serializing_if = "is_false")]
    is_error: bool,
}

#[derive(Serialize)]
struct ToolListResult {
    #[serde(rename = "resultType")]
    result_type: &'static str,
    tools: Vec<ToolDefinition>,
}

#[derive(Serialize)]
struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
    #[serde(rename = "outputSchema")]
    output_schema: Value,
}

#[derive(Debug)]
enum McpKmsCall {
    GetCapabilities,
    Kms(KmsRpcCall),
}

impl McpKmsCall {
    fn operation(&self) -> String {
        match self {
            Self::GetCapabilities => "kms.GetCapabilities".to_string(),
            Self::Kms(call) => call.operation(),
        }
    }

    fn validate(&self) -> Result<(), String> {
        match self {
            Self::GetCapabilities => Ok(()),
            Self::Kms(call) => call.validate(),
        }
    }

    async fn execute(
        self,
        req_id: u64,
        client_id: &str,
        plugin_catalog: &PluginCatalog,
    ) -> Result<Box<RawValue>, tonic::Status> {
        match self {
            Self::GetCapabilities => raw_json(KmsService::get_capabilities()),
            Self::Kms(call) => {
                let grpc_client = plugin_catalog
                    .get_kms_client()
                    .await
                    .map_err(|_| tonic::Status::unavailable("KMS plugin unavailable"))?;
                let mut svc = KmsService::new(grpc_client);
                let result: KmsRpcResult = svc.execute(client_id, req_id, call).await?;
                raw_json(result)
            }
        }
    }
}

pub fn routes(
    auth_client: AuthPluginClient<Channel>,
    rate_limiter: Arc<RateLimiter>,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
    body_max_bytes: u64,
    config: Arc<McpConfig>,
) -> BoxedFilter<(Response,)> {
    let metadata_config = config.clone();
    let metadata_root = warp::path!(".well-known" / "oauth-protected-resource")
        .and(warp::path::end())
        .map(move || metadata_response(metadata_config.clone()));

    let metadata_config = config.clone();
    let metadata_mcp = warp::path!(".well-known" / "oauth-protected-resource" / "mcp")
        .and(warp::path::end())
        .map(move || metadata_response(metadata_config.clone()));

    let endpoint_config = config.clone();
    let endpoint = warp::path("mcp")
        .and(warp::path::end())
        .and(warp::post())
        .and(with_origin(endpoint_config.clone()))
        .and(with_rate_limiter(with_auth(auth_client), rate_limiter))
        .and(warp::body::content_length_limit(body_max_bytes))
        .and(warp::body::json())
        .and(warp::any().map(move || plugin_catalog.clone()))
        .and(warp::any().map(move || account_client.clone()))
        .and(warp::any().map(move || endpoint_config.clone()))
        .and_then(handle_mcp_request);

    let recover_config = config.clone();
    metadata_root
        .or(metadata_mcp)
        .unify()
        .or(endpoint)
        .unify()
        .recover(move |err| handle_mcp_rejection(err, recover_config.clone()))
        .unify()
        .boxed()
}

fn with_origin(
    config: Arc<McpConfig>,
) -> impl Filter<Extract = (HeaderMap,), Error = Rejection> + Clone {
    warp::header::headers_cloned().and_then(move |headers: HeaderMap| {
        let config = config.clone();
        async move {
            if let Some(origin) = headers.get("origin") {
                let origin = origin
                    .to_str()
                    .map_err(|_| warp::reject::custom(McpOriginRejected))?;
                if !config
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed == origin)
                {
                    return Err(warp::reject::custom(McpOriginRejected));
                }
            }
            Ok::<_, Rejection>(headers)
        }
    })
}

async fn handle_mcp_request(
    headers: HeaderMap,
    auth: AuthContext,
    request: McpRequest,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
    config: Arc<McpConfig>,
) -> Result<Response, Rejection> {
    if request.jsonrpc != "2.0" {
        return Ok(protocol_error(
            request_id(&request),
            StatusCode::BAD_REQUEST,
            -32600,
            "Invalid JSON-RPC version",
        ));
    }

    if let Err(err) = validate_mcp_headers(&headers, &request) {
        return Err(warp::reject::custom(err));
    }

    let Some(id) = request.id.clone() else {
        return Ok(warp::reply::with_status("", StatusCode::ACCEPTED).into_response());
    };

    match request.method.as_str() {
        "initialize" => Ok(json_result(id, initialize_result())),
        "ping" => Ok(json_result(id, json!({}))),
        "tools/list" => Ok(json_result(
            id,
            ToolListResult {
                result_type: "complete",
                tools: tool_definitions(),
            },
        )),
        "tools/call" => {
            handle_tool_call(
                id,
                auth,
                request.params,
                plugin_catalog,
                account_client,
                config,
            )
            .await
        }
        _ => Ok(protocol_error(
            id,
            StatusCode::NOT_FOUND,
            -32601,
            format!("Method not found: {}", request.method),
        )),
    }
}

async fn handle_tool_call(
    id: Value,
    auth: AuthContext,
    params: Option<Box<RawValue>>,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
    _config: Arc<McpConfig>,
) -> Result<Response, Rejection> {
    let req_id = request_id_u64(&id);
    let tool_call = parse_tool_call_params(params.as_deref()).map_err(|e| {
        warp::reject::custom(McpProtocolRejected {
            id: id.clone(),
            status: StatusCode::BAD_REQUEST,
            code: -32602,
            message: e,
        })
    })?;

    tracing::debug!(
        "Handling MCP tools/call [id={} tool={}]",
        req_id,
        tool_call.name
    );

    let call = tool_to_kms_call(&tool_call.name, tool_call.arguments.as_deref()).map_err(|e| {
        warp::reject::custom(McpProtocolRejected {
            id: id.clone(),
            status: StatusCode::BAD_REQUEST,
            code: -32602,
            message: e,
        })
    })?;

    if let Err(e) = call.validate() {
        return Ok(protocol_error(
            id,
            StatusCode::OK,
            -32602,
            format!("Invalid request: {e}"),
        ));
    }

    let operation = call.operation();
    let ctx = account_hold(auth, account_client.clone(), 1, &operation).await?;
    let ledger_id = ctx.ledger_id.clone();
    let client_id = ctx.kms_tenant;

    match timeout(
        MCP_REQUEST_TIMEOUT,
        call.execute(req_id, &client_id, &plugin_catalog),
    )
    .await
    {
        Ok(Ok(raw_result)) => {
            tracing::debug!(
                "MCP tools/call succeeded [id={} tool={}]",
                req_id,
                tool_call.name
            );
            tokio::spawn(async move {
                account_settle(account_client, &ledger_id).await;
            });
            Ok(json_result(id, tool_success(raw_result)))
        }
        Ok(Err(status)) => {
            tracing::warn!(
                "MCP tools/call failed [id={} tool={} code={:?}]",
                req_id,
                tool_call.name,
                status.code()
            );
            account_release(account_client, &ledger_id).await;
            Ok(json_result(
                id,
                tool_error(sanitized_status_message(&status)),
            ))
        }
        Err(_) => {
            tracing::warn!(
                "MCP tools/call timed out [id={} tool={}]",
                req_id,
                tool_call.name
            );
            account_release(account_client, &ledger_id).await;
            Ok(json_result(id, tool_error("KMS request timed out")))
        }
    }
}

async fn handle_mcp_rejection(
    err: Rejection,
    config: Arc<McpConfig>,
) -> Result<Response, Infallible> {
    if err.find::<McpOriginRejected>().is_some() {
        return Ok(json_status(
            StatusCode::FORBIDDEN,
            &json!({"error": "origin_not_allowed"}),
        ));
    }
    if let Some(protocol) = err.find::<McpProtocolRejected>() {
        return Ok(protocol_error(
            protocol.id.clone(),
            protocol.status,
            protocol.code,
            protocol.message.clone(),
        ));
    }
    if let Some(gw) = err.find::<GatewayError>() {
        let (status, body) = match gw {
            GatewayError::InsufficientCredits => (
                StatusCode::PAYMENT_REQUIRED,
                json!({"error": "insufficient_credits"}),
            ),
            GatewayError::AccountPluginUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "account_plugin_unavailable", "detail": msg}),
            ),
            GatewayError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": "rate_limit_exceeded"}),
            ),
            GatewayError::NoAuthHeaderError | GatewayError::InvalidAuthHeaderError => {
                (StatusCode::UNAUTHORIZED, json!({"error": gw.to_string()}))
            }
            GatewayError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                json!({"error": "authentication_failed"}),
            ),
            GatewayError::PatExpired => (
                StatusCode::UNAUTHORIZED,
                json!({
                    "error": "token_expired",
                    "message": "Personal access token expired — create a new one in the dashboard"
                }),
            ),
            GatewayError::InvalidCredential => (
                StatusCode::UNAUTHORIZED,
                json!({
                    "error": "invalid_credential",
                    "message": "Unknown or revoked credential"
                }),
            ),
            GatewayError::AuthPluginConnectionError(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "auth_plugin_unavailable"}),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": gw.to_string()}),
            ),
        };
        let mut response = json_status(status, &body);
        if status == StatusCode::UNAUTHORIZED {
            add_authenticate_header(&mut response, &config);
        }
        return Ok(response);
    }
    if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        return Ok(protocol_error(
            Value::Null,
            StatusCode::BAD_REQUEST,
            -32700,
            format!("Parse error: {e}"),
        ));
    }
    if err.is_not_found() {
        return Ok(json_status(
            StatusCode::NOT_FOUND,
            &json!({"error": "not_found"}),
        ));
    }
    tracing::error!("unhandled MCP rejection: {err:?}");
    Ok(json_status(
        StatusCode::INTERNAL_SERVER_ERROR,
        &json!({"error": "internal_error"}),
    ))
}

fn metadata_response(config: Arc<McpConfig>) -> Response {
    json_status(
        StatusCode::OK,
        &json!({
            "resource": config.resource_url,
            "authorization_servers": config.authorization_servers,
            "bearer_methods_supported": ["header"],
            "resource_documentation": "https://github.com/spacecomputer-io/orbitport",
        }),
    )
}

fn validate_mcp_headers(
    headers: &HeaderMap,
    request: &McpRequest,
) -> Result<(), McpProtocolRejected> {
    let Some(version) = header_str(headers, "mcp-protocol-version") else {
        return Ok(());
    };
    if !matches!(
        version,
        MCP_PROTOCOL_VERSION
            | MCP_LEGACY_2025_11_25
            | MCP_LEGACY_2025_06_18
            | MCP_LEGACY_2025_03_26
    ) {
        return Err(header_error(
            request,
            format!("Unsupported MCP protocol version: {version}"),
        ));
    }
    match header_str(headers, "mcp-method") {
        Some(method) if method == request.method => {}
        Some(_) => return Err(header_error(request, "Mcp-Method header mismatch")),
        None if version == MCP_PROTOCOL_VERSION => {
            return Err(header_error(request, "Mcp-Method header is required"));
        }
        None => {}
    }

    if request.method == "tools/call" {
        let params = parse_tool_call_params(request.params.as_deref())
            .map_err(|e| header_error(request, e))?;
        match header_str(headers, "mcp-name") {
            Some(name) if name == params.name => {}
            Some(_) => return Err(header_error(request, "Mcp-Name header mismatch")),
            None if version == MCP_PROTOCOL_VERSION => {
                return Err(header_error(
                    request,
                    "Mcp-Name header is required for tools/call",
                ));
            }
            None => {}
        }
    }

    if version == MCP_PROTOCOL_VERSION {
        let meta_version = protocol_version_meta(request.params.as_deref())
            .ok_or_else(|| header_error(request, "MCP protocol version _meta is required"))?;
        if meta_version != version {
            return Err(header_error(
                request,
                "MCP protocol version header/body mismatch",
            ));
        }
    }

    Ok(())
}

fn parse_tool_call_params(params: Option<&RawValue>) -> Result<ToolCallParams, String> {
    let Some(params) = params else {
        return Err("tools/call params are required".to_string());
    };
    serde_json::from_str(params.get()).map_err(|e| format!("Invalid tools/call params: {e}"))
}

fn protocol_version_meta(params: Option<&RawValue>) -> Option<String> {
    let params = params?;
    let value: Value = serde_json::from_str(params.get()).ok()?;
    value
        .get("_meta")
        .and_then(|meta| meta.get("io.modelcontextprotocol/protocolVersion"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn header_error(request: &McpRequest, message: impl Into<String>) -> McpProtocolRejected {
    McpProtocolRejected {
        id: request_id(request),
        status: StatusCode::BAD_REQUEST,
        code: -32600,
        message: message.into(),
    }
}

fn tool_to_kms_call(name: &str, arguments: Option<&RawValue>) -> Result<McpKmsCall, String> {
    let args = arguments.map(RawValue::get).unwrap_or("{}");
    reject_identity_fields(args)?;
    match name {
        "kms_get_capabilities" => Ok(McpKmsCall::GetCapabilities),
        "kms_create_key" => parse_args(args)
            .map(|req: CreateKeyRequest| McpKmsCall::Kms(KmsRpcCall::CreateKey(req))),
        "kms_get_key_metadata" => parse_args(args)
            .map(|req: GetKeyMetadataRequest| McpKmsCall::Kms(KmsRpcCall::GetKeyMetadata(req))),
        "kms_get_public_key" => parse_args(args)
            .map(|req: GetPublicKeyRequest| McpKmsCall::Kms(KmsRpcCall::GetPublicKey(req))),
        "kms_encrypt" => {
            parse_args(args).map(|req: EncryptRequest| McpKmsCall::Kms(KmsRpcCall::Encrypt(req)))
        }
        "kms_decrypt" => {
            parse_args(args).map(|req: DecryptRequest| McpKmsCall::Kms(KmsRpcCall::Decrypt(req)))
        }
        "kms_sign" => {
            parse_args(args).map(|req: SignRequest| McpKmsCall::Kms(KmsRpcCall::Sign(req)))
        }
        "kms_encapsulate" => parse_args(args)
            .map(|req: EncapsulateRequest| McpKmsCall::Kms(KmsRpcCall::Encapsulate(req))),
        "kms_decapsulate" => parse_args(args)
            .map(|req: DecapsulateRequest| McpKmsCall::Kms(KmsRpcCall::Decapsulate(req))),
        "kms_generate_data_key" => parse_args(args)
            .map(|req: GenerateDataKeyRequest| McpKmsCall::Kms(KmsRpcCall::GenerateDataKey(req))),
        "kms_rotate_key" => parse_args(args)
            .map(|req: RotateKeyRequest| McpKmsCall::Kms(KmsRpcCall::RotateKey(req))),
        "kms_keystore_put" => parse_args(args)
            .map(|req: KeyStorePutRequest| McpKmsCall::Kms(KmsRpcCall::KeyStorePut(req))),
        "kms_keystore_get" => parse_args(args)
            .map(|req: KeyStoreGetRequest| McpKmsCall::Kms(KmsRpcCall::KeyStoreGet(req))),
        "kms_keystore_list" => parse_args(args)
            .map(|req: KeyStoreListRequest| McpKmsCall::Kms(KmsRpcCall::KeyStoreList(req))),
        "kms_keystore_delete" => parse_args(args)
            .map(|req: KeyStoreDeleteRequest| McpKmsCall::Kms(KmsRpcCall::KeyStoreDelete(req))),
        _ => Err(format!("Unknown MCP tool: {name}")),
    }
}

fn parse_args<T: for<'de> Deserialize<'de>>(args: &str) -> Result<T, String> {
    serde_json::from_str(args).map_err(|e| format!("Invalid tool arguments: {e}"))
}

fn reject_identity_fields(args: &str) -> Result<(), String> {
    let fields: HashMap<String, Box<RawValue>> =
        serde_json::from_str(args).map_err(|e| format!("Tool arguments must be an object: {e}"))?;
    for field in ["ClientId", "client_id", "KmsTenant", "kms_tenant"] {
        if fields.contains_key(field) {
            return Err(format!(
                "{field} is controlled by Orbitport and must not be provided"
            ));
        }
    }
    Ok(())
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "orbitport-kms",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            "kms_get_capabilities",
            "Return Orbitport KMS capabilities.",
            obj(vec![], vec![]),
            output_capabilities(),
        ),
        tool(
            "kms_create_key",
            "Create a tenant-scoped KMS key. Do not include ClientId; Orbitport resolves tenancy from auth.",
            obj(
                vec!["Alias", "Description", "KeySpec", "KeyUsage", "Tags"],
                vec![
                    str_prop("Alias", "Tenant-local key alias."),
                    str_prop(
                        "Description",
                        "Key description. Use an empty string if unset.",
                    ),
                    str_prop("Scheme", "Optional scheme: TRANSIT, ETHEREUM, or PQC."),
                    str_prop("KeySpec", "KMS key spec."),
                    str_prop("KeyUsage", "KMS key usage."),
                    tags_prop(),
                ],
            ),
            output_key_metadata(),
        ),
        tool(
            "kms_get_key_metadata",
            "Read metadata for a tenant-scoped KMS key.",
            obj(vec!["KeyId"], vec![str_prop("KeyId", "Key id or alias.")]),
            output_key_metadata(),
        ),
        tool(
            "kms_get_public_key",
            "Read a public key for an asymmetric KMS key.",
            obj(
                vec!["KeyId"],
                vec![
                    str_prop("KeyId", "Key id or alias."),
                    int_prop("Version", "Optional key version."),
                ],
            ),
            obj(
                vec!["PublicKey", "Version"],
                vec![
                    str_prop("PublicKey", "Public key material."),
                    int_prop("Version", "Key version."),
                ],
            ),
        ),
        tool(
            "kms_encrypt",
            "Encrypt base64 plaintext with a KMS encryption key. Secret-bearing inputs and outputs must not be logged.",
            obj(
                vec!["KeyId", "Plaintext"],
                vec![
                    str_prop("KeyId", "Key id or alias."),
                    str_prop("Plaintext", "Base64 plaintext."),
                    str_prop(
                        "EncryptionAlgorithm",
                        "Optional encryption algorithm, currently AES_256_GCM96.",
                    ),
                ],
            ),
            obj(
                vec!["CiphertextBlob", "KeyId", "EncryptionAlgorithm"],
                vec![
                    str_prop("CiphertextBlob", "KMS ciphertext blob."),
                    str_prop("KeyId", "Key id."),
                    str_prop("EncryptionAlgorithm", "Encryption algorithm."),
                ],
            ),
        ),
        tool(
            "kms_decrypt",
            "Decrypt a KMS ciphertext blob. Plaintext output is sensitive and must not be logged.",
            obj(
                vec!["CiphertextBlob"],
                vec![
                    str_prop("CiphertextBlob", "KMS ciphertext blob."),
                    str_prop("KeyId", "Optional key id or alias."),
                    str_prop(
                        "EncryptionAlgorithm",
                        "Optional encryption algorithm, currently AES_256_GCM96.",
                    ),
                ],
            ),
            obj(
                vec!["Plaintext", "KeyId", "EncryptionAlgorithm"],
                vec![
                    str_prop("Plaintext", "Base64 plaintext."),
                    str_prop("KeyId", "Key id."),
                    str_prop("EncryptionAlgorithm", "Encryption algorithm."),
                ],
            ),
        ),
        tool(
            "kms_sign",
            "Sign a base64 message with a KMS signing key. Message inputs may be sensitive and must not be logged.",
            obj(
                vec!["KeyId", "Message", "SigningAlgorithm"],
                vec![
                    str_prop("KeyId", "Key id or alias."),
                    str_prop("Message", "Base64 message."),
                    str_prop("SigningAlgorithm", "Signing algorithm."),
                    str_prop(
                        "MessageType",
                        "Optional message type: RAW, DIGEST, or EIP191.",
                    ),
                ],
            ),
            obj(
                vec!["KeyId", "Signature", "SigningAlgorithm", "KeyVersion"],
                vec![
                    str_prop("KeyId", "Key id."),
                    str_prop("Signature", "Base64 signature."),
                    str_prop("SigningAlgorithm", "Signing algorithm."),
                    int_prop("KeyVersion", "Key version used for signing."),
                ],
            ),
        ),
        tool(
            "kms_encapsulate",
            "Create a key-agreement encapsulation for a KMS key.",
            obj(vec!["KeyId"], vec![str_prop("KeyId", "Key id or alias.")]),
            obj(
                vec!["KeyId", "Ciphertext", "SharedKey", "KeyAgreementAlgorithm"],
                vec![
                    str_prop("KeyId", "Key id."),
                    str_prop("Ciphertext", "Base64 encapsulation ciphertext."),
                    str_prop("SharedKey", "Base64 shared key."),
                    str_prop("KeyAgreementAlgorithm", "Key agreement algorithm."),
                ],
            ),
        ),
        tool(
            "kms_decapsulate",
            "Decapsulate a key-agreement ciphertext. Shared key output is sensitive and must not be logged.",
            obj(
                vec!["KeyId", "Ciphertext"],
                vec![
                    str_prop("KeyId", "Key id or alias."),
                    str_prop("Ciphertext", "Base64 ciphertext."),
                ],
            ),
            obj(
                vec!["KeyId", "KeyAgreementAlgorithm", "SharedKey"],
                vec![
                    str_prop("KeyId", "Key id."),
                    str_prop("KeyAgreementAlgorithm", "Key agreement algorithm."),
                    str_prop("SharedKey", "Base64 shared key."),
                ],
            ),
        ),
        tool(
            "kms_generate_data_key",
            "Generate a data key. Plaintext output is sensitive and must not be logged.",
            obj(
                vec!["KeyId"],
                vec![
                    str_prop("KeyId", "Key id or alias."),
                    str_prop("DataKeySpec", "Optional data key spec: AES_128 or AES_256."),
                    int_prop(
                        "NumberOfBytes",
                        "Optional byte length. Provide exactly one of DataKeySpec or NumberOfBytes.",
                    ),
                ],
            ),
            obj(
                vec!["KeyId", "Plaintext", "CiphertextBlob"],
                vec![
                    str_prop("KeyId", "Key id."),
                    str_prop("Plaintext", "Base64 plaintext data key."),
                    str_prop("CiphertextBlob", "Encrypted data key blob."),
                ],
            ),
        ),
        tool(
            "kms_rotate_key",
            "Rotate a tenant-scoped KMS key.",
            obj(vec!["KeyId"], vec![str_prop("KeyId", "Key id or alias.")]),
            output_key_metadata(),
        ),
        tool(
            "kms_keystore_put",
            "Store an opaque JSON secret object in the tenant key-store. Secret arguments are sensitive and must not be logged.",
            obj(
                vec!["Name", "Secret"],
                vec![
                    str_prop("Name", "Slash-separated key-store entry name."),
                    json!({"name": "Secret", "schema": {"type": "object", "additionalProperties": true, "description": "Opaque JSON object stored without numeric precision loss."}}),
                ],
            ),
            obj(
                vec!["Name", "Version"],
                vec![
                    str_prop("Name", "Key-store entry name."),
                    int_prop("Version", "Stored key-store version."),
                ],
            ),
        ),
        tool(
            "kms_keystore_get",
            "Retrieve an opaque JSON secret object from the tenant key-store. Secret output is sensitive and must not be logged.",
            obj(
                vec!["Name"],
                vec![str_prop("Name", "Slash-separated key-store entry name.")],
            ),
            obj(
                vec!["Name", "Secret"],
                vec![
                    str_prop("Name", "Key-store entry name."),
                    json!({"name": "Secret", "schema": {"type": "object", "additionalProperties": true, "description": "Opaque JSON secret object."}}),
                ],
            ),
        ),
        tool(
            "kms_keystore_list",
            "List immediate key-store entries and folders under an optional prefix.",
            obj(
                vec![],
                vec![str_prop("Prefix", "Optional key-store prefix.")],
            ),
            obj(
                vec!["Names"],
                vec![
                    json!({"name": "Names", "schema": {"type": "array", "items": {"type": "string"}, "description": "Key-store entry and folder names."}}),
                ],
            ),
        ),
        tool(
            "kms_keystore_delete",
            "Delete a key-store entry from the tenant namespace.",
            obj(
                vec!["Name"],
                vec![str_prop("Name", "Slash-separated key-store entry name.")],
            ),
            obj(
                vec!["Name"],
                vec![str_prop("Name", "Deleted key-store entry name.")],
            ),
        ),
    ]
}

fn tool(
    name: &'static str,
    description: &'static str,
    input_schema: Value,
    output_schema: Value,
) -> ToolDefinition {
    ToolDefinition {
        name,
        description,
        input_schema,
        output_schema,
    }
}

fn obj(required: Vec<&'static str>, props: Vec<Value>) -> Value {
    let mut properties = Map::new();
    for prop in props {
        if let Some(name) = prop.get("name").and_then(Value::as_str)
            && let Some(schema) = prop.get("schema")
        {
            properties.insert(name.to_string(), schema.clone());
        }
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}

fn str_prop(name: &'static str, description: &'static str) -> Value {
    json!({"name": name, "schema": {"type": "string", "description": description}})
}

fn int_prop(name: &'static str, description: &'static str) -> Value {
    json!({"name": name, "schema": {"type": "integer", "description": description, "minimum": 1}})
}

fn tags_prop() -> Value {
    json!({
        "name": "Tags",
        "schema": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "TagKey": {"type": "string"},
                    "TagValue": {"type": "string"}
                },
                "required": ["TagKey"]
            }
        }
    })
}

fn output_key_metadata() -> Value {
    obj(
        vec!["KeyMetadata"],
        vec![json!({
            "name": "KeyMetadata",
            "schema": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "KeyId",
                    "Description",
                    "KeySpec",
                    "KeyUsage",
                    "Enabled",
                    "PrimaryVersion",
                    "CreationDate",
                    "Tags",
                    "Scheme",
                    "Alias"
                ],
                "properties": {
                    "KeyId": {"type": "string"},
                    "Description": {"type": "string"},
                    "KeySpec": {"type": "string"},
                    "KeyUsage": {"type": "string"},
                    "Enabled": {"type": "boolean"},
                    "PrimaryVersion": {"type": "integer", "minimum": 0},
                    "CreationDate": {"type": "string"},
                    "Tags": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "TagKey": {"type": "string"},
                                "TagValue": {"type": "string"}
                            },
                            "required": ["TagKey"]
                        }
                    },
                    "Scheme": {"type": "string"},
                    "PublicKey": {"type": "string"},
                    "Address": {"type": "string"},
                    "Alias": {"type": "string"}
                }
            }
        })],
    )
}

fn output_capabilities() -> Value {
    obj(
        vec!["Schemes"],
        vec![json!({
            "name": "Schemes",
            "schema": {
                "type": "array",
                "description": "Supported KMS schemes and operation capabilities.",
                "items": {
                    "type": "object",
                    "additionalProperties": true,
                    "required": ["Scheme", "KeySpecs", "KeyUsages"],
                    "properties": {
                        "Scheme": {"type": "string"},
                        "KeySpecs": {"type": "array", "items": {"type": "string"}},
                        "KeyUsages": {"type": "array", "items": {"type": "string"}},
                        "EncryptionAlgorithms": {"type": "array", "items": {"type": "string"}},
                        "DataKeySpecs": {"type": "array", "items": {"type": "string"}},
                        "SigningCapabilities": {"type": "array", "items": {"type": "object", "additionalProperties": true}},
                        "SupportsEncrypt": {"type": "boolean"},
                        "SupportsDecrypt": {"type": "boolean"},
                        "SupportsGenerateDataKey": {"type": "boolean"},
                        "SupportsRotateKey": {"type": "boolean"},
                        "KeyAgreementCapabilities": {"type": "array", "items": {"type": "object", "additionalProperties": true}},
                        "SupportsEncapsulate": {"type": "boolean"},
                        "SupportsDecapsulate": {"type": "boolean"},
                        "Tags": {"type": "array", "items": {"type": "string"}}
                    }
                }
            }
        })],
    )
}

fn tool_success(raw_result: Box<RawValue>) -> ToolCallResult {
    ToolCallResult {
        result_type: "complete",
        content: vec![TextContent {
            content_type: "text",
            text: raw_result.get().to_string(),
        }],
        structured_content: Some(raw_result),
        is_error: false,
    }
}

fn tool_error(message: impl Into<String>) -> ToolCallResult {
    ToolCallResult {
        result_type: "complete",
        content: vec![TextContent {
            content_type: "text",
            text: message.into(),
        }],
        structured_content: None,
        is_error: true,
    }
}

fn raw_json<T: Serialize>(value: T) -> Result<Box<RawValue>, tonic::Status> {
    serde_json::value::to_raw_value(&value)
        .map_err(|e| tonic::Status::internal(format!("Failed to serialize MCP result: {e}")))
}

fn sanitized_status_message(status: &tonic::Status) -> &'static str {
    match status.code() {
        tonic::Code::NotFound => "KMS resource not found",
        tonic::Code::InvalidArgument => "invalid KMS request",
        tonic::Code::PermissionDenied => "permission denied",
        tonic::Code::Unauthenticated => "authentication failed",
        tonic::Code::Unavailable => "KMS backend unavailable",
        tonic::Code::DeadlineExceeded => "KMS request timed out",
        _ => "KMS backend error",
    }
}

fn json_result<T: Serialize>(id: Value, result: T) -> Response {
    let response = JsonRpcResponse {
        jsonrpc: "2.0",
        result: Some(result),
        error: None,
        id,
    };
    json_status(StatusCode::OK, &response)
}

fn protocol_error(
    id: Value,
    status: StatusCode,
    code: i32,
    message: impl Into<String>,
) -> Response {
    let response = JsonRpcResponse::<()> {
        jsonrpc: "2.0",
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
        }),
        id,
    };
    json_status(status, &response)
}

fn json_status<T: Serialize>(status: StatusCode, body: &T) -> Response {
    warp::reply::with_status(warp::reply::json(body), status).into_response()
}

fn add_authenticate_header(response: &mut Response, config: &McpConfig) {
    let value = format!(
        "Bearer resource_metadata=\"{}\"",
        config.metadata_url().replace('"', "")
    );
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn request_id(request: &McpRequest) -> Value {
    request.id.clone().unwrap_or(Value::Null)
}

fn request_id_u64(id: &Value) -> u64 {
    id.as_u64()
        .unwrap_or_else(|| rand::random::<u64>().saturating_add(1))
}

fn normalize_resource_url(value: String, http_port: u16) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return format!("http://localhost:{http_port}/mcp");
    }
    trimmed.trim_end_matches('/').to_string()
}

fn split_csv(value: String) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::threshold::ThresholdGroupRegistry;
    use std::time::Duration;
    use warp::http::StatusCode;

    fn raw(value: &str) -> Box<RawValue> {
        RawValue::from_string(value.to_string()).unwrap()
    }

    fn test_routes(config: McpConfig) -> BoxedFilter<(Response,)> {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let auth_client = AuthPluginClient::new(channel);
        let plugin_catalog = Arc::new(PluginCatalog::new(
            "http://127.0.0.1:1",
            None,
            "http://127.0.0.1:1",
            None,
            None,
            false,
            "",
            ThresholdGroupRegistry::default(),
        ));
        routes(
            auth_client,
            Arc::new(RateLimiter::new(10, Duration::from_secs(10))),
            plugin_catalog,
            None,
            4096,
            Arc::new(config),
        )
    }

    #[test]
    fn tool_list_contains_all_kms_tools() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools.iter().map(|tool| tool.name).collect();
        assert_eq!(names.len(), 15);
        assert!(names.contains(&"kms_keystore_put"));
        assert!(names.contains(&"kms_sign"));
        assert!(names.contains(&"kms_get_capabilities"));
        assert!(
            tools
                .iter()
                .all(|tool| tool.output_schema["type"] == "object")
        );
    }

    #[test]
    fn keystore_put_arguments_preserve_precise_json_secret() {
        let args = raw(
            r#"{"Name":"github/prod","Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}}"#,
        );
        let call = tool_to_kms_call("kms_keystore_put", Some(&args)).unwrap();
        match call {
            McpKmsCall::Kms(KmsRpcCall::KeyStorePut(req)) => {
                assert_eq!(req.name, "github/prod");
                assert_eq!(
                    req.secret.as_json_str(),
                    r#"{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}"#
                );
            }
            _ => panic!("expected key-store put"),
        }
    }

    #[test]
    fn tool_success_serialization_preserves_precise_structured_content() {
        let raw_result = raw(
            r#"{"Name":"github/prod","Secret":{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}}"#,
        );
        let response = JsonRpcResponse {
            jsonrpc: "2.0",
            result: Some(tool_success(raw_result)),
            error: None,
            id: json!(1),
        };

        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains(r#""resultType":"complete""#));
        assert!(encoded.contains("123456789012345678901234567890"));
        assert!(encoded.contains("3.14159265358979323846"));
    }

    #[test]
    fn tool_arguments_reject_identity_fields() {
        let args = raw(r#"{"KeyId":"kms:abc","ClientId":"attacker"}"#);
        let err = tool_to_kms_call("kms_rotate_key", Some(&args)).unwrap_err();
        assert!(err.contains("ClientId"));
    }

    #[test]
    fn modern_header_validation_requires_matching_meta() {
        let params = raw(r#"{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}"#);
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: Some(params),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(MCP_PROTOCOL_VERSION),
        );
        headers.insert("mcp-method", HeaderValue::from_static("initialize"));

        let err = validate_mcp_headers(&headers, &request).unwrap_err();
        assert!(err.message.contains("mismatch"));
    }

    #[test]
    fn metadata_url_uses_mcp_specific_well_known_path() {
        let config = McpConfig::new(
            "https://api.orbitport.com/mcp",
            "https://auth.orbitport.com",
            "",
            8080,
        );
        assert_eq!(
            config.metadata_url(),
            "https://api.orbitport.com/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn missing_protocol_header_is_legacy_compatible() {
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/list".to_string(),
            params: None,
        };
        let headers = HeaderMap::new();
        validate_mcp_headers(&headers, &request).unwrap();
    }

    #[tokio::test]
    async fn missing_bearer_returns_mcp_www_authenticate_header() {
        let route = test_routes(McpConfig::new(
            "https://api.orbitport.com/mcp",
            "https://auth.orbitport.com",
            "",
            8080,
        ));

        let resp = warp::test::request()
            .method("POST")
            .path("/mcp")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .reply(&route)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let challenge = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(challenge.contains("oauth-protected-resource/mcp"));
    }

    #[tokio::test]
    async fn origin_header_is_rejected_when_not_allowlisted() {
        let route = test_routes(McpConfig::new(
            "https://api.orbitport.com/mcp",
            "https://auth.orbitport.com",
            "https://trusted.example",
            8080,
        ));

        let resp = warp::test::request()
            .method("POST")
            .path("/mcp")
            .header("Origin", "https://evil.example")
            .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
            .reply(&route)
            .await;

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn protected_resource_metadata_is_public() {
        let route = test_routes(McpConfig::new(
            "https://api.orbitport.com/mcp",
            "https://auth.orbitport.com",
            "",
            8080,
        ));

        let resp = warp::test::request()
            .method("GET")
            .path("/.well-known/oauth-protected-resource/mcp")
            .reply(&route)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["resource"], "https://api.orbitport.com/mcp");
        assert_eq!(
            body["authorization_servers"][0],
            "https://auth.orbitport.com"
        );
    }
}
