use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::{Duration, Instant, timeout};
use warp::{Filter, Rejection, Reply, http::StatusCode, reject::Reject};

use crate::metrics;
use crate::service_manager::ServiceManager;
use crate::types::{EncryptionKey, GatewayError, ServiceRequest};

use crate::filters::{
    AuthContextWithHold, RateLimiter, account_release, account_settle, with_account_hold,
    with_auth, with_rate_limiter,
};
use crate::plugins::PluginCatalog;
use crate::proto::plugins::account::account_plugin_client::AccountPluginClient;
use crate::proto::plugins::issuer::{
    GetJwksRequest, IssueTokenRequest, issuer_plugin_client::IssuerPluginClient,
};
use crate::services::jrpc::{JsonRpcRequest, JsonRpcResponse};
use crate::trng::SRC_DERIVED_TRNG;
use tonic::transport::Channel;
use warp::filters::BoxedFilter;
use warp::reply::Response;

impl Reject for GatewayError {}

#[derive(Debug, Clone, Deserialize)]
struct QueryParams {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return (EXPERIMENTAL)
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct PostBody {
    /// The source of the service, i.e. the service provider
    src: Option<String>,
    /// The number of derived items to return
    bulk: Option<usize>,
    /// The key for encryption in the format of <scheme>@<key> (EXPERIMENTAL)
    /// This is used to encrypt the service result.
    /// Currently only supports tpk (threshold public key) i.e. "tpk@<key>".
    key: Option<String>,
    /// The arguments for the service
    /// in a vector of [(key, value), ...]
    args: Option<Vec<(String, String)>>,
}

/// Starts the gateway server, returns a future that resolves when the server stops or fails
/// It exposes the following enpoints:
pub async fn start(
    http_port: u16,
    service_manager: Arc<ServiceManager>,
    plugin_catalog: Arc<PluginCatalog>,
    limit: u32,
    limit_window: u64,
    bulk_max: usize,
    issuer_shared_secret: Option<String>,
) {
    let service_manager_clone = service_manager.clone();
    let service_manager_post_clone = service_manager.clone();

    let rate_limiter = Arc::new(RateLimiter::new(limit, Duration::from_secs(limit_window))); // 100 requests per minute

    let account_client: Option<AccountPluginClient<Channel>> =
        plugin_catalog.get_account_client().await.ok();
    let issuer_client: Option<IssuerPluginClient<Channel>> =
        plugin_catalog.get_issuer_client().await.ok();
    let account_client_rpc = account_client.clone();
    let account_client_get = account_client.clone();
    let account_client_post = account_client.clone();

    // MVP: account-plugin `operation` is a coarse HTTP-method tag, not the
    // semantic op (e.g. "trng", "kms_sign"). Path-derived tagging requires
    // pushing the matched path into `with_account_hold`, which the warp
    // filter signature doesn't carry today.
    // TODO(account-plugin): derive semantic operation tag from path.
    let rpc_route = warp::post()
        .and(warp::path("api").and(warp::path("v1").and(warp::path("rpc"))))
        .and(with_account_hold(
            with_rate_limiter(
                with_auth(service_manager.get_auth_client()),
                rate_limiter.clone(),
            ),
            account_client_rpc.clone(),
            1,
            "rpc",
        ))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(warp::any().map(move || plugin_catalog.clone()))
        .and(warp::any().map(move || account_client_rpc.clone()))
        .and_then(handle_rpc);

    let bulk_max_get = bulk_max;
    let get_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::get())
        .and(with_account_hold(
            with_rate_limiter(
                with_auth(service_manager.get_auth_client()),
                rate_limiter.clone(),
            ),
            account_client_get.clone(),
            1,
            "service_get",
        ))
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_clone.clone()))
        .and(warp::any().map(move || bulk_max_get))
        .and(warp::any().map(move || account_client_get.clone()))
        .and_then(handle_get);

    let bulk_max_post = bulk_max;
    let post_route = warp::path!("api" / "v1" / "services" / String)
        .and(warp::post())
        .and(with_account_hold(
            with_rate_limiter(
                with_auth(service_manager.get_auth_client()),
                rate_limiter.clone(),
            ),
            account_client_post.clone(),
            1,
            "service_post",
        ))
        .and(warp::body::content_length_limit(1024)) // limit to 1 KB payload
        .and(warp::body::json())
        .and(warp::query::<QueryParams>())
        .and(warp::any().map(move || service_manager_post_clone.clone()))
        .and(warp::any().map(move || bulk_max_post))
        .and(warp::any().map(move || account_client_post.clone()))
        .and_then(handle_post);

    // Allowlist: `/healthz` is the only route that bypasses `with_account_hold`.
    // It runs without auth or rate-limiting so probes from k8s / load balancers
    // never spend credits. There is no `/version` route today.
    let health_route = warp::path("healthz").map(|| {
        warp::reply::json(&serde_json::json!({
            "status": "ok"
        }))
    });

    let mut routes: BoxedFilter<(Response,)> = get_route
        .or(post_route)
        .or(rpc_route)
        .or(health_route.with(warp::log("health_check")))
        .map(warp::reply::Reply::into_response)
        .boxed();

    // Issuer-backed routes are mounted only when the issuer plugin is
    // configured and reachable at startup (same pattern as account_client).
    if let Some(client) = issuer_client {
        routes = routes.or(jwks_route(client.clone())).unify().boxed();

        match issuer_shared_secret.as_deref() {
            Some(secret) if !secret.is_empty() => {
                routes = routes
                    .or(pat_issue_route(client, secret.to_string()))
                    .unify()
                    .boxed();
            }
            _ => {
                tracing::warn!(
                    "ORBITPORT_ISSUER_PLUGIN is set but ORBITPORT_ISSUER_SHARED_SECRET is unset or empty; refusing to mount POST /internal/pat/issue"
                );
            }
        }
    }

    let routes = routes.recover(handle_rejection);

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    warp::serve(routes).run(([0, 0, 0, 0], http_port)).await;
}

/// PUBLIC `GET /.well-known/jwks.json` — like `health_route`, it bypasses
/// `with_auth`/`with_account_hold`: verifiers must be able to fetch the key
/// set anonymously. Proxies the issuer plugin's GetJwks and serves the raw
/// JWKS JSON with a 5-minute cache hint.
pub fn jwks_route(
    client: IssuerPluginClient<Channel>,
) -> impl Filter<Extract = (Response,), Error = Rejection> + Clone {
    warp::get()
        .and(warp::path!(".well-known" / "jwks.json"))
        .and(warp::any().map(move || client.clone()))
        .and_then(handle_jwks)
}

async fn handle_jwks(mut client: IssuerPluginClient<Channel>) -> Result<Response, Rejection> {
    match client.get_jwks(GetJwksRequest {}).await {
        Ok(resp) => {
            let jwks = resp.into_inner().jwks_json;
            let reply = warp::reply::with_header(jwks, "content-type", "application/json");
            let reply = warp::reply::with_header(reply, "cache-control", "max-age=300");
            Ok(warp::reply::Reply::into_response(reply))
        }
        Err(e) => {
            tracing::error!("Issuer plugin GetJwks failed: {}", e);
            Ok(json_status(
                &serde_json::json!({"error": "issuer_plugin_unavailable"}),
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatIssueBody {
    jti: String,
    subject: String,
    #[serde(default)]
    kms_tenant: Option<String>,
    expires_at: i64,
}

/// INTERNAL `POST /internal/pat/issue` — deliberately NOT wrapped in
/// `with_auth`/`with_account_hold`: the caller is the dashboard backend, not
/// an end user. Guarded by a constant-time shared-secret bearer check.
pub fn pat_issue_route(
    client: IssuerPluginClient<Channel>,
    shared_secret: String,
) -> impl Filter<Extract = (Response,), Error = Rejection> + Clone {
    warp::post()
        .and(warp::path!("internal" / "pat" / "issue"))
        .and(warp::header::optional::<String>("authorization"))
        .and(warp::body::content_length_limit(4096))
        .and(warp::body::json())
        .and(warp::any().map(move || client.clone()))
        .and(warp::any().map(move || shared_secret.clone()))
        .and_then(handle_pat_issue)
}

async fn handle_pat_issue(
    auth_header: Option<String>,
    body: PatIssueBody,
    mut client: IssuerPluginClient<Channel>,
    shared_secret: String,
) -> Result<Response, Rejection> {
    let expected = format!("Bearer {shared_secret}");
    let authorized = auth_header
        .as_deref()
        .is_some_and(|header| constant_time_eq(header, &expected));
    if !authorized {
        return Ok(json_status(
            &serde_json::json!({"error": "unauthorized"}),
            StatusCode::UNAUTHORIZED,
        ));
    }

    let request = tonic::Request::new(IssueTokenRequest {
        jti: body.jti,
        subject: body.subject,
        kms_tenant: body.kms_tenant.unwrap_or_default(),
        expires_at: body.expires_at,
    });
    match client.issue_token(request).await {
        Ok(resp) => Ok(json_status(
            &serde_json::json!({"token": resp.into_inner().token}),
            StatusCode::OK,
        )),
        Err(e) if e.code() == tonic::Code::InvalidArgument => Ok(json_status(
            &serde_json::json!({"error": e.message()}),
            StatusCode::BAD_REQUEST,
        )),
        Err(e) => {
            tracing::error!("Issuer plugin IssueToken failed: {}", e);
            Ok(json_status(
                &serde_json::json!({"error": "issuer_plugin_unavailable"}),
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

fn json_status(body: &serde_json::Value, status: StatusCode) -> Response {
    warp::reply::Reply::into_response(warp::reply::with_status(warp::reply::json(body), status))
}

/// Constant-time string equality via SHA-256 digests: hashing first makes
/// the comparison length-independent, and the digest fold never
/// short-circuits.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Maps gateway-specific custom rejections to HTTP responses. Without this,
/// warp would default to 500 for every custom rejection.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(gw) = err.find::<GatewayError>() {
        let (status, body) = match gw {
            GatewayError::InsufficientCredits => (
                StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({"error": "insufficient_credits"}),
            ),
            GatewayError::AccountPluginUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "account_plugin_unavailable", "detail": msg}),
            ),
            GatewayError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({"error": "rate_limit_exceeded"}),
            ),
            GatewayError::NoAuthHeaderError | GatewayError::InvalidAuthHeaderError => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": gw.to_string()}),
            ),
            GatewayError::AuthenticationFailed => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "authentication_failed"}),
            ),
            GatewayError::PatExpired => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "token_expired",
                    "message": "Personal access token expired — create a new one in the dashboard"
                }),
            ),
            GatewayError::InvalidCredential => (
                StatusCode::UNAUTHORIZED,
                serde_json::json!({
                    "error": "invalid_credential",
                    "message": "Unknown or revoked credential"
                }),
            ),
            GatewayError::AuthPluginConnectionError(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"error": "auth_plugin_unavailable"}),
            ),
            GatewayError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, serde_json::json!({"error": msg}))
            }
            GatewayError::ServiceTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                serde_json::json!({"error": "service_timeout"}),
            ),
            GatewayError::ServiceNotFoundError(name) => (
                StatusCode::NOT_FOUND,
                serde_json::json!({"error": "service_not_found", "service": name}),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"error": gw.to_string()}),
            ),
        };
        return Ok(warp::reply::with_status(warp::reply::json(&body), status));
    }
    if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        return Ok(warp::reply::with_status(
            warp::reply::json(
                &serde_json::json!({"error": format!("Request body deserialize error: {e}")}),
            ),
            StatusCode::BAD_REQUEST,
        ));
    }
    if err.is_not_found() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "not_found"})),
            StatusCode::NOT_FOUND,
        ));
    }
    if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": "method_not_allowed"})),
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }
    tracing::error!("unhandled rejection: {err:?}");
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"error": "internal_error"})),
        StatusCode::INTERNAL_SERVER_ERROR,
    ))
}

async fn handle_rpc(
    ctx: AuthContextWithHold,
    body: JsonRpcRequest,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Handling RPC request [id={}] {:?}", body.id, body);
    let req_id = body.id;
    let rpc_call = body.call;
    let ledger_id = ctx.ledger_id.clone();
    if let Err(e) = rpc_call.validate() {
        tracing::error!("RPC validation error [id={}]: {}", req_id, e);
        account_release(account_client.clone(), &ledger_id).await;
        let res: JsonRpcResponse<()> =
            JsonRpcResponse::error(req_id, -32602, format!("Invalid request: {e}"));
        return Ok(warp::reply::json(&res));
    }
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    // D9: KMS tenancy comes from the verified kms_tenant (PATs carry it as a
    // claim, legacy Auth0 tokens echo their raw sub). Empty — auth plugin
    // predating the field or a pre-backfill PAT — falls back to client_id,
    // the exact value this path forwarded before.
    let client_id = if ctx.auth.kms_tenant.is_empty() {
        ctx.auth.client_id
    } else {
        ctx.auth.kms_tenant
    };

    match timeout(
        REQUEST_TIMEOUT,
        rpc_call.execute(req_id, &client_id, &plugin_catalog),
    )
    .await
    {
        Ok(Ok(result)) => {
            tracing::debug!("RPC executed successfully [id={}]", req_id);
            tokio::spawn(async move {
                account_settle(account_client, &ledger_id).await;
            });
            Ok(warp::reply::json(&result))
        }
        Ok(Err(e)) => {
            tracing::warn!("RPC execution error [id={}]: {}", req_id, e);
            account_release(account_client, &ledger_id).await;

            let res: JsonRpcResponse<()> = JsonRpcResponse::error(req_id, -32001, e.to_string());

            Ok(warp::reply::json(&res))
        }
        Err(_) => {
            tracing::error!("RPC request timed out [id={}]", req_id);
            account_release(account_client, &ledger_id).await;

            let res: JsonRpcResponse<()> =
                JsonRpcResponse::error(req_id, -32002, "Request timed out");

            Ok(warp::reply::json(&res))
        }
    }
}

async fn handle_get(
    service: String,
    ctx: AuthContextWithHold,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let ledger_id = ctx.ledger_id.clone();
    tracing::debug!(
        "[req={}] Handling GET request for service: {}",
        req_id,
        service
    );
    let src = if let Some(s) = query.src {
        vec![s.clone()]
    } else {
        vec![SRC_DERIVED_TRNG.to_string()]
    };
    if let Some(b) = query.bulk {
        if b > bulk_max {
            metrics::record_validation("GET", "bulk_limit_exceeded");
            account_release(account_client.clone(), &ledger_id).await;
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {b} exceeds maximum {bulk_max}"
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let enc_key = match query.key {
        Some(key) => match EncryptionKey::new_from_arg(&key) {
            Ok(k) => Some(k),
            Err(e) => {
                metrics::record_validation("GET", "invalid_encryption_key");
                account_release(account_client.clone(), &ledger_id).await;
                return Err(warp::reject::custom(GatewayError::BadRequest(
                    e.to_string(),
                )));
            }
        },
        None => None,
    };
    let svc_req = ServiceRequest {
        req_id,
        service,
        src,
        bulk: query.bulk,
        enc_key,
        args: None,
    };
    handle_service_req(svc_req, service_manager.clone(), account_client, ledger_id).await
}

async fn handle_post(
    service: String,
    ctx: AuthContextWithHold,
    body: PostBody,
    query: QueryParams,
    service_manager: Arc<ServiceManager>,
    bulk_max: usize,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    let req_id = new_req_id();
    let ledger_id = ctx.ledger_id.clone();
    let src = if let Some(s) = body.src {
        s.clone()
    } else {
        query.src.unwrap_or(SRC_DERIVED_TRNG.to_string()).clone()
    };

    let bulk = if let Some(b) = body.bulk {
        Some(b)
    } else {
        query.bulk
    };
    if let Some(b) = bulk {
        if b > bulk_max {
            metrics::record_validation("POST", "bulk_limit_exceeded");
            account_release(account_client.clone(), &ledger_id).await;
            return Err(warp::reject::custom(GatewayError::BadRequest(format!(
                "Bulk size {b} exceeds maximum {bulk_max}"
            ))));
        } else {
            tracing::debug!("[req={}] Bulk size: {}", req_id, b);
        }
    }
    let key = if let Some(k) = query.key {
        Some(k)
    } else {
        body.key
    };
    let enc_key = match key {
        Some(key) => match EncryptionKey::new_from_arg(&key) {
            Ok(k) => Some(k),
            Err(e) => {
                metrics::record_validation("POST", "invalid_encryption_key");
                account_release(account_client.clone(), &ledger_id).await;
                return Err(warp::reject::custom(GatewayError::BadRequest(
                    e.to_string(),
                )));
            }
        },
        None => None,
    };
    let args = body.args.clone();
    let svc_req = ServiceRequest {
        req_id,
        service,
        src: vec![src],
        bulk,
        enc_key,
        args,
    };
    handle_service_req(svc_req, service_manager.clone(), account_client, ledger_id).await
}

async fn handle_service_req(
    svc_req: ServiceRequest,
    service_manager: Arc<ServiceManager>,
    account_client: Option<AccountPluginClient<Channel>>,
    ledger_id: String,
) -> Result<impl Reply, Rejection> {
    let timer: Instant = Instant::now();

    let req_id = svc_req.req_id;
    let svc_name = svc_req.service.clone();
    metrics::API_REQ_COUNTER
        .with_label_values(&[&svc_name])
        .inc();
    let response = timeout(Duration::from_secs(10), async {
        service_manager.handle(svc_req).await
    })
    .await;

    let duration = timer.elapsed().as_secs_f64();
    metrics::API_REQ_DURATION_SECONDS
        .with_label_values(&[&svc_name])
        .observe(duration);

    match response {
        Ok(Ok(res)) => match res.result {
            Ok(result) => {
                metrics::API_REQ_OK_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "ok", duration);
                tracing::debug!("[req={}] Got service result", req_id);
                let account_client = account_client.clone();
                let ledger_id = ledger_id.clone();
                tokio::spawn(async move {
                    account_settle(account_client, &ledger_id).await;
                });
                Ok(warp::reply::json(&result))
            }
            Err(e) => {
                metrics::API_REQ_ERR_COUNTER
                    .with_label_values(&[&svc_name])
                    .inc();
                metrics::record_request(&svc_name, "service_error", duration);
                tracing::error!("[req={}] Error result: {:?}", req_id, e);
                account_release(account_client.clone(), &ledger_id).await;
                Err(warp::reject::custom(e))
            }
        },
        Ok(Err(e)) => {
            metrics::API_REQ_FAILED_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "routing_error", duration);
            tracing::error!("[req={}] Error routing request: {:?}", req_id, e);
            account_release(account_client.clone(), &ledger_id).await;
            Err(warp::reject::custom(e))
        }
        Err(_) => {
            metrics::API_REQ_TIMEOUT_COUNTER
                .with_label_values(&[&svc_name])
                .inc();
            metrics::record_request(&svc_name, "timeout", duration);
            tracing::error!("[req={}] Request timed out", req_id);
            account_release(account_client.clone(), &ledger_id).await;
            Err(warp::reject::custom(GatewayError::ServiceTimeout))
        }
    }
}

/// Generates a new random request ID.
fn new_req_id() -> u64 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..u64::MAX)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn pat_expired_rejection_maps_to_401_token_expired() {
        let route = warp::any()
            .and_then(|| async {
                Err::<warp::reply::Json, Rejection>(warp::reject::custom(GatewayError::PatExpired))
            })
            .recover(handle_rejection);

        let resp = warp::test::request().reply(&route).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
        assert_eq!(body["error"], "token_expired");
        assert!(body["message"].as_str().unwrap().contains("expired"));
    }
}
