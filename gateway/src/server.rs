use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use warp::{Filter, Rejection, Reply, http::StatusCode, reject::Reject};

use crate::types::GatewayError;

use crate::auth::pat_issue_route;
use crate::filters::{
    AuthContext, RateLimiter, account_hold, account_release, account_settle, with_auth,
    with_rate_limiter,
};
use crate::plugins::PluginCatalog;
use crate::proto::plugins::account::account_plugin_client::AccountPluginClient;
use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;
use crate::proto::plugins::patissuer::pat_issuer_plugin_client::PatIssuerPluginClient;
use crate::services::jrpc::{JsonRpcRequest, JsonRpcResponse};
use tonic::transport::Channel;
use warp::filters::BoxedFilter;
use warp::reply::Response;

impl Reject for GatewayError {}

/// Starts the gateway server, returns a future that resolves when the server stops or fails
/// It exposes the KMS JSON-RPC API, a health endpoint, and internal PAT issuance.
pub async fn start(
    http_port: u16,
    internal_port: u16,
    auth_client: AuthPluginClient<Channel>,
    plugin_catalog: Arc<PluginCatalog>,
    limit: u32,
    limit_window: u64,
    rpc_body_max_bytes: u64,
) {
    let rate_limiter = Arc::new(RateLimiter::new(limit, Duration::from_secs(limit_window))); // 100 requests per minute

    let account_client: Option<AccountPluginClient<Channel>> =
        plugin_catalog.get_account_client().await.ok();
    let patissuer_client: Option<PatIssuerPluginClient<Channel>> =
        plugin_catalog.get_patissuer_client().await.ok();
    let account_client_rpc = account_client.clone();
    let auth_client_rpc = auth_client.clone();

    // The hold is placed inside handle_rpc: its operation tag comes from the
    // validated body, which a filter ahead of body parsing cannot see.
    let rpc_route = warp::post()
        .and(warp::path("api").and(warp::path("v1").and(warp::path("rpc"))))
        .and(with_rate_limiter(
            with_auth(auth_client_rpc),
            rate_limiter.clone(),
        ))
        .and(warp::body::content_length_limit(rpc_body_max_bytes))
        .and(warp::body::json())
        .and(warp::any().map(move || plugin_catalog.clone()))
        .and(warp::any().map(move || account_client_rpc.clone()))
        .and_then(handle_rpc);

    // Allowlist: `/healthz` is the only public route that skips authentication.
    // It runs without auth or rate-limiting so probes from k8s / load balancers
    // never spend credits. There is no `/version` route today.
    let health_route = warp::path("healthz").map(|| {
        warp::reply::json(&serde_json::json!({
            "status": "ok"
        }))
    });

    let routes: BoxedFilter<(Response,)> = rpc_route
        .or(health_route.with(warp::log("health_check")))
        .map(warp::reply::Reply::into_response)
        .boxed();

    // The public key set is published by the jwks plugin, not here. The
    // gateway routes and meters the API rather than republishing another
    // service's keys.
    let mut internal_task = None;
    if let Some(client) = patissuer_client {
        let internal = internal_routes(client, auth_client);
        tracing::info!("Starting internal http server on: 0.0.0.0:{internal_port}");
        let server = warp::serve(internal)
            .bind(([0, 0, 0, 0], internal_port))
            .await
            .graceful(shutdown_signal());
        internal_task = Some(tokio::spawn(server.run()));
    }

    let routes = routes.recover(handle_rejection);

    tracing::info!("Starting http server on: 0.0.0.0:{}", http_port);

    let server = warp::serve(routes)
        .bind(([0, 0, 0, 0], http_port))
        .await
        .graceful(shutdown_signal());

    server.run().await;

    if let Some(task) = internal_task {
        let _ = task.await;
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        } else {
            std::future::pending().await
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received, draining requests...");
}

/// Everything served on the internal listener. PAT issuance lives here and
/// nowhere else, so no configuration can expose it on the public port.
pub fn internal_routes(
    client: PatIssuerPluginClient<Channel>,
    auth_client: AuthPluginClient<Channel>,
) -> impl Filter<Extract = (impl Reply,), Error = Infallible> + Clone {
    pat_issue_route(client, auth_client).recover(handle_rejection)
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
            GatewayError::ServiceAuthorizationDenied => (
                StatusCode::FORBIDDEN,
                serde_json::json!({"error": "service_authorization_denied"}),
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
    auth: AuthContext,
    body: JsonRpcRequest,
    plugin_catalog: Arc<PluginCatalog>,
    account_client: Option<AccountPluginClient<Channel>>,
) -> Result<impl Reply, Rejection> {
    tracing::debug!("Handling RPC request [id={}] {:?}", body.id, body);
    let req_id = body.id;
    let rpc_call = body.call;
    // Validate before holding, so an invalid request costs nothing and needs
    // no release.
    if let Err(e) = rpc_call.validate() {
        tracing::error!("RPC validation error [id={}]: {}", req_id, e);
        let res: JsonRpcResponse<()> =
            JsonRpcResponse::error(req_id, -32602, format!("Invalid request: {e}"));
        return Ok(warp::reply::json(&res));
    }
    let ctx = account_hold(auth, account_client.clone(), 1, &rpc_call.operation()).await?;
    let ledger_id = ctx.ledger_id.clone();
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
    let client_id = ctx.kms_tenant;

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
