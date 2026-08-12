//! Issuer-backed routes: the public JWKS endpoint and the internal PAT
//! issuance endpoint. Both are mounted only when the issuer plugin is
//! configured.

use serde::Deserialize;
use std::sync::Arc;
use tokio::time::{Duration, timeout};
use warp::{Filter, Rejection, http::StatusCode, reply::Response};

use crate::proto::plugins::issuer::{
    GetJwksRequest, IssueTokenRequest, issuer_plugin_client::IssuerPluginClient,
};
use tonic::transport::Channel;

/// PUBLIC `GET /.well-known/jwks.json` — like `health_route`, it bypasses
/// `with_auth`/`with_account_hold`: verifiers must be able to fetch the key
/// set anonymously. Proxies the issuer plugin's GetJwks and serves the raw
/// JWKS JSON with a 5-minute cache hint.
pub fn jwks_route(
    client: IssuerPluginClient<Channel>,
) -> impl Filter<Extract = (Response,), Error = Rejection> + Clone {
    let cache: JwksCache = Arc::new(tokio::sync::Mutex::new(None));
    warp::get()
        .and(warp::path!(".well-known" / "jwks.json"))
        .and(warp::any().map(move || client.clone()))
        .and(warp::any().map(move || cache.clone()))
        .and_then(handle_jwks)
}

/// Last JWKS body served, with the instant it was fetched.
type JwksCache = Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>;

/// Server-side JWKS cache lifetime. This route is public and unauthenticated,
/// so without it every anonymous request fans straight through to the issuer
/// plugin. Strictly tighter than the `max-age=300` we advertise to clients.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(60);
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

fn jwks_reply(jwks: String) -> Response {
    let reply = warp::reply::with_header(jwks, "content-type", "application/json");
    let reply = warp::reply::with_header(reply, "cache-control", "max-age=300");
    warp::reply::Reply::into_response(reply)
}

async fn handle_jwks(
    mut client: IssuerPluginClient<Channel>,
    cache: JwksCache,
) -> Result<Response, Rejection> {
    // Read the cache and drop the lock before any network call, so a hung
    // issuer plugin never serializes readers behind it.
    if let Some((body, fetched_at)) = cache.lock().await.clone()
        && fetched_at.elapsed() < JWKS_CACHE_TTL
    {
        return Ok(jwks_reply(body));
    }

    match timeout(JWKS_FETCH_TIMEOUT, client.get_jwks(GetJwksRequest {})).await {
        Ok(Ok(resp)) => {
            let jwks = resp.into_inner().jwks_json;
            *cache.lock().await = Some((jwks.clone(), std::time::Instant::now()));
            Ok(jwks_reply(jwks))
        }
        Ok(Err(e)) => {
            tracing::error!("Issuer plugin GetJwks failed: {}", e);
            Ok(json_status(
                &serde_json::json!({"error": "issuer_plugin_unavailable"}),
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
        Err(_) => {
            tracing::error!("Issuer plugin GetJwks timed out");
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
        // The only signal a brute-force or a misconfigured dashboard leaves.
        tracing::warn!("Rejected /internal/pat/issue: bad or missing shared secret");
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
