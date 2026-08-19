//! The internal PAT issuance endpoint. The public key set is published by the
//! jwks plugin, which reads it from the issuer over gRPC.

use serde::Deserialize;
use warp::{Filter, Rejection, http::StatusCode, reply::Response};

use crate::proto::plugins::issuer::{IssueTokenRequest, issuer_plugin_client::IssuerPluginClient};
use tonic::transport::Channel;

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
/// `with_auth`: the caller is the dashboard backend, not an end user.
/// Guarded by a constant-time shared-secret bearer check.
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
/// the comparison length-independent.
fn constant_time_eq(a: &str, b: &str) -> bool {
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
