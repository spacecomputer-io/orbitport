//! Route-level tests for the internal PAT issuance endpoint, driving HTTP
//! requests through `internal_routes` against in-process auth and issuer
//! plugins to assert the Auth0 M2M authorization boundary.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use warp::http::StatusCode;

use gateway::proto::plugins::auth::{
    ServiceTokenValidationRequest, ServiceTokenValidationResponse, TokenValidationRequest,
    TokenValidationResponse,
    auth_plugin_client::AuthPluginClient,
    auth_plugin_server::{AuthPlugin, AuthPluginServer},
};
use gateway::proto::plugins::patissuer::{
    GetJwksRequest, GetJwksResponse, IssueTokenRequest, IssueTokenResponse,
    pat_issuer_plugin_client::PatIssuerPluginClient,
    pat_issuer_plugin_server::{PatIssuerPlugin, PatIssuerPluginServer},
};
use gateway::server::internal_routes;

#[derive(Default)]
struct MockPatIssuerPlugin {
    issue_calls: Arc<AtomicU32>,
}

#[derive(Default)]
struct MockAuthPlugin {
    service_calls: Arc<AtomicU32>,
}

#[tonic::async_trait]
impl AuthPlugin for MockAuthPlugin {
    async fn validate_token(
        &self,
        _req: Request<TokenValidationRequest>,
    ) -> Result<Response<TokenValidationResponse>, Status> {
        Err(Status::unimplemented("not used by internal PAT issuance"))
    }

    async fn validate_service_token(
        &self,
        req: Request<ServiceTokenValidationRequest>,
    ) -> Result<Response<ServiceTokenValidationResponse>, Status> {
        self.service_calls.fetch_add(1, Ordering::SeqCst);
        let req = req.into_inner();
        assert_eq!(req.required_scopes, ["pat:issue"]);

        match req.token.as_str() {
            "authorized-service-token" => Ok(Response::new(ServiceTokenValidationResponse {
                ok: true,
                client_id: "dashboard-service".to_string(),
            })),
            "missing-scope-service-token" => {
                Err(Status::permission_denied("service token is not authorized"))
            }
            "unsupported-service-token" => {
                Err(Status::unimplemented("ValidateServiceToken is unsupported"))
            }
            "unavailable-service-token" => Err(Status::unavailable("auth plugin is down")),
            "empty-client-service-token" => Ok(Response::new(ServiceTokenValidationResponse {
                ok: true,
                client_id: String::new(),
            })),
            _ => Err(Status::unauthenticated("invalid service token")),
        }
    }
}

#[tonic::async_trait]
impl PatIssuerPlugin for MockPatIssuerPlugin {
    async fn issue_token(
        &self,
        req: Request<IssueTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        self.issue_calls.fetch_add(1, Ordering::SeqCst);
        let req = req.into_inner();
        if req.jti == "jti-issuer-error" {
            return Err(Status::internal("signing key unavailable"));
        }
        assert_eq!(req.jti, "jti-1");
        assert_eq!(req.subject, "acct-1");
        Ok(Response::new(IssueTokenResponse {
            ok: true,
            token: "header.payload.signature".to_string(),
            error: String::new(),
        }))
    }

    async fn get_jwks(
        &self,
        _req: Request<GetJwksRequest>,
    ) -> Result<Response<GetJwksResponse>, Status> {
        Ok(Response::new(GetJwksResponse {
            jwks_json: r#"{"keys":[]}"#.to_string(),
        }))
    }
}

async fn start_mock_issuer() -> (SocketAddr, Arc<AtomicU32>) {
    let issue_calls = Arc::new(AtomicU32::new(0));
    let plugin = MockPatIssuerPlugin {
        issue_calls: issue_calls.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(PatIssuerPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });

    // Best-effort: give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, issue_calls)
}

async fn connect(addr: SocketAddr) -> PatIssuerPluginClient<Channel> {
    PatIssuerPluginClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

async fn start_mock_auth() -> (SocketAddr, Arc<AtomicU32>) {
    let service_calls = Arc::new(AtomicU32::new(0));
    let plugin = MockAuthPlugin {
        service_calls: service_calls.clone(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, service_calls)
}

async fn connect_auth(addr: SocketAddr) -> AuthPluginClient<Channel> {
    AuthPluginClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

fn issue_body() -> serde_json::Value {
    serde_json::json!({
        "jti": "jti-1",
        "subject": "acct-1",
        "kmsTenant": "tenant-1",
        "expiresAt": 4102444800i64,
    })
}

#[tokio::test]
async fn issue_route_rejects_missing_or_invalid_service_token() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, service_calls) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(service_calls.load(Ordering::SeqCst), 0);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer invalid-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
    assert_eq!(service_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn issue_route_rejects_service_token_without_required_scope() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer missing-scope-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_reports_an_incompatible_auth_plugin_as_unavailable() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer unsupported-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

/// The internal listener carries PAT issuance and nothing else, so a mistake
/// binding it cannot expose the public API on an unguarded port.
#[tokio::test]
async fn internal_listener_serves_nothing_else() {
    let (addr, _) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let routes = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    for path in [
        "/healthz",
        "/api/v1/services/trng",
        "/.well-known/jwks.json",
    ] {
        let resp = warp::test::request()
            .method("GET")
            .path(path)
            .reply(&routes)
            .await;
        assert!(
            matches!(
                resp.status(),
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{path} must not be served, got {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn issue_route_reports_an_unavailable_auth_plugin_as_unavailable() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer unavailable-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_rejects_validated_token_with_blank_client_id() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, service_calls) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer empty-client-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(service_calls.load(Ordering::SeqCst), 1);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_rejects_oversized_body_without_calling_the_issuer() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    // Over the route's 4096-byte content-length ceiling.
    let mut body = issue_body();
    body["subject"] = serde_json::Value::String("a".repeat(5000));

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .json(&body)
        .reply(&route)
        .await;

    assert!(
        resp.status().is_client_error() || resp.status().is_server_error(),
        "oversized body must be rejected, got {}",
        resp.status()
    );
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_rejects_non_json_body() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .body("this is not json")
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_rejects_body_missing_required_fields() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    // No subject or expiresAt.
    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .json(&serde_json::json!({"jti": "jti-1"}))
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_rejects_get_method() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, service_calls) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("GET")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(service_calls.load(Ordering::SeqCst), 0);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_surfaces_issuer_failure_without_a_token() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, _) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let mut body = issue_body();
    body["jti"] = serde_json::Value::String("jti-issuer-error".to_string());

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .json(&body)
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let resp_body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(resp_body["error"], "patissuer_plugin_unavailable");
    assert!(resp_body.get("token").is_none());
    assert_eq!(issue_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn issue_route_accepts_authorized_service_token() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let (auth_addr, service_calls) = start_mock_auth().await;
    let route = internal_routes(connect(addr).await, connect_auth(auth_addr).await);

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer authorized-service-token")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(body["token"], "header.payload.signature");
    assert_eq!(issue_calls.load(Ordering::SeqCst), 1);
    assert_eq!(service_calls.load(Ordering::SeqCst), 1);
}
