//! Route-level tests for the internal PAT issuance endpoint.
//!
//! Spins up an in-process tonic server that impersonates the issuer plugin
//! (mirroring `account_plugin_grpc.rs`) and drives HTTP requests through the
//! same `pat_issue_route` filter the gateway mounts, asserting the
//! shared-secret guard: wrong secret → 401 (issuer never called), correct
//! secret → 200 with the minted token.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use warp::http::StatusCode;

use gateway::proto::plugins::issuer::{
    GetJwksRequest, GetJwksResponse, IssueTokenRequest, IssueTokenResponse,
    issuer_plugin_client::IssuerPluginClient,
    issuer_plugin_server::{IssuerPlugin, IssuerPluginServer},
};
use gateway::server::pat_issue_route;

#[derive(Default)]
struct MockIssuerPlugin {
    issue_calls: Arc<AtomicU32>,
}

#[tonic::async_trait]
impl IssuerPlugin for MockIssuerPlugin {
    async fn issue_token(
        &self,
        req: Request<IssueTokenRequest>,
    ) -> Result<Response<IssueTokenResponse>, Status> {
        self.issue_calls.fetch_add(1, Ordering::SeqCst);
        let req = req.into_inner();
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
    let plugin = MockIssuerPlugin {
        issue_calls: issue_calls.clone(),
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(IssuerPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });

    // Best-effort: give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, issue_calls)
}

async fn connect(addr: SocketAddr) -> IssuerPluginClient<Channel> {
    IssuerPluginClient::connect(format!("http://{addr}"))
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
async fn issue_route_rejects_wrong_secret() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let client = connect(addr).await;
    let route = pat_issue_route(client, "top-secret".to_string());

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer wrong-secret")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);

    // Missing header entirely is also a 401.
    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(issue_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn issue_route_accepts_correct_secret() {
    let (addr, issue_calls) = start_mock_issuer().await;
    let client = connect(addr).await;
    let route = pat_issue_route(client, "top-secret".to_string());

    let resp = warp::test::request()
        .method("POST")
        .path("/internal/pat/issue")
        .header("authorization", "Bearer top-secret")
        .json(&issue_body())
        .reply(&route)
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(resp.body()).unwrap();
    assert_eq!(body["token"], "header.payload.signature");
    assert_eq!(issue_calls.load(Ordering::SeqCst), 1);
}
