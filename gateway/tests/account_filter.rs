//! Warp-route-level tests for the account-plugin credit-gating filter.
//!
//! These drive HTTP requests through `with_account_hold` and assert the
//! status code + release-call behavior. The auth filter is short-circuited
//! with a synthetic `AuthContext` so we exercise the account-plugin
//! filter wiring in isolation.
//!
//! Coverage:
//! - (a) insufficient credits → 402
//! - (b) plugin unreachable → 503 (fail-closed)
//! - (c) no-op when account client is None (handler runs, no release call)
//! - (d) release fires when the handler errors after a successful hold

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use warp::{Filter, Rejection, Reply, http::StatusCode};

use gateway::filters::{AuthContext, AuthContextWithHold, account_release, with_account_hold};
use gateway::proto::plugins::account::{
    HoldRequest, HoldResponse, ReleaseRequest, ReleaseResponse, SettleRequest, SettleResponse,
    account_plugin_client::AccountPluginClient,
    account_plugin_server::{AccountPlugin, AccountPluginServer},
};
use gateway::types::GatewayError;

#[derive(Clone, Copy, Debug)]
enum HoldBehavior {
    Ok,
    Insufficient,
}

struct MockAccountPlugin {
    hold_calls: Arc<AtomicU32>,
    release_calls: Arc<AtomicU32>,
    behavior: HoldBehavior,
}

#[tonic::async_trait]
impl AccountPlugin for MockAccountPlugin {
    async fn hold(&self, _req: Request<HoldRequest>) -> Result<Response<HoldResponse>, Status> {
        self.hold_calls.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            HoldBehavior::Ok => Ok(Response::new(HoldResponse {
                ok: true,
                ledger_id: "ledger-warp".to_string(),
                balance_after: 99,
                error: String::new(),
            })),
            HoldBehavior::Insufficient => Err(Status::failed_precondition("insufficient_credits")),
        }
    }

    async fn release(
        &self,
        _req: Request<ReleaseRequest>,
    ) -> Result<Response<ReleaseResponse>, Status> {
        self.release_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(ReleaseResponse {
            ok: true,
            balance_after: 100,
            error: String::new(),
        }))
    }

    async fn settle(
        &self,
        _req: Request<SettleRequest>,
    ) -> Result<Response<SettleResponse>, Status> {
        Ok(Response::new(SettleResponse {
            ok: true,
            balance_after: 99,
            error: String::new(),
        }))
    }
}

async fn start_mock_plugin(behavior: HoldBehavior) -> (SocketAddr, Arc<AtomicU32>, Arc<AtomicU32>) {
    let hold_calls = Arc::new(AtomicU32::new(0));
    let release_calls = Arc::new(AtomicU32::new(0));
    let plugin = MockAccountPlugin {
        hold_calls: hold_calls.clone(),
        release_calls: release_calls.clone(),
        behavior,
    };

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(AccountPluginServer::new(plugin))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .ok();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, hold_calls, release_calls)
}

async fn connect(addr: SocketAddr) -> AccountPluginClient<Channel> {
    AccountPluginClient::connect(format!("http://{addr}"))
        .await
        .unwrap()
}

/// Stand-in auth filter that produces a fixed AuthContext, bypassing JWT
/// validation. Lets us exercise `with_account_hold` without standing up the
/// real auth plugin.
fn synthetic_auth() -> impl Filter<Extract = (AuthContext,), Error = Rejection> + Clone {
    warp::any().and_then(|| async {
        Ok::<_, Rejection>(AuthContext {
            jwt: "test-jwt".to_string(),
            client_id: "client-warp".to_string(),
        })
    })
}

async fn ok_handler(_ctx: AuthContextWithHold) -> Result<impl Reply, Rejection> {
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"status": "ok"})),
        StatusCode::OK,
    ))
}

/// Mirrors the production rejection mapping so tests assert the same status
/// codes the gateway returns.
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    if let Some(gw) = err.find::<GatewayError>() {
        let status = match gw {
            GatewayError::InsufficientCredits => StatusCode::PAYMENT_REQUIRED,
            GatewayError::AccountPluginUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({"error": gw.to_string()})),
            status,
        ));
    }
    Ok(warp::reply::with_status(
        warp::reply::json(&serde_json::json!({"error": "not_found"})),
        StatusCode::NOT_FOUND,
    ))
}

#[tokio::test]
async fn filter_insufficient_credits_returns_402() {
    let (addr, hold_calls, release_calls) = start_mock_plugin(HoldBehavior::Insufficient).await;
    let client = connect(addr).await;

    let route = warp::path("test")
        .and(with_account_hold(synthetic_auth(), Some(client), 1, "trng"))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    // No release: the hold failed, so there's no ledger to release.
    assert_eq!(release_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn filter_plugin_unreachable_returns_503() {
    // Lazily-connected channel to an unreachable port — every Hold RPC fails
    // with Unavailable, which the filter maps to GatewayError::AccountPluginUnavailable
    // (fail-closed).
    let channel = tonic::transport::Channel::from_static("http://127.0.0.1:1").connect_lazy();
    let client = AccountPluginClient::new(channel);

    let route = warp::path("test")
        .and(with_account_hold(synthetic_auth(), Some(client), 1, "trng"))
        .and_then(ok_handler)
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn filter_no_client_passes_through_and_does_not_release() {
    // When the account plugin URL is unset, the gateway constructs
    // `with_account_hold(..., None, ...)` and the handler must run normally
    // with an empty ledger_id.
    let route = warp::path("test")
        .and(with_account_hold(synthetic_auth(), None, 1, "trng"))
        .and_then(|ctx: AuthContextWithHold| async move {
            assert!(
                ctx.ledger_id.is_empty(),
                "ledger_id must be empty when client is None"
            );
            assert_eq!(ctx.auth.client_id, "client-warp");
            Ok::<_, Rejection>(warp::reply::with_status(
                warp::reply::json(&serde_json::json!({"status": "ok"})),
                StatusCode::OK,
            ))
        })
        .recover(handle_rejection);

    let resp = warp::test::request().path("/test").reply(&route).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // account_release with no client is a no-op (covered by grpc tests too,
    // but assert here that the End-to-end path doesn't panic).
    account_release(None, "").await;
}

#[tokio::test]
async fn filter_release_fires_when_handler_errors_after_hold() {
    let (addr, hold_calls, release_calls) = start_mock_plugin(HoldBehavior::Ok).await;
    let client = connect(addr).await;
    let release_client = connect(addr).await;

    // Handler that always errors — mirrors what server.rs does on service
    // failure: call account_release with the ledger_id from the hold.
    let release_client_filter = warp::any().map(move || release_client.clone());
    let route = warp::path("test")
        .and(with_account_hold(synthetic_auth(), Some(client), 1, "trng"))
        .and(release_client_filter)
        .and_then(
            |ctx: AuthContextWithHold, rc: AccountPluginClient<Channel>| async move {
                assert_eq!(ctx.ledger_id, "ledger-warp");
                account_release(Some(rc), &ctx.ledger_id).await;
                Err::<warp::reply::Json, Rejection>(warp::reject::custom(
                    GatewayError::ServiceTimeout,
                ))
            },
        )
        .recover(handle_rejection);

    let _ = warp::test::request().path("/test").reply(&route).await;

    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
    assert_eq!(release_calls.load(Ordering::SeqCst), 1);
}
