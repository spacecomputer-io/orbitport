//! gRPC-layer smoke tests for the account plugin client wiring, exercising
//! the generated client against an in-process mock. Filter-chain behavior
//! lives in `account_filter.rs`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

use gateway::proto::plugins::account::{
    HoldRequest, HoldResponse, ReleaseRequest, ReleaseResponse, SettleRequest, SettleResponse,
    account_plugin_client::AccountPluginClient,
    account_plugin_server::{AccountPlugin, AccountPluginServer},
};

#[derive(Default)]
struct MockAccountPlugin {
    hold_calls: Arc<AtomicU32>,
    release_calls: Arc<AtomicU32>,
    settle_calls: Arc<AtomicU32>,
    behavior: HoldBehavior,
}

#[derive(Clone, Copy, Debug, Default)]
enum HoldBehavior {
    #[default]
    Ok,
    Insufficient,
    Unavailable,
}

#[tonic::async_trait]
impl AccountPlugin for MockAccountPlugin {
    async fn hold(&self, _req: Request<HoldRequest>) -> Result<Response<HoldResponse>, Status> {
        self.hold_calls.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            HoldBehavior::Ok => Ok(Response::new(HoldResponse {
                ok: true,
                ledger_id: "ledger-1".to_string(),
                balance_after: 42,
                error: String::new(),
                kms_tenant: "tenant-1".to_string(),
            })),
            HoldBehavior::Insufficient => Err(Status::failed_precondition("insufficient_credits")),
            HoldBehavior::Unavailable => Err(Status::unavailable("dashboard down")),
        }
    }

    async fn release(
        &self,
        _req: Request<ReleaseRequest>,
    ) -> Result<Response<ReleaseResponse>, Status> {
        self.release_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(ReleaseResponse {
            ok: true,
            balance_after: 43,
            error: String::new(),
        }))
    }

    async fn settle(
        &self,
        _req: Request<SettleRequest>,
    ) -> Result<Response<SettleResponse>, Status> {
        self.settle_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(SettleResponse {
            ok: true,
            balance_after: 42,
            error: String::new(),
        }))
    }
}

async fn start_mock_plugin(
    behavior: HoldBehavior,
) -> (SocketAddr, Arc<AtomicU32>, Arc<AtomicU32>, Arc<AtomicU32>) {
    let hold_calls = Arc::new(AtomicU32::new(0));
    let release_calls = Arc::new(AtomicU32::new(0));
    let settle_calls = Arc::new(AtomicU32::new(0));
    let plugin = MockAccountPlugin {
        hold_calls: hold_calls.clone(),
        release_calls: release_calls.clone(),
        settle_calls: settle_calls.clone(),
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

    // Best-effort: give the server a moment to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, hold_calls, release_calls, settle_calls)
}

async fn connect(addr: SocketAddr) -> AccountPluginClient<Channel> {
    let endpoint = format!("http://{addr}");
    AccountPluginClient::connect(endpoint).await.unwrap()
}

#[tokio::test]
async fn hold_success_returns_ledger_id() {
    let (addr, hold_calls, _, _) = start_mock_plugin(HoldBehavior::Ok).await;
    let mut client = connect(addr).await;

    let resp = client
        .hold(HoldRequest {
            client_id: "client-1".to_string(),
            units: 1,
            operation: "trng".to_string(),
            jti: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.ok);
    assert_eq!(resp.ledger_id, "ledger-1");
    assert_eq!(hold_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn hold_insufficient_credits_maps_to_failed_precondition() {
    let (addr, _, _, _) = start_mock_plugin(HoldBehavior::Insufficient).await;
    let mut client = connect(addr).await;

    let err = client
        .hold(HoldRequest {
            client_id: "client-1".to_string(),
            units: 1,
            operation: "trng".to_string(),
            jti: String::new(),
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert_eq!(err.message(), "insufficient_credits");
}

#[tokio::test]
async fn hold_unavailable_propagates() {
    let (addr, _, _, _) = start_mock_plugin(HoldBehavior::Unavailable).await;
    let mut client = connect(addr).await;

    let err = client
        .hold(HoldRequest {
            client_id: "client-1".to_string(),
            units: 1,
            operation: "trng".to_string(),
            jti: String::new(),
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn release_increments_counter() {
    let (addr, _, release_calls, _) = start_mock_plugin(HoldBehavior::Ok).await;

    // Use the gateway's account_release helper end-to-end.
    let client = connect(addr).await;
    gateway::filters::account_release(Some(client), "ledger-1").await;

    assert_eq!(release_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn release_noop_when_no_client() {
    gateway::filters::account_release(None, "ledger-1").await;
    // And empty ledger_id is also a no-op.
    gateway::filters::account_release(None, "").await;
}

#[tokio::test]
async fn release_2s_timeout_is_respected() {
    // A closed port forces the timeout path: release should swallow the
    // error and return within 2s.
    let bad_endpoint = "http://127.0.0.1:1";
    let channel = tonic::transport::Channel::from_static(bad_endpoint).connect_lazy();
    let client = AccountPluginClient::new(channel);

    let start = std::time::Instant::now();
    gateway::filters::account_release(Some(client), "ledger-1").await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "release should respect ~2s timeout, took {:?}",
        elapsed
    );
}

#[tokio::test]
async fn settle_increments_counter() {
    let (addr, _, _, settle_calls) = start_mock_plugin(HoldBehavior::Ok).await;

    // Use the gateway's account_settle helper end-to-end.
    let client = connect(addr).await;
    gateway::filters::account_settle(Some(client), "ledger-1").await;

    assert_eq!(settle_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn settle_noop_when_no_client() {
    gateway::filters::account_settle(None, "ledger-1").await;
    // And empty ledger_id is also a no-op.
    gateway::filters::account_settle(None, "").await;
}

#[tokio::test]
async fn settle_2s_timeout_is_respected() {
    // A closed port forces the timeout path: settle should swallow the
    // error and return within 2s.
    let bad_endpoint = "http://127.0.0.1:1";
    let channel = tonic::transport::Channel::from_static(bad_endpoint).connect_lazy();
    let client = AccountPluginClient::new(channel);

    let start = std::time::Instant::now();
    gateway::filters::account_settle(Some(client), "ledger-1").await;
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "settle should respect ~2s timeout, took {:?}",
        elapsed
    );
}
