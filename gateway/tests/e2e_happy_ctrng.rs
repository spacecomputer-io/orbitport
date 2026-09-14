#![cfg(feature = "ctrng")]

use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

#[tokio::test]
async fn test_e2e_happy_ctrng() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e RPC test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let resp = common::rpc_ctrng_get(&base_url, &access_token, 5).await?;
        assert_eq!(resp.items.len(), 5, "RPC response did not honor chunks=5");
        for item in &resp.items {
            assert!(!item.value.is_empty(), "RPC response item value is empty");
            assert_eq!(
                item.src.as_deref(),
                Some("mixed"),
                "RPC response item src was not mixed"
            );
        }
        tracing::debug!("RPC response: {:?}", resp);
        tracing::info!("RPC request completed successfully");
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        tracing::error!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    tracing::info!("Test completed successfully");
}
