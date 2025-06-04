use std::env;

mod common;

/// Test e2e offline profile (aptos orbital api is down)
/// run with `cargo test --test e2e_offline --features localtest`
/// to run the test with local docker containers.
/// NOTE that you can also run from the root of the repo with:
/// `make E2E_PROFILE=offline e2e`
#[tokio::test]
async fn test_e2e_offline() {
    tracing_subscriber::fmt::init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e offline path test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("offline").await.unwrap();

    let result = async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let n = 1;
        for _ in 0..n {
            let resp = common::get_trng(&base_url, &access_token, None, None, None).await?;
            assert!(resp.data.len() > 0, "Response data is empty");
        }
        tracing::info!("All requests completed successfully");
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
