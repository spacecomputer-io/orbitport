use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

#[tokio::test]
async fn test_e2e_threshold_sign_two_of_three() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e threshold signing test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let req_id = unique_req_id();
        let dkg = common::rpc_threshold_coordinate_dkg(&base_url, &access_token, req_id).await?;
        let message = "aGVsbG8gdGhyZXNob2xkIHNpZ25pbmc=";
        let signing =
            common::rpc_threshold_sign(&base_url, &access_token, req_id + 1, &dkg.key_id, message)
                .await?;

        assert_eq!(signing.key_id, dkg.key_id);
        assert_eq!(signing.group_name, "e2e-group");
        assert_eq!(signing.status, "sign_completed");
        assert!(!signing.signature.is_empty());

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

    tracing::info!("Threshold signing e2e test completed successfully");
}

fn unique_req_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is earlier than UNIX_EPOCH")
        .as_millis() as u64
}
