use std::env;

mod common;

#[tokio::test]
async fn test_e2e_error_rpc_bad_method() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "kms.Missing",
            "params": {}
        });
        let response = common::rpc_request(&base_url, &access_token, payload).await?;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "Unknown RPC method should be rejected during request deserialization"
        );
        let body = response
            .text()
            .await
            .map_err(|e| common::E2EError::ParseError(e.to_string()))?;
        assert!(
            body.contains("Request body deserialize error") || body.contains("unknown variant"),
            "Unexpected bad-method response body: {body}"
        );
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
}
