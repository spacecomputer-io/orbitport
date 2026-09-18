use std::env;

mod common;

async fn assert_rpc_validation_error(
    base_url: &str,
    access_token: &str,
    req_id: u64,
    chunks: u32,
    expected_msg: &str,
) -> Result<(), common::E2EError> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ctrng.Get",
        "params": {
            "chunks": chunks
        }
    });

    let response = common::rpc_request(base_url, access_token, payload).await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "Validation error should still return a JSON-RPC response"
    );

    let raw = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| common::E2EError::ParseError(e.to_string()))?;

    assert_eq!(raw.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
    assert_eq!(raw.get("id").and_then(|v| v.as_u64()), Some(req_id));
    assert!(
        raw.get("result").is_none(),
        "Validation error responses should not include a result field"
    );

    let error = raw
        .get("error")
        .ok_or_else(|| common::E2EError::ParseError("Missing error field".to_string()))?;
    assert_eq!(error.get("code").and_then(|v| v.as_i64()), Some(-32602));
    let message = error
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| common::E2EError::ParseError("Missing error.message".to_string()))?;
    assert!(
        message.contains(expected_msg),
        "Expected error message to mention '{expected_msg}', got '{message}'"
    );

    Ok(())
}

#[tokio::test]
async fn test_e2e_error_rpc_invalid_chunks() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        assert_rpc_validation_error(&base_url, &access_token, 11, 0, "Chunks must be at least 1")
            .await?;
        assert_rpc_validation_error(&base_url, &access_token, 12, 11, "Max chunks exceeded")
            .await?;
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
            "method": "ctrng.Missing",
            "params": {
                "chunks": 1
            }
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
