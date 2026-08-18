use serde::de::DeserializeOwned;
use std::env;
use thiserror::Error;
use tokio::process::Command;

use gateway::structures::service::ServiceResult;

const THRESHOLD_GROUP: &str = "e2e-group";
const THRESHOLD_MOUNT: &str = "threshold";

/// Error type for end-to-end tests
#[allow(dead_code)]
#[derive(Error, Debug)]
pub enum E2EError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Failed to execute command: {0}")]
    CommandError(String),
    #[error("Failed to parse response: {0}")]
    ParseError(String),
    #[error("Failed to make request: {0}")]
    RequestError(String),
    #[error("Assertion failed: {0}")]
    AssertionFailed(String),
}

/// Get the TRNG service from the orbitport gateway.
#[allow(dead_code)]
pub async fn get_trng(
    base_url: &str,
    access_token: &str,
    src: Option<Vec<String>>,
    bulk: Option<usize>,
    tpk: Option<String>,
) -> Result<ServiceResult, E2EError> {
    let srcs = src.unwrap_or(vec![]);
    let src = srcs
        .into_iter()
        .map(|s| format!("src={s}"))
        .collect::<Vec<String>>()
        .join("&");
    let client = reqwest::Client::new();
    let start_time = std::time::Instant::now();
    tracing::debug!("Making request to gateway with src: {}", src);
    let bulk = bulk.unwrap_or(0);
    let bulk = if bulk > 0 {
        format!("&bulk={bulk}")
    } else {
        String::new()
    };
    let tpk = if let Some(tpk) = tpk {
        format!("&key={tpk}")
    } else {
        String::new()
    };
    let response = client
        .get(format!("{base_url}/api/v1/services/trng?{src}{bulk}{tpk}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| E2EError::RequestError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        tracing::error!("Gateway returned Error: {} | Body: {}", status, text);
        return Err(E2EError::AssertionFailed(format!(
            "Server returned error {}: {}",
            status, text
        )));
    }

    let raw = response
        .text()
        .await
        .map_err(|e| E2EError::ParseError(e.to_string()))?;
    tracing::debug!("Raw response: {}", raw);
    let parsed = serde_json::from_str::<ServiceResult>(&raw)
        .map_err(|e| E2EError::ParseError(e.to_string()))?;

    let elapsed_time = start_time.elapsed();
    tracing::debug!("Request completed in {:?}", elapsed_time);

    Ok(parsed)
}

#[allow(dead_code)]
pub async fn rpc_ctrng_get(
    base_url: &str,
    access_token: &str,
    count: u32,
) -> Result<gateway::proto::services::ctrng::CTrngResponse, E2EError> {
    let req_id = 1;
    let payload = serde_json::json!(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "ctrng.Get",
            "params": serde_json::json!({
                "chunks": count
            }),
        }
    );
    rpc_success_result(base_url, access_token, req_id, payload).await
}

#[allow(dead_code)]
pub async fn rpc_threshold_coordinate_dkg(
    base_url: &str,
    access_token: &str,
    req_id: u64,
) -> Result<gateway::proto::services::threshold::DkgResponse, E2EError> {
    let nodes = threshold_test_nodes();
    prepare_threshold_nodes(&nodes).await?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "kms_threshold.CoordinateDKG",
        "params": {
            "Alias": format!("e2e-key-{req_id}"),
            "GroupName": THRESHOLD_GROUP,
            "SessionId": format!("dkg-session-{req_id}")
        },
    });

    rpc_success_result(base_url, access_token, req_id, payload).await
}

#[allow(dead_code)]
pub async fn rpc_threshold_sign(
    base_url: &str,
    access_token: &str,
    req_id: u64,
    key_id: &str,
    message: &str,
) -> Result<gateway::proto::services::threshold::ThresholdSignResponse, E2EError> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "kms_threshold.Sign",
        "params": {
            "KeyId": key_id,
            "GroupName": THRESHOLD_GROUP,
            "SessionId": format!("sign-session-{req_id}"),
            "Message": message
        },
    });

    rpc_success_result(base_url, access_token, req_id, payload).await
}

struct ThresholdTestNode {
    node_id: &'static str,
    party_index: i32,
    host_openbao_url: &'static str,
}

fn threshold_test_nodes() -> Vec<ThresholdTestNode> {
    vec![
        ThresholdTestNode {
            node_id: "node-a",
            party_index: 0,
            host_openbao_url: "http://localhost:8200",
        },
        ThresholdTestNode {
            node_id: "node-b",
            party_index: 1,
            host_openbao_url: "http://localhost:8201",
        },
        ThresholdTestNode {
            node_id: "node-c",
            party_index: 2,
            host_openbao_url: "http://localhost:8202",
        },
    ]
}

async fn prepare_threshold_nodes(nodes: &[ThresholdTestNode]) -> Result<(), E2EError> {
    let client = reqwest::Client::new();
    let participants = serde_json::to_string(
        &nodes
            .iter()
            .map(|node| {
                serde_json::json!({
                    "node_id": node.node_id,
                    "party_index": node.party_index,
                })
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|e| E2EError::ParseError(e.to_string()))?;

    for node in nodes {
        openbao_post(
            &client,
            node.host_openbao_url,
            &format!("/v1/{THRESHOLD_MOUNT}/config/node"),
            serde_json::json!({ "node_id": node.node_id }),
        )
        .await?;

        openbao_post(
            &client,
            node.host_openbao_url,
            &format!("/v1/{THRESHOLD_MOUNT}/groups/{THRESHOLD_GROUP}"),
            serde_json::json!({
                "threshold": 2,
                "participants": participants,
            }),
        )
        .await?;
    }

    Ok(())
}

async fn openbao_post(
    client: &reqwest::Client,
    base_url: &str,
    path: &str,
    payload: serde_json::Value,
) -> Result<(), E2EError> {
    let response = client
        .post(format!("{}{}", base_url.trim_end_matches('/'), path))
        .header("Content-Type", "application/json")
        .header("X-Vault-Token", "root")
        .json(&payload)
        .send()
        .await
        .map_err(|e| E2EError::RequestError(e.to_string()))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(E2EError::AssertionFailed(format!(
            "OpenBao setup returned error {status}: {text}"
        )));
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn rpc_request(
    base_url: &str,
    access_token: &str,
    payload: serde_json::Value,
) -> Result<reqwest::Response, E2EError> {
    reqwest::Client::new()
        .post(format!("{base_url}/api/v1/rpc"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .bearer_auth(access_token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| E2EError::RequestError(e.to_string()))
}

#[allow(dead_code)]
pub async fn rpc_success_result<T: DeserializeOwned>(
    base_url: &str,
    access_token: &str,
    req_id: u64,
    payload: serde_json::Value,
) -> Result<T, E2EError> {
    let response = rpc_request(base_url, access_token, payload).await?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        tracing::error!("Gateway returned Error: {} | Body: {}", status, text);
        return Err(E2EError::AssertionFailed(format!(
            "Server returned error {}: {}",
            status, text
        )));
    }

    let raw = response
        .json::<serde_json::Value>()
        .await
        .map_err(|e| E2EError::ParseError(e.to_string()))?;
    tracing::debug!("jRPC response: {}", raw);

    if raw.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(E2EError::AssertionFailed(
            "Response missing jsonrpc=2.0".to_string(),
        ));
    }
    if raw.get("id").and_then(|v| v.as_u64()) != Some(req_id) {
        return Err(E2EError::AssertionFailed(format!(
            "Expected response id {req_id}, got {:?}",
            raw.get("id")
        )));
    }
    if raw.get("error").is_some() {
        return Err(E2EError::AssertionFailed(format!(
            "Expected success response, got error: {}",
            raw.get("error").unwrap_or(&serde_json::Value::Null)
        )));
    }

    let result = raw
        .get("result")
        .ok_or_else(|| E2EError::ParseError("Missing result field".to_string()))?;

    serde_json::from_value::<T>(result.clone()).map_err(|e| E2EError::ParseError(e.to_string()))
}

/// Prepare the test environment by starting the orbitport Docker containers.
/// This function is called before the tests are executed.
/// It checks if the containers are already running, and if not, it starts them.
/// The function returns `true` if the containers were started, and `false` if they were already running.
#[allow(dead_code)]
pub async fn pre_test(profile: &str) -> Result<bool, E2EError> {
    tracing::info!("Preparing test environment");

    if !is_running("gateway").await.unwrap_or(false) {
        tracing::info!("Starting orbitport");
        let env_file = env::var("OPTEST_DOTENV").unwrap_or(".dev.env".to_string());
        let output = Command::new("docker-compose")
            .current_dir("..")
            .arg("-f")
            .arg("dev.docker-compose.yaml")
            .arg("--env-file")
            .arg(&env_file)
            .arg("up")
            .arg("-d")
            .arg("--build")
            .arg("--force-recreate")
            .env("OPMOCK_PROFILE", profile)
            .output()
            .await
            .map_err(|e| E2EError::CommandError(e.to_string()))?;

        if !output.status.success() {
            let error_message = String::from_utf8_lossy(&output.stderr);
            return Err(E2EError::CommandError(format!(
                "Failed to start orbitport: {}",
                error_message
            )));
        }
        tracing::info!("Waiting for orbitport to start");

        // Wait for the containers to be up for 10 sec
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                return Err(E2EError::InternalError("Timeout waiting for containers to be up".to_string()));
            }
            _ = is_running("gateway") => {
                tracing::info!("Orbitport is running");
                return Ok(true);
            }
        };
    }
    tracing::info!("Orbitport is running");
    Ok(false)
}

/// Stop the orbitport Docker containers if they are running.
/// This function is called after the tests are completed.
#[allow(dead_code)]
pub async fn post_test(started: bool) -> Result<(), E2EError> {
    if started {
        tracing::info!("Stopping orbitport");
        let output = Command::new("docker-compose")
            .current_dir("..")
            .arg("-f")
            .arg("dev.docker-compose.yaml")
            .arg("down")
            .output()
            .await
            .map_err(|e| E2EError::CommandError(e.to_string()))?;

        if !output.status.success() {
            let error_message = String::from_utf8_lossy(&output.stderr);
            return Err(E2EError::CommandError(format!(
                "Failed to stop orbitport: {}",
                error_message
            )));
        }
    }
    Ok(())
}

/// Check if a Docker container is running by its name.
/// Returns `true` if the container is running, `false` otherwise.
#[allow(dead_code)]
pub async fn is_running(container_name: &str) -> Result<bool, E2EError> {
    let output = Command::new("docker")
        .arg("ps")
        .arg("-q")
        .arg("--filter")
        .arg(format!("name={container_name}"))
        .output()
        .await
        .map_err(|e| E2EError::CommandError(e.to_string()))?;

    if output.status.success() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        if output_str.trim().is_empty() {
            Ok(false)
        } else {
            Ok(true)
        }
    } else {
        Err(E2EError::CommandError(
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }
}
