use std::env;
use thiserror::Error;
use tokio::process::Command;

use gateway::structures::service::ServiceResult;

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
}

/// Get the TRNG service from the orbitport gateway.
pub async fn get_trng(
    base_url: &str,
    access_token: &str,
    src: Option<Vec<String>>,
    bulk: Option<usize>,
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
        format!("bulk={bulk}")
    } else {
        String::new()
    };
    let response = client
        .get(format!("{base_url}/api/v1/services/trng?{src}&{bulk}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| E2EError::RequestError(e.to_string()))?;

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
        std::env::set_current_dir("../").expect("Failed to change directory");
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg("dev.docker-compose.yaml")
            .arg("--env-file")
            .arg(&env_file)
            .arg("up")
            .arg("-d")
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

        std::env::set_current_dir("gateway").expect("Failed to change directory");
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
        std::env::set_current_dir("../").expect("Failed to change directory");
        let output = Command::new("docker-compose")
            .arg("-f")
            .arg("dev.docker-compose.yaml")
            .arg("down")
            .output()
            .await
            .map_err(|e| E2EError::CommandError(e.to_string()))?;

        std::env::set_current_dir("gateway").expect("Failed to change directory");

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
