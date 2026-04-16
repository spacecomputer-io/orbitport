use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tonic::transport::Channel;
use tonic_health::pb::{
    HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus,
    health_client::HealthClient,
};

use crate::proto::plugins::masterseed::master_seed_plugin_client::MasterSeedPluginClient;

use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PluginError {
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Failed to connect to plugin: {0}")]
    ConnectionError(String),
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
}

async fn check_health(addr: &str) -> Result<HealthCheckResponse, tonic::Status> {
    let channel = Channel::from_shared(addr.to_string())
        .map_err(|e| tonic::Status::unavailable(format!("Failed to create channel: {e}")))?
        .connect()
        .await
        .map_err(|e| tonic::Status::unavailable(format!("Failed to connect to {addr}: {e}")))?;
    let mut client = HealthClient::new(channel);
    let request = HealthCheckRequest::default();
    client
        .check(request)
        .await
        .map(|response| response.into_inner())
}

pub async fn wait_for(
    addrs: Vec<String>,
    max_retry_delay: Duration,
    shutdown: Arc<Notify>,
) -> Result<(), PluginError> {
    let mut retry_delay = Duration::from_secs(1);
    let start_time = std::time::Instant::now();
    let shutdown = shutdown.notified();
    tokio::pin!(shutdown);

    tracing::info!(
        "Waiting for dependencies to be healthy before serving traffic: {:?}",
        addrs
    );

    let mut remaining = VecDeque::from(addrs);
    loop {
        let n = remaining.len();
        for _i in 0..n {
            let Some(addr) = remaining.pop_front() else {
                break;
            };
            let health_result = tokio::select! {
                _ = &mut shutdown => {
                    return Err(PluginError::InternalError(
                        "Received shutdown signal while waiting for dependencies".to_string(),
                    ));
                }
                result = check_health(addr.as_str()) => result,
            };
            match health_result {
                Ok(response) => {
                    if response.status() != ServingStatus::Serving {
                        tracing::debug!(
                            "Plugin {} is not serving. Status: {:?}",
                            addr,
                            response.status()
                        );
                        remaining.push_back(addr);
                    } else {
                        tracing::debug!("Plugin {} is serving.", addr);
                    }
                }
                Err(e) => {
                    tracing::debug!("Failed to check health for {}: {}", addr, e);
                    remaining.push_back(addr);
                }
            }
        }
        if remaining.is_empty() {
            let elapsed_time = start_time.elapsed();
            tracing::info!(
                "All dependencies are healthy. Time elapsed: {:?}",
                elapsed_time
            );
            return Ok(());
        }
        let elapsed_time = start_time.elapsed();
        tracing::warn!(
            "Not all dependencies are healthy. Time elapsed: {:?}. Retrying in {:?}",
            elapsed_time,
            retry_delay
        );
        tokio::select! {
            _ = &mut shutdown => {
                return Err(PluginError::InternalError(
                    "Received shutdown signal while waiting for dependencies".to_string(),
                ));
            }
            _ = tokio::time::sleep(retry_delay) => {}
        }
        retry_delay = (retry_delay * 2).min(max_retry_delay); // Exponential backoff
    }
}

pub struct PluginCatalog {
    urls: Arc<HashMap<String, String>>,
}

impl PluginCatalog {
    /// Build a catalog from an explicit name→URL map. Typically constructed
    /// from `ORBITPORT_PLUGIN_*` environment variables; see `from_env`.
    pub fn new(urls: HashMap<String, String>) -> Self {
        PluginCatalog {
            urls: Arc::new(urls),
        }
    }

    /// Build a catalog by scanning the environment for variables matching
    /// `ORBITPORT_PLUGIN_<NAME>=<url>`. `<NAME>` is lowercased and becomes
    /// the key. Adding a plugin therefore requires no code change here —
    /// just set the env var and its URL is registered automatically.
    pub fn from_env() -> Self {
        const PREFIX: &str = "ORBITPORT_PLUGIN_";
        let urls = std::env::vars()
            .filter_map(|(k, v)| {
                k.strip_prefix(PREFIX)
                    .map(|suffix| (suffix.to_lowercase(), v))
            })
            .collect();
        Self::new(urls)
    }

    /// All registered plugin URLs (unordered). Used by `wait_for` at startup.
    pub fn urls(&self) -> Vec<String> {
        self.urls.values().cloned().collect()
    }

    /// Look up a plugin URL by name without opening a connection.
    pub fn url(&self, plugin_name: &str) -> Option<&str> {
        self.urls.get(plugin_name).map(|s| s.as_str())
    }

    pub async fn get_client(&self, plugin_name: &str) -> Result<Channel, PluginError> {
        let url = self
            .urls
            .get(plugin_name)
            .ok_or_else(|| PluginError::PluginNotFound(plugin_name.to_string()))?;

        Channel::from_shared(url.to_string())
            .map_err(|e| PluginError::ConnectionError(format!("Failed to create channel: {e}")))?
            .connect()
            .await
            .map_err(|_e| PluginError::ConnectionError(plugin_name.to_string()))
    }

    pub async fn get_auth_client(&self) -> Result<AuthPluginClient<Channel>, PluginError> {
        let channel = self.get_client("auth").await?;
        Ok(AuthPluginClient::new(channel))
    }

    pub async fn get_masterseed_client(
        &self,
    ) -> Result<MasterSeedPluginClient<Channel>, PluginError> {
        let channel = self.get_client("masterseed").await?;
        Ok(MasterSeedPluginClient::new(channel))
    }
}
