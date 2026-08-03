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

use crate::proto::plugins::account::account_plugin_client::AccountPluginClient;
use crate::proto::plugins::auth::auth_plugin_client::AuthPluginClient;
use crate::proto::plugins::issuer::issuer_plugin_client::IssuerPluginClient;
use crate::proto::plugins::kms::kms_plugin_client::KmsPluginClient;
use crate::proto::plugins::threshold::threshold_plugin_client::ThresholdPluginClient;
use crate::services::threshold::ThresholdGroupRegistry;

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
    threshold_enabled: bool,
    threshold_groups: ThresholdGroupRegistry,
}

impl PluginCatalog {
    pub fn new(
        auth_url: &str,
        masterseed_url: &str,
        kms_url: &str,
        account_url: Option<&str>,
        issuer_url: Option<&str>,
        threshold_enabled: bool,
        threshold_url: &str,
        threshold_groups: ThresholdGroupRegistry,
    ) -> Self {
        let mut urls = HashMap::new();
        urls.insert("auth".to_string(), auth_url.to_string());
        urls.insert("kms".to_string(), kms_url.to_string());
        urls.insert("masterseed".to_string(), masterseed_url.to_string());
        if let Some(url) = account_url {
            urls.insert("account".to_string(), url.to_string());
        }
        if let Some(url) = issuer_url {
            urls.insert("issuer".to_string(), url.to_string());
        }
        if threshold_enabled {
            urls.insert("threshold".to_string(), threshold_url.to_string());
        }

        PluginCatalog {
            urls: Arc::new(urls),
            threshold_enabled,
            threshold_groups,
        }
    }

    /// Returns a lazy channel: it connects on first use and reconnects on its
    /// own afterwards. Eager `.connect()` here would bind a configured plugin's
    /// availability to one instant at startup — a blip would leave the caller
    /// holding `None` for the process lifetime, silently disabling whatever
    /// that plugin gates (credit holds and PAT revocation, for the account
    /// plugin). Startup health is already gated by `wait_for`.
    pub async fn get_client(&self, plugin_name: &str) -> Result<Channel, PluginError> {
        let url = self
            .urls
            .get(plugin_name)
            .ok_or_else(|| PluginError::PluginNotFound(plugin_name.to_string()))?;

        Ok(Channel::from_shared(url.to_string())
            .map_err(|e| PluginError::ConnectionError(format!("Failed to create channel: {e}")))?
            .connect_lazy())
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

    pub async fn get_kms_client(&self) -> Result<KmsPluginClient<Channel>, PluginError> {
        let channel = self.get_client("kms").await?;
        Ok(KmsPluginClient::new(channel))
    }

    pub async fn get_account_client(&self) -> Result<AccountPluginClient<Channel>, PluginError> {
        let channel = self.get_client("account").await?;
        Ok(AccountPluginClient::new(channel))
    }

    pub async fn get_issuer_client(&self) -> Result<IssuerPluginClient<Channel>, PluginError> {
        let channel = self.get_client("issuer").await?;
        Ok(IssuerPluginClient::new(channel))
    }

    pub async fn get_threshold_client(
        &self,
    ) -> Result<ThresholdPluginClient<Channel>, PluginError> {
        if !self.threshold_enabled {
            return Err(PluginError::PluginNotFound("threshold".to_string()));
        }
        let channel = self.get_client("threshold").await?;
        Ok(ThresholdPluginClient::new(channel))
    }

    pub fn threshold_enabled(&self) -> bool {
        self.threshold_enabled
    }

    pub fn threshold_groups(&self) -> ThresholdGroupRegistry {
        self.threshold_groups.clone()
    }
}
