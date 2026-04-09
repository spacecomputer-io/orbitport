use tonic::transport::Channel;

use crate::metrics;

use crate::proto::plugins::masterseed::{
    GetSeedsRequest, GetSeedsResponse, master_seed_plugin_client::MasterSeedPluginClient,
};
use crate::proto::services::ctrng::{CTrngResponse, CTrngResult};
use thiserror::Error;

/// The entropy src used for space-based randomness
pub const SRC_SPACE: &str = "space";
/// The entropy src used for masterseed-derived fallback
pub const SRC_MIXED: &str = "mixed";

/// Error type for the CTrngService
#[derive(Error, Debug)]
pub enum CTrngError {
    #[error("Failed to fetch from masterseed plugin: {0}")]
    MasterSeedFailure(String),
}

#[derive(Clone)]
pub struct CTrngService {
    masterseed_client: MasterSeedPluginClient<Channel>,
}

impl CTrngService {
    /// Creates a new instance of the CTrngService.
    pub fn new(masterseed_client: MasterSeedPluginClient<Channel>) -> Self {
        CTrngService { masterseed_client }
    }

    /// Get random values using a mixed approach where random values are derived from space-based seed.
    pub async fn get_mixed(&mut self, count: u32) -> Result<CTrngResponse, CTrngError> {
        let req = tonic::Request::new(GetSeedsRequest { count });
        let resp: GetSeedsResponse = self
            .masterseed_client
            .get_seeds(req)
            .await
            .map_err(|e| {
                tracing::warn!("Masterseed GetSeeds({}) failed: {}", count, e);
                metrics::record_trng_source("mixed", "error");
                CTrngError::MasterSeedFailure(
                    "Failed to get values from masterseed plugin".to_string(),
                )
            })?
            .into_inner();

        if resp.values.is_empty() {
            tracing::warn!("Masterseed returned empty values");
            metrics::record_trng_source("mixed", "empty");
            return Err(CTrngError::MasterSeedFailure("empty values".to_string()));
        }

        metrics::record_trng_source("mixed", "success");

        Ok(CTrngResponse {
            items: resp
                .values
                .into_iter()
                .map(|v| CTrngResult {
                    value: v,
                    src: Some("mixed".to_string()),
                })
                .collect(),
        })
    }
}
