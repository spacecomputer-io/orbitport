use threshold::core::CiphertextMsg;
use tonic::transport::Channel;

use crate::metrics;
use crate::proto::trng::TrngResponse;

use crate::proto::masterseed::{
    GetSeedsRequest, GetSeedsResponse, master_seed_plugin_client::MasterSeedPluginClient,
};

use crate::structures::service::ServiceResult;
use crate::types::{
    EncryptionKey, EncryptionScheme, GatewayError, ServiceHandler, ServiceRequest, ServiceResponse,
};

use thiserror::Error;

/// The src used for masterseed-derived fallback
pub const SRC_DERIVED_TRNG: &str = "derived";
/// The service name for trng (true random number generator)
pub const SERVICE_TRNG: &str = "trng";

/// Error type for the TrngService
/// This error type is used to represent errors that occur
/// when interacting with the TrngService.
#[derive(Error, Debug)]
pub enum TrngError {
    #[error("Trng service error: {0}")]
    GatewayError(#[from] GatewayError),
}

/// The TrngService is a service that provides access to the Aptos Orbital
/// randomness plugin (primary) and the masterseed plugin (fallback).
#[derive(Clone)]
pub struct TrngService {
    masterseed_client: MasterSeedPluginClient<Channel>,
}

unsafe impl Send for TrngService {}

impl TrngService {
    /// Creates a new instance of the TrngService.
    pub async fn new(
        masterseed_client: MasterSeedPluginClient<Channel>,
    ) -> Result<Self, TrngError> {
        Ok(TrngService { masterseed_client })
    }

    fn vals_to_bulk(results: Vec<String>) -> Vec<ServiceResult> {
        results
            .into_iter()
            .map(|v| ServiceResult {
                service: SERVICE_TRNG.to_string(),
                src: SRC_DERIVED_TRNG.to_string(),
                data: v,
                signature: None,
                bulk: None,
            })
            .collect()
    }

    async fn fetch_master_seeds(&mut self, count: u32) -> Result<Vec<String>, GatewayError> {
        if count == 0 {
            return Err(GatewayError::BadRequest("fetch: count must be > 0".into()));
        }

        let req = tonic::Request::new(GetSeedsRequest { count });
        let resp: GetSeedsResponse = self
            .masterseed_client
            .get_seeds(req)
            .await
            .map_err(|e| {
                tracing::error!("Masterseed GetSeeds({}) failed: {}", count, e);
                metrics::TRNG_FALLBACKS_COUNTER
                    .with_label_values(&["masterseed", "error"])
                    .inc();
                GatewayError::InternalError(
                    "Failed to get seeds from masterseed plugin".to_string(),
                )
            })?
            .into_inner();

        if resp.values.is_empty() {
            tracing::warn!("Masterseed returned empty seeds");
            metrics::TRNG_FALLBACKS_COUNTER
                .with_label_values(&["masterseed", "empty"])
                .inc();
            return Err(GatewayError::InternalError(
                "Masterseed returned empty values".to_string(),
            ));
        }

        Ok(resp.values)
    }
}

impl ServiceHandler for TrngService {
    async fn handle(&mut self, svc_req: ServiceRequest) -> Result<ServiceResponse, GatewayError> {
        tracing::debug!(
            "Received TRNG request ({}) for service: {}, src: {:?}, bulk: {:?}, enc_key: {:?}",
            svc_req.req_id,
            svc_req.service,
            svc_req.src,
            svc_req.bulk,
            svc_req.enc_key
        );

        // bulk request is capped.
        let count = svc_req.bulk.unwrap_or(1) as u32;

        // Fetch from Masterseed
        let values = self.fetch_master_seeds(count).await?;
        let bulk_results = if svc_req.bulk.is_some() {
            TrngService::vals_to_bulk(values.clone())
        } else {
            vec![]
        };

        // If not bulk, we take the first value for the main data field
        let single_val_response = TrngResponse {
            values: values.clone(),
            sig: "".to_string(),
        };

        process_response(
            svc_req.req_id,
            svc_req.enc_key,
            single_val_response,
            SRC_DERIVED_TRNG,
            bulk_results,
        )
    }
}

fn process_response(
    req_id: u64,
    enc_key: Option<EncryptionKey>,
    trng: TrngResponse,
    src: &str,
    bulk_results: Vec<ServiceResult>,
) -> Result<ServiceResponse, GatewayError> {
    let bulk = if bulk_results.is_empty() {
        None
    } else {
        Some(bulk_results)
    };

    let first_val = trng.values.first().cloned().unwrap_or_default();

    let data = if let Some(enc_key) = enc_key {
        match enc_key.scheme {
            EncryptionScheme::None => first_val.clone(),
            EncryptionScheme::Threshold => {
                let pk = threshold::serialization::pubkey_from_hex(enc_key.key.as_str()).map_err(
                    |e| {
                        tracing::error!("Failed to parse public key: {}", e);
                        GatewayError::InvalidEncryptionKey
                    },
                )?;
                let cipher = CiphertextMsg::new(pk.encrypt(&first_val));
                cipher.try_into().map_err(|e| {
                    tracing::error!("Failed to encrypt TRNG value: {}", e);
                    GatewayError::InternalError("Failed to encrypt TRNG value".to_string())
                })?
            }
        }
    } else {
        first_val
    };

    let signature = None;

    Ok(ServiceResponse {
        req_id,
        result: Ok(ServiceResult {
            service: SERVICE_TRNG.to_string(),
            src: src.to_string(),
            data,
            signature,
            bulk,
        }),
    })
}
