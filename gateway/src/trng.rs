use std::sync::Arc;
use threshold::core::CiphertextMsg;
use tonic::transport::Channel;

use crate::ctx;
use crate::metrics;
use crate::proto::trng::{
    TrngRequest, TrngResponse, randomness_plugin_client::RandomnessPluginClient,
};

use crate::proto::masterseed::{
    GetSeedsRequest, GetSeedsResponse, master_seed_plugin_client::MasterSeedPluginClient,
};

use crate::structures::service::ServiceResult;
use crate::types::{
    EncryptionKey, EncryptionScheme, GatewayError, ServiceHandler, ServiceRequest, ServiceResponse,
};

use thiserror::Error;

/// The src used for aptos orbital services
pub const SRC_APTOS_ORBITAL: &str = "aptosorbital";
/// The src used for aptos orbital services
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
    aptos_orbital_client: RandomnessPluginClient<Channel>,
    masterseed_client: MasterSeedPluginClient<Channel>,
}

unsafe impl Send for TrngService {}

impl TrngService {
    /// Creates a new instance of the TrngService.
    pub async fn new(
        _ctx: Arc<ctx::Context>,
        trng_url: &str,
        masterseed_client: MasterSeedPluginClient<Channel>,
    ) -> Result<Self, TrngError> {
        let aptos_orbital_client = RandomnessPluginClient::connect(trng_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to randomness plugin: {}", e);
                TrngError::GatewayError(GatewayError::ServiceConnectionError(e.to_string()))
            })?;

        Ok(TrngService {
            aptos_orbital_client,
            masterseed_client,
        })
    }

    async fn fallback_one(&mut self) -> Result<TrngResponse, GatewayError> {
        metrics::TRNG_FALLBACKS_COUNTER
            .with_label_values(&["derived"])
            .inc();

        let req = tonic::Request::new(GetSeedsRequest { count: 1 });
        let resp: GetSeedsResponse = self
            .masterseed_client
            .get_seeds(req)
            .await
            .map_err(|e| {
                tracing::error!("Masterseed GetSeeds(1) failed: {}", e);
                GatewayError::InternalError("masterseed GetSeeds failed".to_string())
            })?
            .into_inner();

        if resp.values.is_empty() {
            metrics::TRNG_FALLBACKS_COUNTER
                .with_label_values(&["err"])
                .inc();
            return Err(GatewayError::InternalError(
                "No values from masterseed".to_string(),
            ));
        }

        metrics::TRNG_FALLBACKS_COUNTER
            .with_label_values(&["ok"])
            .inc();

        Ok(TrngResponse {
            values: resp.values, // hex strings
            sig: "".to_string(), // no signature
        })
    }

    // handle N derived RNGs for bulk responses
    async fn fallback_bulk(&mut self, count: usize) -> Result<Vec<ServiceResult>, GatewayError> {
        let req = tonic::Request::new(GetSeedsRequest {
            count: count as u32,
        });

        let resp: GetSeedsResponse = self
            .masterseed_client
            .get_seeds(req)
            .await
            .map_err(|e| {
                tracing::error!("Masterseed GetSeeds({}) failed: {}", count, e);
                GatewayError::InternalError("masterseed GetSeeds (bulk) failed".to_string())
            })?
            .into_inner();

        if resp.values.is_empty() {
            return Ok(vec![]);
        }

        let mut out = Vec::with_capacity(resp.values.len());
        for v in resp.values {
            out.push(ServiceResult {
                service: SERVICE_TRNG.to_string(),
                src: SRC_DERIVED_TRNG.to_string(),
                data: v,
                signature: None,
                bulk: None,
            });
        }
        Ok(out)
    }
}

impl ServiceHandler for TrngService {
    async fn handle(&mut self, svc_req: ServiceRequest) -> Result<ServiceResponse, GatewayError> {
        tracing::info!(
            "Received request ({}) for service: {}, src: {:?}, bulk: {:?}, enc_key: {:?}",
            svc_req.req_id,
            svc_req.service,
            svc_req.src,
            svc_req.bulk,
            svc_req.enc_key
        );
        match get_trng(self.aptos_orbital_client.clone()).await {
            Ok(mut trng) => {
                // aptos returns empty
                if trng.values.is_empty() {
                    tracing::warn!("TRNG returned empty values; attempting fallback");
                    if svc_req.src.contains(&SRC_DERIVED_TRNG.to_string()) {
                        trng = self.fallback_one().await?;
                    } else {
                        return Err(GatewayError::InternalError("no values in TRNG".to_string()));
                    }
                }

                // bulk RNG case
                let bulk_results = if let Some(b) = svc_req.bulk {
                    self.fallback_bulk(b).await?
                } else {
                    vec![]
                };

                let response = process_response(
                    svc_req.req_id,
                    svc_req.enc_key,
                    trng,
                    SRC_APTOS_ORBITAL,
                    bulk_results,
                )?;
                Ok(response)
            }
            Err(e) => {
                tracing::warn!("Failed to get trng from aptos orbital: {}", e);
                if svc_req.src.contains(&SRC_DERIVED_TRNG.to_string()) {
                    tracing::info!("Fallback to masterseed plugin");
                    let trng = self.fallback_one().await?;
                    let bulk_results = if let Some(b) = svc_req.bulk {
                        self.fallback_bulk(b).await?
                    } else {
                        vec![]
                    };
                    let response = process_response(
                        svc_req.req_id,
                        svc_req.enc_key,
                        trng,
                        SRC_DERIVED_TRNG,
                        bulk_results,
                    )?;
                    return Ok(response);
                }
                Err(e)
            }
        }
    }
}

async fn get_trng(
    mut client: RandomnessPluginClient<Channel>,
) -> Result<TrngResponse, GatewayError> {
    let request = TrngRequest {
        ignore_sig: false,
        chunks: 1,
    };
    let trng: TrngResponse = client
        .get_trng(request)
        .await
        .map_err(|e| {
            tracing::warn!("Failed to get trng: {}", e);
            GatewayError::InternalError("Failed to get trng".to_string())
        })?
        .into_inner();
    Ok(trng)
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
    // TODO: Uncomment once public key is available
    // let signature = if trng.sig.is_empty() {
    //     None
    // } else {
    //     Some(Signature {
    //         value: trng.sig,
    //         pk: "".to_string(), // TODO: Add public key
    //         algo: None,
    //     })
    // };

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
