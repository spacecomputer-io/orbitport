use std::sync::{Arc, RwLock};

use rand::Rng as _;
use threshold::core::CiphertextMsg;
use tokio::sync::broadcast::{Receiver, Sender};
use tonic::transport::Channel;

use crate::ctx;
use crate::metrics;
use crate::proto::trng::{
    TrngRequest, TrngResponse, randomness_plugin_client::RandomnessPluginClient,
};
use crate::structures::service::ServiceResult;
use crate::types::{
    EncryptionKey, EncryptionScheme, GatewayError, ServiceHandler, ServiceRequest, ServiceResponse,
};

use bip32::{ChildNumber, ExtendedPrivateKey, XPrv};

use thiserror::Error;

/// The src used for aptos orbital services
pub const SRC_APTOS_ORBITAL: &str = "aptosorbital";
/// The src used for aptos orbital services
pub const SRC_DERIVED_TRNG: &str = "derived";
/// The service name for trng (true random number generator)
pub const SERVICE_TRNG: &str = "trng";
/// The size of the TRNG (true random number generator) output.
const TRNG_SIZE: usize = 32;
/// The default master seed interval in seconds.
const DEFAULT_MASTER_SEED_INTERVAL: u64 = 60 * 60; // 60 min
/// The maximum number of master seeds to keep in memory.
/// Once this limit is reached, the oldest master seed will be removed.
const MAX_MASTER_SEEDS: usize = 10;

/// Error type for the TrngService
/// This error type is used to represent errors that occur
/// when interacting with the TrngService.
#[derive(Error, Debug)]
pub enum TrngError {
    #[error("Trng service error: {0}")]
    GatewayError(#[from] GatewayError),
    #[error("Failed to derive TRN from master seed: {0}")]
    MasterSeedDerivationError(String),
}

/// The TrngService is a service that provides access to the Aptos Orbital
/// randomness plugin. It maintains a list of master_seed that it keeps collecting in the background
/// (every master_seed_interval) and uses it to derive new random numbers as fallback strategy
/// when aptos orbital is not available or doesn't keep up with the demand.
#[derive(Clone)]
pub struct TrngService {
    aptos_orbital_client: RandomnessPluginClient<Channel>,
    master_seeds: Arc<RwLock<Vec<MasterSeed>>>,
}

unsafe impl Send for TrngService {}

impl TrngService {
    /// Creates a new instance of the TrngService.
    pub async fn new(
        ctx: Arc<ctx::Context>,
        trng_url: &str,
        master_seed_interval: Option<u64>,
        master_seed: Option<String>,
    ) -> Result<Self, TrngError> {
        let aptos_orbital_client = RandomnessPluginClient::connect(trng_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to randomness plugin: {}", e);
                TrngError::GatewayError(GatewayError::ServiceConnectionError(e.to_string()))
            })?;
        let master_seeds = match master_seed {
            Some(seed) => {
                let mut master_seeds = vec![];
                if !seed.is_empty() {
                    let master_seed = MasterSeed(seed);
                    let _ = master_seed.derive(0)?;
                    tracing::info!("Using master seed with {} bytes", master_seed.0.len());
                    master_seeds.push(master_seed);
                }
                metrics::TRNG_MASTER_SEEDS.set(master_seeds.len() as i64);
                Arc::new(RwLock::new(master_seeds))
            }
            None => {
                metrics::TRNG_MASTER_SEEDS.set(0);
                Arc::new(RwLock::new(vec![]))
            }
        };
        let master_seed_interval = master_seed_interval.unwrap_or(DEFAULT_MASTER_SEED_INTERVAL);
        if master_seed_interval > 0 {
            tracing::info!(
                "Starting master seed fetcher with interval of {} seconds",
                master_seed_interval
            );
            // Create a channel for sending master seeds
            let (tx, mut rx) = tokio::sync::broadcast::channel::<MasterSeed>(1);
            // Spawn a task to receive master seeds and add them to self.master_seeds
            let master_seeds_clone = master_seeds.clone();
            let mut quit = ctx.recv();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = quit.recv() => {
                            tracing::info!("Received stop signal, stopping master seed fetcher");
                            break;
                        }
                        mseed = rx.recv() => {
                            match mseed {
                                Ok(master_seed) => {
                                    tracing::info!("Received master seed with {} bytes", master_seed.0.len());
                                    let mut master_seeds = master_seeds_clone.write().unwrap();
                                    // Check if we have reached the maximum number of master seeds
                                    // If so, remove the oldest one (like a ring buffer)
                                    if master_seeds.len() >= MAX_MASTER_SEEDS {
                                        master_seeds.remove(0);
                                    }
                                    master_seeds.push(master_seed);
                                    metrics::TRNG_MASTER_SEEDS.set(master_seeds.len() as i64);
                                }
                                Err(_) => {
                                    tracing::warn!("Failed to receive master seed");
                                }
                            }
                        }
                    }
                }
            });
            // Spawn a task to fetch master seeds
            tokio::spawn(fetch_master_seeds(
                trng_url.to_string(),
                master_seed_interval,
                tx,
                ctx.recv(),
            ));
        }
        Ok(TrngService {
            aptos_orbital_client,
            master_seeds,
        })
    }

    fn get_next_master_seed(&self) -> Option<MasterSeed> {
        let master_seeds = self.master_seeds.read().unwrap();
        if master_seeds.is_empty() {
            return None;
        }
        let mut rng = rand::rng();
        let index = rng.random_range(0..master_seeds.len());
        Some(master_seeds[index].clone())
    }

    async fn fallback(&mut self) -> Result<TrngResponse, GatewayError> {
        metrics::TRNG_FALLBACKS_COUNTER
        .with_label_values(&["derived"])
        .inc();

        if let Some(master_seed) = self.get_next_master_seed() {
            let mut rng = rand::rng();
            let index = rng.random_range(0..ChildNumber::HARDENED_FLAG);
            match master_seed.derive(index) {
                Ok(key) => {
                    let trng = to_trng(key);
                    metrics::TRNG_FALLBACKS_COUNTER
                    .with_label_values(&["ok"])
                    .inc();

                    let resp = TrngResponse {
                        values: vec![trng],
                        sig: "".to_string(),
                    };
                    Ok(resp)
                }
                Err(e) => {
                    metrics::TRNG_FALLBACKS_COUNTER
                    .with_label_values(&["err"])
                    .inc();

                    tracing::error!("Failed to derive key from master seed: {}", e);
                    Err(GatewayError::InternalError(
                        "Failed to derive key".to_string(),
                    ))
                }
            }
        } else {
            metrics::TRNG_FALLBACKS_COUNTER
            .with_label_values(&["err"])
            .inc();

            tracing::error!("No master seed available");
            Err(GatewayError::InternalError(
                "No master seed available".to_string(),
            ))
        }
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
                if trng.values.is_empty() {
                    tracing::warn!("TRNG returned empty values; attempting fallback");
                    if svc_req.src.contains(&SRC_DERIVED_TRNG.to_string()) {
                        trng = self.fallback().await?;
                    } else {
                        return Err(GatewayError::InternalError("no values in TRNG".to_string()));
                    }
                }

                let bulk_results = if svc_req.bulk.is_some() {
                    let first_val = trng.values.first().cloned().ok_or_else(|| {
                        GatewayError::InternalError("no values in TRNG".to_string())
                    })?;
                    let master_seed = MasterSeed(first_val);
                    derive_results(master_seed, svc_req.bulk.unwrap()).await?
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
                    tracing::info!("Fallback to derived trng");
                    let trng = self.fallback().await?;
                    let bulk_results = if svc_req.bulk.is_some() {
                        let first_val = trng.values.first().cloned().ok_or_else(|| {
                            GatewayError::InternalError("no values in TRNG".to_string())
                        })?;
                        let master_seed = MasterSeed(first_val);
                        derive_results(master_seed, svc_req.bulk.unwrap()).await?
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

async fn derive_results(
    master_seed: MasterSeed,
    bulk: usize,
) -> Result<Vec<ServiceResult>, GatewayError> {
    let mut results = vec![];
    for i in 0..bulk {
        let derived_key = master_seed.derive(i as u32);
        if derived_key.is_err() {
            tracing::error!("Failed to derive key from master");
            return Err(GatewayError::InternalError(
                "Failed to derive key from master".to_string(),
            ));
        }
        let derived_trng = to_trng(derived_key.unwrap());
        results.push(ServiceResult {
            service: SERVICE_TRNG.to_string(),
            src: SRC_DERIVED_TRNG.to_string(),
            data: derived_trng,
            signature: None, // TODO: Add signature
            bulk: None,
        });
    }
    Ok(results)
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

pub async fn fetch_master_seeds(
    trng_url: String,
    fetch_interval: u64,
    processor: Sender<MasterSeed>,
    mut quit: Receiver<()>,
) {
    let client = match RandomnessPluginClient::connect(trng_url.to_string()).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to connect to randomness plugin: {}", e);
            return;
        }
    };
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(fetch_interval));
    loop {
        tokio::select! {
            _ = quit.recv() => {
                tracing::info!("Received stop signal, stopping trng service");
                break;
            }
            _ = interval.tick() => {
                tracing::info!("Collecting master seed");
                let trng = get_trng(client.clone()).await;
                match trng {
                    Ok(trng) => {
                        if let Some(first) = trng.values.first() {
                            let master_seed = MasterSeed(first.clone());
                            match master_seed.derive(0) {
                                Ok(_) => {
                                    if let Err(e) = processor.send(master_seed.clone()) {
                                        tracing::error!("Failed to send master seed: {}", e);
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to derive key from master seed: {}", e);
                                    continue;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to get trng: {}", e);
                    }
                }
            }
        }
    }
}

/// MasterSeed is used to derive new random numbers from a cTRNG.
/// It holds a master key that is used to derive new keys where we use their bytes as random numbers.
#[derive(Clone, Debug, PartialEq)]
pub struct MasterSeed(String);

impl MasterSeed {
    /// Derives a new key from the master seed using the given path.
    /// The path is a sequence of integers separated by slashes. E.g. "0/1/2".
    fn derive(&self, index: u32) -> Result<Vec<u8>, TrngError> {
        let seed = self.0.clone();
        let root_private_key: XPrv = ExtendedPrivateKey::new(&seed).map_err(|e| {
            tracing::error!("Failed to create root private key: {}", e);
            TrngError::MasterSeedDerivationError(e.to_string())
        })?;

        let mut child_index = index;
        if child_index >= ChildNumber::HARDENED_FLAG {
            child_index %= ChildNumber::HARDENED_FLAG;
        }
        let child_number = ChildNumber::new(child_index, true).map_err(|e| {
            tracing::error!("Failed to create child number: {}", e);
            TrngError::MasterSeedDerivationError(e.to_string())
        })?;
        let child_key = root_private_key.derive_child(child_number).map_err(|e| {
            tracing::error!("Failed to derive child key: {}", e);
            TrngError::MasterSeedDerivationError(e.to_string())
        })?;
        Ok(child_key.public_key().to_bytes().to_vec())
    }
}

fn to_trng(key: Vec<u8>) -> String {
    if key.len() < TRNG_SIZE {
        return hex::encode(key);
    }
    hex::encode(&key[..TRNG_SIZE])
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let master_seed = MasterSeed(
            "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890".to_string(),
        );
        let derived_key = to_trng(master_seed.derive(0).unwrap());
        assert_eq!(
            derived_key,
            "036d5cc0bc13731b437905c4851fab6e618aabac1635ef4d2e74c4046dc3b465".to_string()
        );
        let derived_key_1 = to_trng(master_seed.derive(1).unwrap());
        assert_eq!(
            derived_key_1,
            "0224c02f4c886f8fe38037df5b8f674d75150246a1e1e0628b373927f7df35ab".to_string()
        );
    }

    #[test]
    fn test_derive_key_error() {
        let master_seed = MasterSeed("invalid_seed".to_string());
        let result = master_seed.derive(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_hardened() {
        let master_seed = MasterSeed(
            "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890".to_string(),
        );
        let derived_key = to_trng(master_seed.derive(ChildNumber::HARDENED_FLAG + 1).unwrap());
        assert_eq!(
            derived_key,
            "0224c02f4c886f8fe38037df5b8f674d75150246a1e1e0628b373927f7df35ab".to_string()
        );
    }

    #[tokio::test]
    async fn test_derive_results() {
        let master_seed = MasterSeed(
            "a1b2c3d4e5f67890abcdef1234567890a1b2c3d4e5f67890abcdef1234567890".to_string(),
        );
        let results = derive_results(master_seed, 10).await.unwrap();
        assert_eq!(results.len(), 10);
        let results_json = serde_json::to_string(&results).unwrap();
        tracing::debug!("Derived results JSON: {}", results_json);
        for result in results {
            assert_eq!(result.service, SERVICE_TRNG.to_string());
            assert_eq!(result.src, SRC_DERIVED_TRNG.to_string());
            assert_eq!(result.bulk.is_none(), true);
        }
    }
}
