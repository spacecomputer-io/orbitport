use tonic::transport::Channel;

use crate::storage::blockstore::{BlockError, Blockstore, Bucketstore};
use crate::structures::block::Block;

use crate::proto::ipfs::{AddRequest, GetRequest, ipfs_agent_client::IpfsAgentClient};

const NAMESPACE_IPFS: &str = "ipfs";
const NAMESPACE_IPNS: &str = "ipns";

/// A blockstore that uses IPFS as the underlying storage mechanism.
/// This blockstore uses the IPFS agent to get and put blocks.
/// It is used to abstract the underlying storage mechanism for blocks.
#[derive(Clone, Debug)]
pub struct IpfsBlockstore {
    client: IpfsAgentClient<Channel>,
}

impl IpfsBlockstore {
    /// Creates a new IPFS blockstore.
    /// It connects to the IPFS agent at the given URL.
    pub async fn new(ipfs_agent_url: &str) -> Result<Self, BlockError> {
        let client = IpfsAgentClient::connect(ipfs_agent_url.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to IPFS agent: {}", e);
                BlockError::RemoteStorageNotConnected
            })?;
        Ok(IpfsBlockstore { client })
    }
}

/// implementation of the Blockstore trait for IPFS
impl Blockstore for IpfsBlockstore {
    fn get_block(
        &self,
        link: &str,
    ) -> impl std::future::Future<Output = Result<(Block, String), BlockError>> + Send {
        let mut client = self.client.clone();
        let link = link.to_string();
        async move {
            let request = GetRequest {
                namespace: NAMESPACE_IPFS.to_string(),
                key: link,
            };
            match client.get(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    let block = Block::try_from(resp.data).map_err(|e| {
                        tracing::error!("Failed to convert block to raw data: {}", e);
                        BlockError::GetBlockError(format!(
                            "Failed to convert block to raw data: {}",
                            e
                        ))
                    })?;
                    let p = resp.path;
                    Ok((block, p))
                }
                Err(e) => Err(BlockError::GetBlockError(format!(
                    "Failed to get block: {}",
                    e
                ))),
            }
        }
    }

    fn add_block(
        &self,
        block: Block,
        publish_name: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, BlockError>> + Send {
        let mut client = self.client.clone();
        async move {
            let block_raw = block.try_into().map_err(|e| {
                tracing::error!("Failed to convert block to raw data: {}", e);
                BlockError::GetBlockError(format!("Failed to convert block to raw data: {}", e))
            })?;
            let request = AddRequest {
                data: block_raw,
                publish_name,
            };
            match client.add(request).await {
                Ok(response) => Ok(response.into_inner().cid),
                Err(e) => Err(BlockError::AddBlockError(format!(
                    "Failed to add block: {}",
                    e
                ))),
            }
        }
    }
}

/// implementation of the Bucketstore trait for IPFS
impl Bucketstore for IpfsBlockstore {
    fn get_bucket(
        &self,
        link: &str,
    ) -> impl std::future::Future<Output = Result<(Block, String), BlockError>> + Send {
        let mut client = self.client.clone();
        let link = link.to_string();
        async move {
            let request = GetRequest {
                namespace: NAMESPACE_IPNS.to_string(),
                key: link,
            };
            match client.get(request).await {
                Ok(response) => {
                    let resp = response.into_inner();
                    let block = Block::try_from(resp.data).map_err(|e| {
                        tracing::error!("Failed to convert block to raw data: {}", e);
                        BlockError::GetBlockError(format!(
                            "Failed to convert block to raw data: {}",
                            e
                        ))
                    })?;
                    let p = resp.path;
                    Ok((block, p))
                }
                Err(e) => Err(BlockError::GetBlockError(format!(
                    "Failed to get bucket: {}",
                    e
                ))),
            }
        }
    }

    fn add_bucket(
        &self,
        name: &str,
        genesis_block: Block,
    ) -> impl std::future::Future<Output = Result<(String, String), BlockError>> + Send {
        let mut client = self.client.clone();
        async move {
            let block_raw = Vec::<u8>::try_from(genesis_block).map_err(|e| {
                tracing::error!("Failed to convert block to raw data: {}", e);
                BlockError::GetBlockError(format!("Failed to convert block to raw data: {}", e))
            })?;
            let request = AddRequest {
                data: block_raw,
                publish_name: Some(name.to_string()),
            };
            match client.add(request).await {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    if resp.ipns_name.is_none() {
                        return Err(BlockError::AddBlockError("IPNS name is empty".to_string()));
                    }
                    let cid = resp.cid;
                    let ipns_name = format!("/ipns/{}", resp.ipns_name.unwrap());
                    tracing::info!(
                        "Successfully added bucket with ipns link: '{ipns_name}' for cid '{cid}'"
                    );
                    Ok((cid, ipns_name))
                }
                Err(e) => Err(BlockError::AddBlockError(format!(
                    "Failed to add bucket: {}",
                    e
                ))),
            }
        }
    }
}
