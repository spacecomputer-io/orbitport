use crate::storage::blockstore::{BlockError, Blockstore, Bucketstore};
use crate::structures::beacon::BeaconBlock;
use crate::structures::block::Block;

pub async fn create_beacon(
    beacon_block: BeaconBlock,
    bucketstore: impl Bucketstore + Send + Sync,
) -> Result<(String, String), BlockError> {
    let b = beacon_block.clone();
    match beacon_block {
        BeaconBlock::Genesis(data) => {
            let block = Block::try_from(b).map_err(|e| {
                tracing::error!("Failed to convert beacon to block: {}", e);
                BlockError::GetBlockError(format!("Failed to convert beacon to block: {}", e))
            })?;
            let (cid, publish_name) = bucketstore
                .add_bucket(&data.metadata.name, block.clone())
                .await?;
            Ok((cid, publish_name))
        }
        BeaconBlock::Block(_) => Err(BlockError::AddBlockError(
            "Cannot create a beacon block from a non-genesis block".to_string(),
        )),
    }
}

pub async fn add_beacon_block(
    beacon_name: &str,
    beacon_block: BeaconBlock,
    bucketstore: impl Bucketstore + Send + Sync,
    blockstore: impl Blockstore + Send + Sync,
) -> Result<String, BlockError> {
    let mut block = Block::try_from(beacon_block.clone()).map_err(|e| {
        tracing::error!("Failed to convert beacon to block: {}", e);
        BlockError::GetBlockError(format!("Failed to convert beacon to block: {}", e))
    })?;
    match beacon_block {
        BeaconBlock::Genesis(data) => {
            let (cid, publish_link) = bucketstore
                .add_bucket(&data.metadata.name, block.clone())
                .await?;
            tracing::info!(
                "Added genesis block {} to bucket {} with published link {}",
                cid.as_str(),
                beacon_name,
                publish_link
            );
            Ok(cid)
        }
        BeaconBlock::Block(_) => {
            let (_, last_path) = bucketstore.get_bucket(beacon_name).await?;
            let last_cid = last_path.clone().replace("/ipfs/", "");
            block.link = last_cid;
            let cid = blockstore
                .add_block(block, Some(beacon_name.to_string()))
                .await?;
            tracing::info!("Added block {} to bucket {}", cid.as_str(), beacon_name);
            Ok(cid)
        }
    }
}
