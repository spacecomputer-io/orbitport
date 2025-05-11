use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::structures::block::Block;

/// An error that can occur when working with blocks.
#[derive(Error, Debug, PartialEq)]
pub enum BlockError {
    #[error("Failed to add block: {0}")]
    AddBlockError(String),
    #[error("Failed to get block: {0}")]
    GetBlockError(String),
    #[error("Out of bounds")]
    OutOfBoundsError,
    #[error("Remote storage not connected")]
    RemoteStorageNotConnected,
}

/// A trait for a bucketstore that can get and put buckets that reference some underlying blocks.
pub trait Bucketstore {
    fn get_bucket(
        &self,
        name: &str,
    ) -> impl std::future::Future<Output = Result<(Block, String), BlockError>> + Send;

    fn add_bucket(
        &self,
        name: &str,
        genesis_block: Block,
    ) -> impl std::future::Future<Output = Result<(String, String), BlockError>> + Send;
}

/// A trait for a blockstore that can get and put blocks.
/// This trait is used to abstract the underlying storage mechanism for blocks.
pub trait Blockstore {
    fn get_block(
        &self,
        link: &str,
    ) -> impl std::future::Future<Output = Result<(Block, String), BlockError>> + Send;

    fn add_block(
        &self,
        block: Block,
        publish_name: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, BlockError>> + Send;
}

/// Reads blocks from the blockstore starting from the given head to a maximum depth or the end of the chain.
pub async fn read_blocks(
    blockstore: Arc<impl Blockstore>,
    head: &str,
    max_depth: usize,
) -> Result<Vec<Block>, BlockError> {
    let mut blocks = Vec::new();
    let mut current = head.to_string();
    let mut depth = 0;
    while depth < max_depth {
        match blockstore.get_block(&current).await {
            Ok((block, _)) => {
                if blocks.iter().any(|b: &Block| b.link == block.link) {
                    break; // Avoid cycles
                }
                blocks.push(block.clone());
                if block.link.is_empty() {
                    return Ok(blocks);
                }
                current = block.link;
                depth += 1;
            }
            Err(e) => {
                if e == BlockError::OutOfBoundsError {
                    return Ok(blocks);
                } else {
                    tracing::warn!("Failed to get block {}: {}", current, e);
                    return Err(e);
                }
            }
        }
    }
    Ok(blocks)
}

/// An in-memory blockstore implementation of the Blockstore trait.
/// This is a simple implementation that uses a HashMap to store blocks in memory.
#[derive(Clone, Debug)]
pub struct InMemBlockstore {
    blocks: Arc<RwLock<HashMap<String, Block>>>,
}

impl InMemBlockstore {
    /// Creates a new `InMemBlockstore`.
    pub fn new() -> Self {
        InMemBlockstore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    /// Returns the number of blocks in the blockstore.
    pub async fn size(&self) -> usize {
        self.blocks.read().await.len()
    }
    /// Removes the block with the given link.
    pub async fn clear(&self, link: &str) {
        let mut blocks = self.blocks.write().await;
        blocks.remove(link);
    }
    /// Clears all blocks in the blockstore.
    pub async fn clear_all(&self) {
        let mut blocks = self.blocks.write().await;
        blocks.clear();
    }
}

impl Default for InMemBlockstore {
    fn default() -> Self {
        Self::new()
    }
}

impl Blockstore for InMemBlockstore {
    fn get_block(
        &self,
        link: &str,
    ) -> impl std::future::Future<Output = Result<(Block, String), BlockError>> + Send {
        let blocks = self.blocks.clone();
        let link = link.to_string();
        async move {
            let blocks = blocks.read().await;
            if let Some(block) = blocks.get(&link) {
                Ok((block.clone(), link.to_string()))
            } else {
                Err(BlockError::GetBlockError(format!(
                    "Block not found: {}",
                    link
                )))
            }
        }
    }

    fn add_block(
        &self,
        block: Block,
        _: Option<String>,
    ) -> impl std::future::Future<Output = Result<String, BlockError>> + Send {
        let blocks = self.blocks.clone();
        async move {
            let block_hash = block.hash().ok_or(BlockError::GetBlockError(
                "Failed to hash block".to_string(),
            ))?;
            let mut blocks = blocks.write().await;
            blocks.insert(block_hash.clone(), block);
            Ok(block_hash)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_read_blocks() {
        let blockstore = Arc::new(InMemBlockstore::new());
        let block1 = Block::new("".to_string(), vec![1, 2, 3]);
        let block2 = Block::new(block1.hash().unwrap(), vec![4, 5, 6]);
        let block3 = Block::new(block2.hash().unwrap(), vec![7, 8, 9]);

        let _ = blockstore.add_block(block1.clone(), None).await;
        let _ = blockstore.add_block(block2.clone(), None).await;
        let _ = blockstore.add_block(block3.clone(), None).await;

        let blocks = read_blocks(blockstore.clone(), block3.hash().unwrap().as_str(), 2)
            .await
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], block3);
        assert_eq!(blocks[1], block2);

        let blocks = read_blocks(blockstore.clone(), block2.hash().unwrap().as_str(), 5)
            .await
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], block2);
        assert_eq!(blocks[1], block1);
    }
}
