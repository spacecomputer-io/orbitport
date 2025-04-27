use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::RwLock;

/// A block that contains data and a link to the next block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub link: String,
    pub data: Vec<u8>,
}

impl Block {
    /// Creates a new `Block` with the given link and data.
    pub fn new(link: String, data: Vec<u8>) -> Self {
        Block { link, data }
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        let block_bytes: Vec<u8> = TryFrom::try_from(self.clone()).unwrap_or(vec![]);
        hasher.update(&block_bytes);
        let hash = hasher.finalize();
        hex::encode(hash)
    }
}

/// Converts a `Block` to a string representation.
impl std::fmt::Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Block {{ link: {}, data: {} }}",
            self.link,
            hex::encode(&self.data)
        )
    }
}

/// Converts a `Block` from a `Vec<u8>` by deserializing it from JSON.
impl TryFrom<Vec<u8>> for Block {
    type Error = serde_json::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&bytes)
    }
}

/// Converts a `Block` to a `Vec<u8>` by serializing it to JSON.
impl TryFrom<Block> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        serde_json::to_vec(&block)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum BlockError {
    #[error("Failed to get block: {0}")]
    GetBlockError(String),
    #[error("Out of bounds")]
    OutOfBoundsError,
}

/// A trait for a blockstore that can get and put blocks.
/// This trait is used to abstract the underlying storage mechanism for blocks.
pub trait Blockstore {
    fn get_block(
        &self,
        link: &str,
    ) -> impl std::future::Future<Output = Result<Block, BlockError>> + Send;
    fn add_block(
        &self,
        block: Block,
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
            Ok(block) => {
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
    pub fn new() -> Self {
        InMemBlockstore {
            blocks: Arc::new(RwLock::new(HashMap::new())),
        }
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
    ) -> impl std::future::Future<Output = Result<Block, BlockError>> + Send {
        let blocks = self.blocks.clone();
        let link = link.to_string();
        async move {
            let blocks = blocks.read().await;
            if let Some(block) = blocks.get(&link) {
                Ok(block.clone())
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
    ) -> impl std::future::Future<Output = Result<String, BlockError>> + Send {
        let block_hash = block.hash();
        let blocks = self.blocks.clone();
        async move {
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
        let block2 = Block::new(block1.hash(), vec![4, 5, 6]);
        let block3 = Block::new(block2.hash(), vec![7, 8, 9]);

        let _ = blockstore.add_block(block1.clone()).await;
        let _ = blockstore.add_block(block2.clone()).await;
        let _ = blockstore.add_block(block3.clone()).await;

        let blocks = read_blocks(blockstore.clone(), block3.hash().as_str(), 2)
            .await
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], block3);
        assert_eq!(blocks[1], block2);

        let blocks = read_blocks(blockstore.clone(), block2.hash().as_str(), 5)
            .await
            .unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0], block2);
        assert_eq!(blocks[1], block1);
    }
}
