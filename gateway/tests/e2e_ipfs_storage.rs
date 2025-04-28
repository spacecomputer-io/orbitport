use std::env;

use gateway::storage::{
    blockstore::{Blockstore, Bucketstore},
    ipfs::IpfsBlockstore,
};
use gateway::structures::block::Block;

#[tokio::test]
async fn test_e2e_ipfs_storage() {
    tracing_subscriber::fmt::init();

    let ipfs_agent_url =
        env::var("OPTEST_IPFS_AGENT").unwrap_or("http://localhost:50002".to_string());

    tracing::info!("Starting e2e happy path test with ipfs_agent_url: {ipfs_agent_url}");

    let blockstore = IpfsBlockstore::new(&ipfs_agent_url).await.unwrap();

    let block = Block::new("test_block".to_string(), vec![1, 2, 3, 4, 5]);

    let block_hash = blockstore.add_block(block.clone()).await.unwrap();
    let retrieved_block = blockstore.get_block(&block_hash).await.unwrap();
    assert_eq!(block, retrieved_block);
    tracing::info!(
        "Successfully added and retrieved block from IPFS: {:?}",
        block
    );
    tracing::info!("Block hash: {}", block_hash);

    let now = std::time::SystemTime::now();
    let bucket_name = format!(
        "bucket{}",
        now.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    );
    let g_block = Block::new("test_genesis_block".to_string(), vec![1, 2, 3, 4, 5, 6]);
    let (g_cid, g_ipns) = blockstore
        .add_bucket(bucket_name.as_str(), g_block.clone())
        .await
        .unwrap();
    let retrieved_block = blockstore.get_bucket(bucket_name.as_str()).await.unwrap();
    assert_eq!(retrieved_block, g_block);
    tracing::info!("Successfully added bucket with IPNS link: '{g_ipns}' for CID '{g_cid}'");
}
