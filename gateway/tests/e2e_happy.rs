use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

mod common;

use gateway::proto::services::kms::{
    CreateKeyResponse, DecryptResponse, EncryptResponse, GenerateDataKeyResponse,
    RotateKeyResponse, SignResponse,
};

fn unique_alias(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is earlier than UNIX_EPOCH")
        .as_nanos();
    format!("{prefix}-{now}")
}

/// Test e2e happy path.
#[tokio::test]
async fn test_e2e_happy() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e happy path test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let n = 1;
        tracing::info!("Making {n} trng requests");
        for _ in 0..n {
            let resp = common::get_trng(&base_url, &access_token, None, None, None).await?;
            assert!(!resp.data.is_empty(), "Response data is empty");
        }
        tracing::info!("Making {n} trng (bulk=10) requests");
        for _ in 0..n {
            let resp = common::get_trng(&base_url, &access_token, None, Some(10), None).await?;
            tracing::debug!("Bulk response: {:?}", resp);
            assert!(!resp.data.is_empty(), "Response data is empty");
            assert!(resp.bulk.is_some(), "Bulk is None");
            assert_eq!(resp.bulk.unwrap().len(), 10, "Bulk is not 10");
        }
        tracing::info!("All requests completed successfully");
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        tracing::error!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    tracing::info!("Test completed successfully");
}

#[tokio::test]
async fn test_e2e_happy_kms_ethereum_create_key_and_sign() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e KMS Ethereum RPC test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let alias = unique_alias("e2e-ethereum");
        let create_req_id = 41;
        let create_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": create_req_id,
            "method": "kms.CreateKey",
            "params": {
                "Description": "gateway e2e ethereum key",
                "Scheme": "ETHEREUM",
                "KeySpec": "ECC_SECG_P256K1",
                "KeyUsage": "SIGN_VERIFY",
                "Alias": &alias,
                "Tags": [
                    {
                        "TagKey": "test",
                        "TagValue": "e2e"
                    }
                ]
            }
        });

        let create_resp: CreateKeyResponse =
            common::rpc_success_result(&base_url, &access_token, create_req_id, create_payload)
                .await?;
        let metadata = create_resp.key_metadata.ok_or_else(|| {
            common::E2EError::AssertionFailed(
                "kms.CreateKey did not return KeyMetadata".to_string(),
            )
        })?;

        assert_eq!(
            metadata.key_id,
            format!("kms:{alias}"),
            "CreateKey returned unexpected KeyId"
        );
        assert_eq!(
            metadata.scheme, "ETHEREUM",
            "CreateKey returned the wrong Scheme"
        );
        assert_eq!(
            metadata.key_spec, "ECC_SECG_P256K1",
            "CreateKey returned the wrong KeySpec"
        );
        assert_eq!(
            metadata.key_usage, "SIGN_VERIFY",
            "CreateKey returned the wrong KeyUsage"
        );
        assert!(
            metadata.enabled,
            "CreateKey returned disabled KeyMetadata for a new key"
        );
        assert_eq!(metadata.alias, alias, "CreateKey did not return Alias");
        assert!(
            metadata.primary_version > 0,
            "CreateKey did not return a positive PrimaryVersion"
        );
        assert!(
            !metadata.creation_date.is_empty(),
            "CreateKey did not return CreationDate"
        );
        assert_eq!(metadata.tags.len(), 1, "CreateKey did not persist Tags");
        assert_eq!(metadata.tags[0].tag_key, "test", "TagKey was not preserved");
        assert_eq!(
            metadata.tags[0].tag_value, "e2e",
            "TagValue was not preserved"
        );

        let public_key = metadata.public_key.as_deref().ok_or_else(|| {
            common::E2EError::AssertionFailed(
                "CreateKey did not return Ethereum PublicKey".to_string(),
            )
        })?;
        let address = metadata.address.as_deref().ok_or_else(|| {
            common::E2EError::AssertionFailed(
                "CreateKey did not return Ethereum Address".to_string(),
            )
        })?;
        assert!(
            public_key.starts_with("0x") && public_key.len() > 2,
            "CreateKey returned invalid Ethereum PublicKey: {public_key}"
        );
        assert!(
            address.starts_with("0x") && address.len() == 42,
            "CreateKey returned invalid Ethereum Address: {address}"
        );

        let sign_req_id = 42;
        let sign_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": sign_req_id,
            "method": "kms.Sign",
            "params": {
                "KeyId": &alias,
                "Message": "Hello Orbitport",
                "SigningAlgorithm": "ETHEREUM_SECP256K1",
                "MessageType": "EIP191"
            }
        });

        let sign_resp: SignResponse =
            common::rpc_success_result(&base_url, &access_token, sign_req_id, sign_payload).await?;
        assert_eq!(
            sign_resp.key_id, metadata.key_id,
            "Sign returned a different KeyId"
        );
        assert_eq!(
            sign_resp.signing_algorithm, "ETHEREUM_SECP256K1",
            "Sign returned the wrong SigningAlgorithm"
        );
        assert!(
            sign_resp.signature.starts_with("0x"),
            "Sign did not return a hex signature"
        );
        assert!(
            sign_resp.signature.len() == 132,
            "Expected a 65-byte Ethereum signature, got {} chars",
            sign_resp.signature.len()
        );

        tracing::debug!("CreateKey metadata: {:?}", metadata);
        tracing::debug!("Sign response: {:?}", sign_resp);
        tracing::info!("KMS Ethereum CreateKey + Sign completed successfully");
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        tracing::error!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    tracing::info!("Test completed successfully");
}

#[tokio::test]
async fn test_e2e_happy_kms_transit_create_encrypt_decrypt_generate_data_key_and_rotate_key() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e KMS Transit RPC test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let plaintext = "SGVsbG8gT3JiaXRwb3J0";
        let alias = unique_alias("e2e-transit");

        let create_req_id = 51;
        let create_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": create_req_id,
            "method": "kms.CreateKey",
            "params": {
                "Description": "gateway e2e transit key",
                "Scheme": "TRANSIT",
                "KeySpec": "AES_256_GCM96",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "Alias": &alias,
                "Tags": [
                    {
                        "TagKey": "test",
                        "TagValue": "transit-e2e"
                    }
                ]
            }
        });

        let create_resp: CreateKeyResponse =
            common::rpc_success_result(&base_url, &access_token, create_req_id, create_payload)
                .await?;
        let metadata = create_resp.key_metadata.ok_or_else(|| {
            common::E2EError::AssertionFailed(
                "kms.CreateKey did not return KeyMetadata".to_string(),
            )
        })?;

        assert_eq!(
            metadata.key_id,
            format!("kms:{alias}"),
            "CreateKey returned unexpected KeyId"
        );
        assert_eq!(metadata.scheme, "TRANSIT", "CreateKey returned the wrong Scheme");
        assert_eq!(
            metadata.key_spec, "AES_256_GCM96",
            "CreateKey returned the wrong KeySpec"
        );
        assert_eq!(
            metadata.key_usage, "ENCRYPT_DECRYPT",
            "CreateKey returned the wrong KeyUsage"
        );
        assert!(metadata.enabled, "CreateKey returned disabled KeyMetadata");
        assert_eq!(
            metadata.primary_version, 1,
            "Transit CreateKey should start at PrimaryVersion 1"
        );
        assert!(
            !metadata.creation_date.is_empty(),
            "CreateKey did not return CreationDate"
        );
        assert_eq!(metadata.tags.len(), 1, "CreateKey did not persist Tags");
        assert_eq!(metadata.tags[0].tag_key, "test", "TagKey was not preserved");
        assert_eq!(
            metadata.tags[0].tag_value, "transit-e2e",
            "TagValue was not preserved"
        );
        assert_eq!(metadata.alias, alias, "CreateKey did not return Alias");
        assert!(
            metadata.public_key.is_none(),
            "Transit symmetric key should not expose PublicKey"
        );
        assert!(metadata.address.is_none(), "Transit key should not expose Address");

        let encrypt_req_id = 52;
        let encrypt_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": encrypt_req_id,
            "method": "kms.Encrypt",
            "params": {
                "KeyId": &alias,
                "Plaintext": plaintext,
                "EncryptionAlgorithm": "AES_256_GCM96"
            }
        });

        let encrypt_resp: EncryptResponse =
            common::rpc_success_result(&base_url, &access_token, encrypt_req_id, encrypt_payload)
                .await?;
        assert_eq!(
            encrypt_resp.key_id, metadata.key_id,
            "Encrypt returned a different KeyId"
        );
        assert_eq!(
            encrypt_resp.encryption_algorithm, "AES_256_GCM96",
            "Encrypt returned the wrong EncryptionAlgorithm"
        );
        assert!(
            !encrypt_resp.ciphertext_blob.is_empty(),
            "Encrypt returned an empty CiphertextBlob"
        );
        assert_ne!(
            encrypt_resp.ciphertext_blob, plaintext,
            "Encrypt returned plaintext instead of a ciphertext blob"
        );

        let decrypt_req_id = 53;
        let decrypt_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": decrypt_req_id,
            "method": "kms.Decrypt",
            "params": {
                "CiphertextBlob": encrypt_resp.ciphertext_blob,
                "KeyId": &alias,
                "EncryptionAlgorithm": "AES_256_GCM96"
            }
        });

        let decrypt_resp: DecryptResponse =
            common::rpc_success_result(&base_url, &access_token, decrypt_req_id, decrypt_payload)
                .await?;
        assert_eq!(
            decrypt_resp.key_id, metadata.key_id,
            "Decrypt returned a different KeyId"
        );
        assert_eq!(
            decrypt_resp.encryption_algorithm, "AES_256_GCM96",
            "Decrypt returned the wrong EncryptionAlgorithm"
        );
        assert_eq!(
            decrypt_resp.plaintext, plaintext,
            "Decrypt did not return the original plaintext"
        );

        let data_key_req_id = 54;
        let data_key_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": data_key_req_id,
            "method": "kms.GenerateDataKey",
            "params": {
                "KeyId": &alias,
                "DataKeySpec": "AES_256"
            }
        });

        let data_key_resp: GenerateDataKeyResponse =
            common::rpc_success_result(&base_url, &access_token, data_key_req_id, data_key_payload)
                .await?;
        assert_eq!(
            data_key_resp.key_id, metadata.key_id,
            "GenerateDataKey returned a different KeyId"
        );
        assert!(
            !data_key_resp.plaintext.is_empty(),
            "GenerateDataKey returned empty plaintext"
        );
        assert!(
            !data_key_resp.ciphertext_blob.is_empty(),
            "GenerateDataKey returned empty CiphertextBlob"
        );

        let decrypt_data_key_req_id = 55;
        let decrypt_data_key_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": decrypt_data_key_req_id,
            "method": "kms.Decrypt",
            "params": {
                "CiphertextBlob": data_key_resp.ciphertext_blob,
                "KeyId": &alias,
                "EncryptionAlgorithm": "AES_256_GCM96"
            }
        });

        let decrypt_data_key_resp: DecryptResponse = common::rpc_success_result(
            &base_url,
            &access_token,
            decrypt_data_key_req_id,
            decrypt_data_key_payload,
        )
        .await?;
        assert_eq!(
            decrypt_data_key_resp.key_id, metadata.key_id,
            "Decrypt for GenerateDataKey returned a different KeyId"
        );
        assert_eq!(
            decrypt_data_key_resp.plaintext, data_key_resp.plaintext,
            "Decrypting the generated data key did not return the generated plaintext"
        );

        let rotate_req_id = 56;
        let rotate_payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": rotate_req_id,
            "method": "kms.RotateKey",
            "params": {
                "KeyId": &alias
            }
        });

        let rotate_resp: RotateKeyResponse =
            common::rpc_success_result(&base_url, &access_token, rotate_req_id, rotate_payload)
                .await?;
        let rotated = rotate_resp.key_metadata.ok_or_else(|| {
            common::E2EError::AssertionFailed(
                "kms.RotateKey did not return KeyMetadata".to_string(),
            )
        })?;
        assert_eq!(
            rotated.key_id, metadata.key_id,
            "RotateKey returned a different KeyId"
        );
        assert_eq!(rotated.scheme, "TRANSIT", "RotateKey returned the wrong Scheme");
        assert_eq!(
            rotated.key_spec, "AES_256_GCM96",
            "RotateKey returned the wrong KeySpec"
        );
        assert_eq!(
            rotated.key_usage, "ENCRYPT_DECRYPT",
            "RotateKey returned the wrong KeyUsage"
        );
        assert!(
            rotated.primary_version > metadata.primary_version,
            "RotateKey did not increase PrimaryVersion"
        );

        tracing::debug!("Transit CreateKey metadata: {:?}", metadata);
        tracing::debug!("Transit Encrypt response: {:?}", encrypt_resp);
        tracing::debug!("Transit GenerateDataKey response: {:?}", data_key_resp);
        tracing::debug!("Transit RotateKey metadata: {:?}", rotated);
        tracing::info!(
            "KMS Transit CreateKey + Encrypt + Decrypt + GenerateDataKey + RotateKey completed successfully"
        );
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        tracing::error!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    tracing::info!("Test completed successfully");
}

#[tokio::test]
async fn test_e2e_happy_rpc() {
    _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e RPC test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let resp = common::rpc_ctrng_get(&base_url, &access_token, 5).await?;
        assert_eq!(resp.items.len(), 5, "RPC response did not honor chunks=5");
        for item in &resp.items {
            assert!(!item.value.is_empty(), "RPC response item value is empty");
            assert_eq!(
                item.src.as_deref(),
                Some("mixed"),
                "RPC response item src was not mixed"
            );
        }
        tracing::debug!("RPC response: {:?}", resp);
        tracing::info!("RPC request completed successfully");
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        tracing::error!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    tracing::info!("Test completed successfully");
}
