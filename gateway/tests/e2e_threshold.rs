use std::env;

mod common;

/// Test e2e threshold encryption.
#[tokio::test]
async fn test_e2e_threshold() {
    tracing_subscriber::fmt::init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    tracing::info!("Starting e2e threshold decryption test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let n_peers = 5;
    let n_threshold = 3;

    let mut t_committee = threshold::core::Committee::new(n_peers, n_threshold);
    let t_decryptor = threshold::core::ShareDecryptor::new(t_committee.pk_set.clone());
    let pk = t_committee.pk_set.public_key();
    let tpk = format!("threshold@{}", threshold::serialization::pubkey_hex(pk));

    let result = async {
        let n = 1;
        tracing::info!("Making {n} trng requests");
        for _ in 0..n {
            let resp =
                common::get_trng(&base_url, &access_token, None, None, Some(tpk.clone())).await?;
            assert!(!resp.data.is_empty(), "Response data is empty");
            let ciphertext_msg =
                threshold::core::CiphertextMsg::try_from(resp.data.clone()).unwrap();
            let ciphertext = ciphertext_msg.get_ciphertext();
            for i in 0..n_threshold + 1 {
                let actor = t_committee.get_actor(i);
                let dec_share = actor.decrypt_share(ciphertext.clone()).unwrap();
                t_decryptor.add_share(i, dec_share).unwrap();
            }
            let decrypted = t_decryptor.decrypt(ciphertext.clone()).unwrap();
            let decrypted_hex = hex::encode(decrypted);
            tracing::debug!("Decrypted hex: {decrypted_hex}");
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
