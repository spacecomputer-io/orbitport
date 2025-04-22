use std::{
    env,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

mod common;

const TEST_TOKEN: &str = "test_access_token";

/// Test e2e load tests.
#[tokio::test]
async fn test_e2e_load() {
    tracing_subscriber::fmt::init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or(TEST_TOKEN.to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    let rps = env::var("OPTEST_RPS")
        .unwrap_or("3".to_string())
        .parse()
        .unwrap_or(3);
    let total_req: usize = env::var("OPTEST_TOTAL_REQ")
        .unwrap_or("60".to_string())
        .parse()
        .unwrap_or(60);
    let threads: usize = env::var("OPTEST_THREADS")
        .unwrap_or("4".to_string())
        .parse()
        .unwrap_or(4);

    tracing::info!("Starting e2e happy path test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let mut handles = vec![];
        for i in 0..threads {
            tracing::info!("Starting thread {i}");
            let access_token = access_token.clone();
            let base_url = base_url.clone();
            let rps = rps;
            let total_req = total_req;
            let access_token = if access_token == TEST_TOKEN.to_string() {
                format!("test_access_token_{}", i + 1)
            } else {
                access_token
            };
            let handle = tokio::spawn(async move {
                if let Err(e) = run_test(access_token, base_url, rps, total_req).await {
                    tracing::error!("Thread {i} failed: {:?}", e);
                    return Err(e);
                }
                Ok(())
            });
            handles.push(handle);
        }
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {
                    tracing::info!("Thread completed successfully");
                }
                Ok(Err(e)) => {
                    tracing::warn!("Thread failed: {:?}", e);
                    return Err(e);
                }
                Err(e) => {
                    tracing::error!("Failed to join thread: {:?}", e);
                    return Err(common::E2EError::InternalError(e.to_string()));
                }
            }
        }
        tracing::info!("All threads completed successfully");
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

async fn run_test(
    access_token: String,
    base_url: String,
    rps: usize,
    total_req: usize,
) -> Result<(), common::E2EError> {
    let sent = Arc::new(AtomicUsize::new(0));
    let received = Arc::new(AtomicUsize::new(0));
    let interval = std::time::Duration::from_secs(1);

    loop {
        let sent_round = Arc::new(AtomicUsize::new(0));
        let received_round = Arc::new(AtomicUsize::new(0));
        let access_token = access_token.clone();
        let base_url = base_url.clone();

        let sent_round_clone = sent_round.clone();
        let received_round_clone = received_round.clone();
        let handle = tokio::spawn(async move {
            let mut handles = vec![tokio::spawn(async move {
                // Wait for the interval to complete, regardless of when the requests finish
                tokio::time::sleep(interval).await;
            })];
            for _ in 0..rps {
                let sent = sent_round_clone.clone();
                let received = received_round_clone.clone();
                let access_token = access_token.clone();
                let base_url = base_url.clone();

                handles.push(tokio::spawn(async move {
                    sent.fetch_add(1, Ordering::SeqCst);
                    match common::get_trng(&base_url, &access_token, None).await {
                        Ok(resp) => {
                            assert!(resp.data.len() > 0, "Response data is empty");
                            received.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => {
                            tracing::error!("Request failed: {:?}", e);
                        }
                    }
                }));
            }
            for handle in handles {
                if let Err(e) = handle.await {
                    tracing::error!("Failed to join thread: {:?}", e);
                }
            }
        });

        tokio::select! {
            _ = handle => {
                tracing::info!("All requests completed successfully");
            }
            _ = tokio::time::sleep(interval) => {
            }
        }

        tracing::info!(
            "Round completed: sent: {}, received: {}",
            sent_round.load(Ordering::SeqCst),
            received_round.load(Ordering::SeqCst)
        );

        sent.fetch_add(sent_round.load(Ordering::SeqCst), Ordering::SeqCst);
        received.fetch_add(received_round.load(Ordering::SeqCst), Ordering::SeqCst);

        if sent.load(Ordering::SeqCst) >= total_req {
            break;
        }
    }
    let sent = sent.load(Ordering::SeqCst);
    let received = received.load(Ordering::SeqCst);
    let success_rate = received as f64 / sent as f64;
    tracing::info!("Total requests sent: {}, received: {}, success rate: {}%", sent, received, success_rate * 100.0);
    assert!(sent > 0, "No requests sent");
    if sent != received {
        assert!(
            success_rate > 0.9,
            "More than 10% of requests failed or missed"
        );
    }
    Ok::<(), common::E2EError>(())
}
