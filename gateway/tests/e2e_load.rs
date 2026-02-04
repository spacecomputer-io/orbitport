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

    tracing::info!(
        "Starting e2e load test with base_url: {base_url}; req per second (per thread): {rps}; total_req: {total_req}; threads: {threads}"
    );

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let mut handles = vec![];
        for i in 0..threads {
            tracing::debug!("Starting thread {i}");
            let access_token = access_token.clone();
            let base_url = base_url.clone();
            let rps = rps;
            let total_req = total_req;
            let unique_token = format!("{}_{}", access_token, i);

            let handle = tokio::spawn(async move {
                if let Err(e) = run_test(unique_token, base_url, rps, total_req).await {
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
                    tracing::debug!("Thread completed successfully");
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

    let mut batch_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    loop {
        if sent.load(Ordering::SeqCst) >= total_req {
            break;
        }

        let access_token = access_token.clone();
        let base_url = base_url.clone();
        
        // clone global counters to pass into async block
        let sent_clone = sent.clone();
        let received_clone = received.clone();

        // Spawn batch of requests for this round
        let handle = tokio::spawn(async move {
            let mut request_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

            for _ in 0..rps {
                let sent = sent_clone.clone();
                let received = received_clone.clone();
                let access_token = access_token.clone();
                let base_url = base_url.clone();

                request_handles.push(tokio::spawn(async move {
                    sent.fetch_add(1, Ordering::SeqCst);
                    match common::get_trng(&base_url, &access_token, None, None, None).await {
                        Ok(resp) => {
                            if resp.data.len() > 0 {
                                received.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Request failed: {:?}", e);
                        }
                    }
                }));
            }

            for h in request_handles {
                let _ = h.await;
            }
        });

        batch_handles.push(handle);

        tokio::time::sleep(interval).await;

        tracing::debug!(
            "Current status - sent: {}, received: {}",
            sent.load(Ordering::SeqCst),
            received.load(Ordering::SeqCst)
        );
    }

    // Wait for all batches to finish
    for h in batch_handles {
        let _ = h.await;
    }

    let sent_final = sent.load(Ordering::SeqCst);
    let received_final = received.load(Ordering::SeqCst);

    if sent_final == 0 {
        return Ok(());
    }

    let success_rate = received_final as f64 / sent_final as f64;
    tracing::info!(
        "Total requests sent: {}, received: {}, success rate: {:.2}%",
        sent_final,
        received_final,
        success_rate * 100.0
    );

    if sent_final != received_final {
        assert!(
            success_rate >= 0.9,
            "More than 10% of requests failed or missed (Sent: {}, Received: {})",
            sent_final,
            received_final
        );
    }
    Ok(())
}
