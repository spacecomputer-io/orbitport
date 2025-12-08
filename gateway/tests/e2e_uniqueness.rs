use std::collections::HashSet;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

mod common;

#[tokio::test]
async fn test_e2e_uniqueness() {
    let verbose = env::var("OPTEST_VERBOSE").is_ok();
    // init logging without relying on it for the RNG output
    let _ = tracing_subscriber::fmt::try_init();

    let access_token = env::var("OPTEST_TOKEN").unwrap_or("test_access_token".to_string());
    let base_url = env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string());

    println!("Starting e2e uniqueness test with base_url: {base_url}");

    #[cfg(feature = "localtest")]
    let started = common::pre_test("happy").await.unwrap();

    let result = async {
        let iterations = 100;
        let bulk_size = 10;
        let total_expected = iterations * bulk_size;

        let mut unique_values: HashSet<String> = HashSet::with_capacity(total_expected);

        println!("Starting collection of {total_expected} RNG values...");

        for i in 1..=iterations {
            // Rate limit throttle (300ms delay) - less and we'll hit the rate limit
            sleep(Duration::from_millis(300)).await;

            let resp =
                common::get_trng(&base_url, &access_token, None, Some(bulk_size), None).await?;

            if resp.bulk.is_none() {
                return Err(common::E2EError::AssertionFailed(format!(
                    "Request {i}: Expected bulk response, got None"
                )));
            }

            let bulk_items = resp.bulk.unwrap();

            if bulk_items.len() != bulk_size {
                return Err(common::E2EError::AssertionFailed(format!(
                    "Request {i}: Expected {bulk_size} items, got {}",
                    bulk_items.len()
                )));
            }

            // Iterate and Print
            for (j, item) in bulk_items.iter().enumerate() {
                let val = &item.data;

                if verbose {
                    println!("[Req {:03} | Item {:02}] {}", i, j, val);
                }
                if !unique_values.insert(val.clone()) {
                    return Err(common::E2EError::AssertionFailed(format!(
                        "DUPLICATE FOUND! Value '{}' was received more than once.",
                        val
                    )));
                }
            }
        }

        println!("Successfully collected {total_expected} values. Checking final counts...");

        assert_eq!(
            unique_values.len(),
            total_expected,
            "Total unique count does not match expected count"
        );

        println!("SUCCESS: All {total_expected} values were unique. No collisions detected.");
        Ok::<(), common::E2EError>(())
    }
    .await;

    #[cfg(feature = "localtest")]
    if let Err(e) = common::post_test(started).await {
        eprintln!("Failed to clean up test environment: {:?}", e);
    }

    if let Err(e) = result {
        panic!("Test failed: {:?}", e);
    }

    println!("Test completed successfully");
}
