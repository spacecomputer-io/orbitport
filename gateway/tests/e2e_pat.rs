//! End-to-end tests for the PAT surface against the running dev stack.
//!
//! Like every e2e_* suite here, these need the stack already up and fail with
//! connection-refused otherwise:
//!
//!   make devenv && make e2e-all
//!
//! Two regressions these guard, both found in review of the issuer work:
//!
//!   1. PAT issuance was mounted on the public HTTP port, reachable from the
//!      internet behind nothing but a static shared secret.
//!   2. KMS tenancy was read from the token's own `kms_tenant` claim, asserted
//!      once at mint time and trusted for the life of the token.
//!   3. The gateway republished the issuer's key set. That now belongs to the
//!      jwks plugin, on its own listener.
//!
//! The dev stack authenticates with authnoop, so these do not exercise PAT
//! *verification* at the gateway — that needs local-pat.compose.yaml, and the
//! signature itself is checked here against the published JWKS instead.

use std::env;

mod common;

const DEV_SHARED_SECRET: &str = "dev-only-issuer-secret";

fn public_url() -> String {
    env::var("OPTEST_URL").unwrap_or("http://localhost:8080".to_string())
}

/// Host port for the gateway's internal listener. Container-side it is 8081;
/// the dev stack publishes it on 8090 because ipfs-node already takes 8081.
fn internal_url() -> String {
    env::var("OPTEST_INTERNAL_URL").unwrap_or("http://localhost:8090".to_string())
}

/// The jwks plugin, which publishes the key set the gateway used to proxy.
/// Container-side it is 8080; the dev stack publishes it on 8091.
fn jwks_url() -> String {
    env::var("OPTEST_JWKS_URL").unwrap_or("http://localhost:8091".to_string())
}

fn shared_secret() -> String {
    env::var("ORBITPORT_PATISSUER_SHARED_SECRET").unwrap_or(DEV_SHARED_SECRET.to_string())
}

fn issue_body(jti: &str, claimed_tenant: &str, ttl_secs: i64) -> serde_json::Value {
    let exp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + ttl_secs;
    serde_json::json!({
        "jti": jti,
        "subject": "acct-e2e",
        "kmsTenant": claimed_tenant,
        "expiresAt": exp,
    })
}

async fn mint(jti: &str, claimed_tenant: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{}/internal/pat/issue", internal_url()))
        .bearer_auth(shared_secret())
        .json(&issue_body(jti, claimed_tenant, 3600))
        .send()
        .await
        .expect("internal listener unreachable — is the dev stack up?");
    assert_eq!(resp.status(), 200, "mint failed");
    resp.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .expect("no token in mint response")
        .to_string()
}

fn b64url_json(part: &str) -> serde_json::Value {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("JWT segment is not base64url");
    serde_json::from_slice(&raw).expect("JWT segment is not JSON")
}

/// The endpoint that mints year-long tokens must not answer on the port the
/// load balancer fronts, whatever the caller presents.
#[tokio::test]
async fn test_e2e_pat_issue_is_not_served_on_the_public_port() {
    let resp = reqwest::Client::new()
        .post(format!("{}/internal/pat/issue", public_url()))
        .bearer_auth(shared_secret())
        .json(&issue_body("e2e-public", "", 3600))
        .send()
        .await
        .expect("gateway unreachable — is the dev stack up?");

    assert_ne!(
        resp.status(),
        200,
        "the public port minted a PAT; issuance must stay on the internal listener"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains("token"),
        "the public port returned a token: {body}"
    );
}

/// The key set moved to the jwks plugin. The gateway routes and meters the
/// API; it no longer republishes the issuer's keys.
#[tokio::test]
async fn test_e2e_pat_jwks_is_not_served_by_the_gateway() {
    let resp = reqwest::get(format!("{}/.well-known/jwks.json", public_url()))
        .await
        .expect("gateway unreachable — is the dev stack up?");

    assert_ne!(
        resp.status(),
        200,
        "the gateway still serves JWKS; it belongs to the jwks plugin"
    );
}

#[tokio::test]
async fn test_e2e_pat_internal_listener_requires_the_shared_secret() {
    let client = reqwest::Client::new();
    let url = format!("{}/internal/pat/issue", internal_url());

    let wrong = client
        .post(&url)
        .bearer_auth("not-the-secret")
        .json(&issue_body("e2e-badsecret", "", 3600))
        .send()
        .await
        .expect("internal listener unreachable — is the dev stack up?");
    assert_eq!(wrong.status(), 401, "a bad secret must be rejected");

    let missing = client
        .post(&url)
        .json(&issue_body("e2e-nosecret", "", 3600))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 401, "a missing secret must be rejected");
}

/// Ties the minted token to the key the gateway publishes: transit signs with a
/// key version, the JWKS advertises it as `kid`, and a verifier must be able to
/// check one against the other. A kid mismatch or a bad public-key export would
/// break every downstream verifier while minting kept working.
#[tokio::test]
async fn test_e2e_pat_minted_pat_verifies_against_the_published_jwks() {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    let token = mint("e2e-jwks", "").await;

    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "not a compact JWS: {token}");
    let header = b64url_json(parts[0]);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JWT");
    let kid = header["kid"].as_str().expect("no kid header").to_string();

    let jwks: serde_json::Value = reqwest::get(format!("{}/.well-known/jwks.json", jwks_url()))
        .await
        .expect("JWKS unreachable — is the dev stack up?")
        .json()
        .await
        .expect("JWKS is not JSON");

    let jwk = jwks["keys"]
        .as_array()
        .expect("JWKS has no keys array")
        .iter()
        .find(|k| k["kid"].as_str() == Some(kid.as_str()))
        .unwrap_or_else(|| panic!("JWKS publishes no key for kid {kid}: {jwks}"));
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");

    let key = DecodingKey::from_ec_components(
        jwk["x"].as_str().expect("JWK has no x"),
        jwk["y"].as_str().expect("JWK has no y"),
    )
    .expect("JWK is not a usable EC key");

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[env::var("ORBITPORT_PATISSUER_AUD")
        .unwrap_or("https://op-dev.spacecomputer.io/api".to_string())]);
    validation
        .set_issuer(&[env::var("ORBITPORT_PATISSUER_ISS")
            .unwrap_or("https://auth.orbitport.local".to_string())]);

    let claims = decode::<serde_json::Value>(&token, &key, &validation)
        .expect("the published JWKS does not verify the minted PAT")
        .claims;
    assert_eq!(claims["sub"], "acct-e2e");
    assert_eq!(claims["jti"], "e2e-jwks");
}

/// The issuer caps how far ahead a token may expire, so a caller that reaches
/// the mint endpoint still cannot ask for an unbounded one.
#[tokio::test]
async fn test_e2e_pat_expiry_beyond_the_ceiling_is_refused() {
    let ten_years = 10 * 365 * 24 * 60 * 60;
    let resp = reqwest::Client::new()
        .post(format!("{}/internal/pat/issue", internal_url()))
        .bearer_auth(shared_secret())
        .json(&issue_body("e2e-longlived", "", ten_years))
        .send()
        .await
        .expect("internal listener unreachable — is the dev stack up?");

    assert_eq!(
        resp.status(),
        400,
        "the issuer accepted an expiry past its ceiling"
    );
}

/// KMS tenancy must follow the hold response, not the caller.
///
/// authnoop derives a distinct client_id per bearer token, so before this
/// change two different tokens landed in two different KMS namespaces. Both now
/// resolve to the tenancy accountnoop reports, which is what lets the second
/// token read the first one's key. That shared view is an artefact of the noop
/// plugin reporting one tenant for everyone — the property under test is that
/// the gateway took tenancy from the hold at all.
#[tokio::test]
async fn test_e2e_pat_kms_tenancy_follows_the_hold_not_the_caller() {
    let base_url = public_url();
    let alias = format!("e2e-tenancy-{}", std::process::id());

    let create = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9001,
        "method": "kms.CreateKey",
        "params": {
            "Description": "e2e tenancy probe",
            "Scheme": "TRANSIT",
            "KeySpec": "AES_256_GCM96",
            "KeyUsage": "ENCRYPT_DECRYPT",
            "Alias": &alias,
            "Tags": [],
            // Ignored by the gateway, which overwrites it with the resolved
            // tenancy. Present so a regression that trusted it would show up.
            "ClientId": "caller-supplied-should-be-ignored"
        }
    });
    let created = common::rpc_request(&base_url, "token-alpha", create)
        .await
        .expect("kms.CreateKey failed — is the dev stack up?")
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert!(
        created["error"].is_null(),
        "kms.CreateKey returned an error: {created}"
    );

    // A different bearer token, so authnoop reports a different client_id.
    let encrypt = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9002,
        "method": "kms.Encrypt",
        "params": {
            "KeyId": &alias,
            "Plaintext": "aGVsbG8=",
            "EncryptionAlgorithm": "AES_256_GCM96"
        }
    });
    let encrypted = common::rpc_request(&base_url, "token-beta", encrypt)
        .await
        .expect("kms.Encrypt failed")
        .json::<serde_json::Value>()
        .await
        .unwrap();

    assert!(
        encrypted["error"].is_null(),
        "a second caller could not reach the key, so tenancy came from the \
         caller rather than the hold response: {encrypted}"
    );
}
