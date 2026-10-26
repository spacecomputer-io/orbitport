# Release signing in CI

CI hashes the release artifact and asks the KMS to sign the hash. The runner only holds an API token, so a compromised runner can request signatures while the attacker has access but can never take the key. Customers verify with the published public key and plain `openssl`.

```bash
./run.sh
```

API calls: `kms.Sign` (`ECDSA_SHA_256`, `DIGEST`), `kms.GetPublicKey` on `examples-sign-p256`.

Signing the digest keeps large artifacts on the runner: only 32 bytes reach the KMS.
