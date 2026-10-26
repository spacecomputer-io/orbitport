# Signed webhooks

The sender signs every webhook as `<timestamp>.<body>` with an ECDSA P-256 key in the KMS. The receiver fetches the public key once and verifies each event locally. A changed byte or a replayed timestamp fails.

```bash
./run.sh
```

API calls: `kms.GetPublicKey`, `kms.Sign` (`ECDSA_SHA_256`) on `examples-sign-p256`. Verification uses `openssl` only.
