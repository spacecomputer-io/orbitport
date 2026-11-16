# Signed config and feature flags

The release pipeline signs config and feature flags with a KMS key. The service verifies them with the public key before loading and keeps the last good config when the check fails. A direct edit to the ConfigMap is ignored.

```bash
./run.sh
```

API calls: `kms.Sign` (`ECDSA_SHA_256`), `kms.GetPublicKey` on `examples-sign-p256`.
