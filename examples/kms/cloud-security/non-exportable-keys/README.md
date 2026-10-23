# Non-exportable keys vs. stored secrets

The same private key handled two ways. Stored as a key-store secret, it comes back in full to anyone with the token and stays usable after the token is revoked. As a KMS key, the API exposes only metadata and the public key, yet it signs; a leaked token is useful only until it is revoked.

```bash
./run.sh
```

API calls: `kms_keystore.Put`, `kms_keystore.Get`, `kms_keystore.Delete`, `kms.GetKeyMetadata`, `kms.Sign` (`ED25519`) on `examples-sign-ed25519`.

Use the key-store for secrets that other systems need in plaintext (API keys, passwords). Use KMS keys for anything that only needs to sign or encrypt.
