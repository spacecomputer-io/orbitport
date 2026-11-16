# Verify without trusting us

Signatures from the KMS are standard ECDSA P-256 (or Ed25519, RSA) signatures. Once you have the public key, verification needs no SDK, no account and no call to Orbitport: plain `openssl` is enough. Pin the key's fingerprint to make sure it is the right one.

```bash
./run.sh
```

API calls: `kms.Sign` (`ECDSA_SHA_256`), `kms.GetPublicKey` on `examples-sign-p256`.
