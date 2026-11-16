# Software license keys

A vendor signs each license with an Ed25519 key in the KMS. The app ships with only the public key and checks the license offline. Editing the license (more seats, later expiry) breaks the signature.

```bash
./run.sh
```

API calls: `kms.GetPublicKey`, `kms.Sign` (`ED25519`) on `examples-sign-ed25519`. Verification needs OpenSSL 3.
