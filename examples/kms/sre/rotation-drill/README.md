# Rotation drill

Rotate a live encryption key and a live signing key, then show that nothing breaks: old ciphertext still decrypts, old signatures still verify against the old public key version, and new signatures carry the new version.

```bash
./run.sh
```

API calls: `kms.Encrypt`, `kms.Decrypt`, `kms.Sign`, `kms.RotateKey`, `kms.GetPublicKey` (with `Version`) on `examples-rotation-encrypt` and `examples-rotation-sign`.

Each run rotates both keys, so it costs two `RotateKey` operations.
