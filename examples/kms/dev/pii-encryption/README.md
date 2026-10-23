# Field-level PII encryption

The app encrypts sensitive columns (email, national ID) with the KMS before writing them to the database. A leaked dump or backup shows only ciphertext, and the app never holds a key.

```bash
./run.sh
```

API calls: `kms.Encrypt`, `kms.Decrypt` on the `examples-encrypt` key.

Each field is one call, which fits small values. For files and large blobs, see [large file encryption](../large-file-encryption/).
