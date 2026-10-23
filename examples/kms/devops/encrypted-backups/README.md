# Encrypted backups

A nightly job compresses a database dump, encrypts it locally with a data key from the KMS, and uploads only ciphertext plus the wrapped key. Restoring needs a KMS call, so a leaked bucket or a stolen disk exposes nothing.

```bash
./run.sh
```

API calls: `kms.GenerateDataKey`, `kms.Decrypt` on `examples-encrypt`. The same works for Terraform state or any file.
