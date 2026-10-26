# Encrypted config files

A values file with secrets is encrypted with a data key from the KMS. Only the ciphertext and the wrapped key are committed. The deploy pipeline decrypts it with the KMS right before use, so the plaintext never lands in git.

```bash
./run.sh
```

API calls: `kms.GenerateDataKey`, `kms.Decrypt` on `examples-encrypt`.
