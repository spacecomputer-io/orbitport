# Crypto-shredding for GDPR erasure

Each user's data is encrypted under their own data key, and only the small wrapped key is kept in a key table. To erase a user, delete every copy of their wrapped key. Their records may still sit in logs, replicas and old backups, but they can no longer be decrypted.

```bash
./run.sh
```

API calls: `kms.GenerateDataKey`, `kms.Decrypt` on `examples-encrypt`.

The guarantee holds only if every copy of the wrapped key is deleted, backups of the key table included.
