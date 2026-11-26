# Tamper-evident logs

At the end of each day, the SHA-256 of the audit log is signed with a KMS key. The signature and the key version are stored next to the log. Months later an auditor verifies the file with the matching public key version; removing or editing a single line fails the check.

```bash
./run.sh
```

API calls: `kms.Sign` (`DIGEST`), `kms.GetPublicKey` (with `Version`) on `examples-sign-p256`.
