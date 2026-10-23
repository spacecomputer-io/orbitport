# Secrets per environment

Secrets are stored under `examples/dev/` and `examples/prod/` with the same names, listed by prefix, and read by environment. Deploy code stays the same; only the prefix changes.

```bash
./run.sh
```

API calls: `kms_keystore.Put`, `kms_keystore.List`, `kms_keystore.Get`.
