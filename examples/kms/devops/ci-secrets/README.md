# Secrets out of .env files

Credentials live in the KMS key-store, scoped to your account. A CI job fetches them at runtime, so the repo and the runner image hold no passwords. The only secret in CI is the Orbitport token.

```bash
./run.sh
```

API calls: `kms_keystore.Put`, `kms_keystore.Get` on `examples/ci/db`.
