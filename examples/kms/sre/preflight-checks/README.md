# Preflight checks before deploy

Before rolling out, the pipeline reads the KMS capabilities and checks that every scheme, key spec and signing algorithm the release depends on is supported. A missing one stops the deploy before anything breaks in production.

```bash
./run.sh
```

API calls: `kms.GetCapabilities` (free).
