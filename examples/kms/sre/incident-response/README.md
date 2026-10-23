# Incident response

A CI runner is compromised. The attacker has its API token, not the signing key. Revoking the token in the dashboard ends their access, and one `RotateKey` call makes every later signature carry a new key version. Old releases keep verifying, and there is no key material to hunt down.

```bash
./run.sh
```

API calls: `kms.Sign`, `kms.RotateKey` on `examples-rotation-sign`. Token revocation happens in the dashboard.
