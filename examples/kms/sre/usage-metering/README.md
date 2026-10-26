# Usage and metering

Every API call is metered per operation, and the dashboard shows the request counts and credits used. This demo runs a small burst of calls, then points to the dashboard to see them.

```bash
./run.sh
```

API calls: `kms.Encrypt`, `kms.Sign`, `kms.GetCapabilities`.
