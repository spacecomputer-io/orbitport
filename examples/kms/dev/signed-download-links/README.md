# Signed download links

The backend signs `<path>` and `<expires>` with an Ed25519 key in the KMS and puts the signature in the URL. The edge or storage layer checks the link with only the public key, so it holds no secret. Changing the path or the expiry makes the link fail, and expired links are refused.

```bash
./run.sh
```

API calls: `kms.GetPublicKey`, `kms.Sign` (`ED25519`) on `examples-sign-ed25519`. Verification needs OpenSSL 3.
