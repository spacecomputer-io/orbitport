# JWTs signed by the KMS

An auth service mints ES256 JWTs with a KMS key instead of a key file on disk. The `kid` header carries the key version, so verifiers can pick the right public key after a rotation. Editing a claim breaks the signature.

```bash
./run.sh
```

API calls: `kms.GetKeyMetadata`, `kms.Sign` (`ECDSA_SHA_256`), `kms.GetPublicKey` on `examples-sign-p256`.

The KMS returns ECDSA signatures in DER. JWS uses the raw 64-byte `r||s` form, so the script converts between the two with `openssl asn1parse`.
