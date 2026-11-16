# Container image and SBOM signing

The pipeline signs the image digest and the SBOM with a KMS key. A deploy gate checks both with the public key before anything runs: a different image under the same tag or an edited SBOM is blocked.

```bash
./run.sh
```

API calls: `kms.Sign` (`ECDSA_SHA_256`, `DIGEST`), `kms.GetPublicKey` on `examples-sign-p256`. Verification needs OpenSSL 3.

The image digest is already a SHA-256, so it is signed as a digest directly. The manifest here is a stand-in; with a real registry, use the digest from `docker buildx imagetools inspect`.
