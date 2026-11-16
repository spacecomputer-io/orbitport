# Large file encryption

Envelope encryption: the KMS hands out a fresh data key per file, the file is encrypted locally, and only the wrapped data key is stored next to it. Large files never travel to the KMS. Decrypting means asking the KMS to unwrap the data key, so access to the master key still controls access to every file.

```bash
./run.sh            # 100 MB file
SIZE_MB=10 ./run.sh # smaller file
```

API calls: `kms.GenerateDataKey` (64 bytes), `kms.Decrypt` on `examples-encrypt`.

The file is encrypted with AES-256-CTR and authenticated with HMAC-SHA256 (encrypt-then-MAC), with separate halves of the 64-byte data key. The `openssl enc` command line is fine for a demo; in an application, use a crypto library with AES-GCM or similar.
