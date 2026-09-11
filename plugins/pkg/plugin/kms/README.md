# Orbitport Plugin / KMS

Multi-tenant Key Management Service. Wraps an OpenBao backend behind a small,
provider-agnostic gRPC contract so the gateway can offer encrypt / decrypt /
sign / key-agreement / data-key / key-rotation operations and a simple
agent-oriented key-store to clients without leaking the underlying engine.

## Overview

Implements `KmsPlugin` (`proto/plugins/kms.proto`) with crypto RPCs and
key-store RPCs:

- `CreateKey(alias, scheme, key_spec, key_usage, …)` — provisions a new key
  in the chosen provider and persists its metadata. Returns a stable
  `key_id = "kms:<alias>"` plus, for asymmetric keys, the `public_key` (and
  for Ethereum keys, the derived `address`).
- `Encrypt(key_id, plaintext, …)` / `Decrypt(ciphertext_blob, …)` —
  symmetric crypto (Transit only). The ciphertext is wrapped in a
  versioned, base64-JSON envelope (`v`, `scheme`, `key_id`, `provider_key`,
  `ciphertext`, `algorithm`) so `Decrypt` can route back to the right
  provider and tenant without the caller tracking it.
- `Sign(key_id, message, signing_algorithm, message_type)` — asymmetric
  signing. Transit handles the standard suites (ECDSA P-256/P-384, Ed25519,
  RSA-4096); the Ethereum provider handles secp256k1 with `RAW`, `DIGEST`,
  and `EIP191` message types; the PQC provider handles ML-DSA with `RAW`
  base64-encoded messages.
- `Encapsulate(key_id)` — ML-KEM key agreement. Computes locally from the
  stored PQC ML-KEM public key and returns a base64 ciphertext plus the
  caller-side base64 shared key.
- `Decapsulate(key_id, ciphertext)` — ML-KEM key
  agreement. Asks OpenBao to recover the server-side shared key with the stored
  PQC ML-KEM private key and returns the base64 shared key to the authenticated
  caller. The shared key is sensitive and must not be logged or persisted
  unprotected.
- `GenerateDataKey(key_id, data_key_spec | number_of_bytes)` — returns a
  fresh data key as `{plaintext, ciphertext_blob}` so callers can do
  envelope encryption (Transit only).
- `RotateKey(key_id)` — bumps the OpenBao key version (Transit only).
- `Put(name, secret)` — stores or overwrites arbitrary JSON key material in the
  KMS key-store under the authenticated client.
- `Export(name, wrap_ttl_seconds)` — returns a short-lived one-time OpenBao
  wrapping token for the named key-store entry. It does not return raw secret
  material directly.
- `Unwrap(name, wrap_token)` — redeems a wrapping token once and returns the
  stored JSON object if the token belongs to that key-store entry.
- `List(prefix)` / `Delete(name)` — list or delete key-store entries owned by
  the authenticated client.

The gateway-facing service proto (`proto/services/kms.proto`) covers the
consumer-facing crypto message shapes and adds `GetCapabilities`, which the
gateway answers locally without a plugin round-trip. Key-store JSON-RPC request
shapes live in the gateway adapter, while the internal plugin gRPC contract is
defined in `proto/plugins/kms.proto`.

## Providers

The plugin selects a provider per request based on the key's `scheme`. All
providers talk to the same OpenBao instance over HTTP.

### Transit

Wraps OpenBao's [Transit Secrets Engine](https://openbao.org/docs/secrets/transit/)
mounted at `ORBITPORT_KMS_TRANSIT_MOUNT` (default `transit`).

- Encryption: `AES_256_GCM96`.
- Signing: `ECDSA_P256`, `ECDSA_P384`, `ED25519`, `RSA_4096` (with PKCS1v15
  or PSS for RSA, message types `RAW` / `DIGEST`).
- Supports `GenerateDataKey` (`AES_128`, `AES_256`) and `RotateKey`.
- For asymmetric keys, the plugin fetches the OpenBao-exported PEM public
  key on `CreateKey` and returns it in `KeyMetadata.public_key`.

The previous `SYMMETRIC_DEFAULT` shorthand for encryption keys was removed
in favour of an explicit `AES_256_GCM96` spec — callers must name the
algorithm at create time.

### Ethereum

Wraps a custom OpenBao Ethereum Secrets Engine mounted at
`ORBITPORT_KMS_ETHEREUM_MOUNT` (default `ethereum`).

- Single key spec: `ECC_SECG_P256K1`, signing only.
- Signing algorithm: `ETHEREUM_SECP256K1` with message types `RAW`,
  `DIGEST`, and `EIP191` (the `personal_sign` standard). `RAW` expects
  base64-encoded bytes, which Orbitport Keccak-hashes before direct signing.
  `DIGEST` accepts either base64-encoded 32-byte digests or validated
  `0x`-prefixed hex digests.
- `CreateKey` returns both `public_key` and the derived Ethereum `address`.
- Encrypt / Decrypt / GenerateDataKey / RotateKey are intentionally rejected
  with `FailedPrecondition` — Ethereum keys are sign-only.

### PQC

Wraps the OpenBao PQC Secrets Engine mounted at `ORBITPORT_KMS_PQC_MOUNT`
(default `pqc`).

- Key specs: `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.
- Key agreement specs: `ML_KEM_768`, `ML_KEM_1024`.
- Signing algorithm: `ML_DSA`.
- Key agreement algorithm: `ML_KEM`.
- Message type: `RAW` only. Messages must be base64-encoded bytes.
- `CreateKey` returns the ML-DSA public key or ML-KEM encapsulation key as
  base64 in `KeyMetadata.public_key`. ML-KEM encapsulation uses that public
  key locally; ML-KEM decapsulation is delegated to OpenBao.
- Encrypt / Decrypt / GenerateDataKey / RotateKey are intentionally rejected
  with `FailedPrecondition` — PQC keys are sign/key-agreement only.

## Multi-tenancy and key naming

Every gateway request carries a `client_id` that the plugin uses to scope
keys. Tenant isolation is enforced in two places:

- **Backend key names** — `tenant_<sha256(client_id)[:16]>_<alias>`, so two
  tenants can pick the same alias and never collide in OpenBao.
- **Metadata storage** — written to OpenBao's KV v2 mount
  (`ORBITPORT_KMS_KV_MOUNT`, default `secret`) under
  `kms/metadata/<tenant>/<alias>`. Decrypt requests cross-check the blob's
  `key_id` against the requesting tenant's metadata, so a leaked ciphertext
  cannot be decrypted by a different client.

Aliases are user-chosen, validated to `[A-Za-z0-9._-]{1,128}`, and may not
start with the reserved `kms:` prefix. The canonical external identifier is
always `kms:<alias>`; both forms resolve to the same backend key.

## Key-store

The key-store is for agentic workloads that need a simple place to persist and
retrieve arbitrary key material or secrets through Orbitport KMS. It is
separate from operational KMS metadata:

- **Storage path** — OpenBao KV v2 mount `ORBITPORT_KMS_KEY_STORE_MOUNT`
  (default `key-store`) under `owners/<tenant>/<name>`.
- **Tenant scope** — the same authenticated `client_id` model as the existing
  KMS. The plugin hashes it into `tenant_<sha256(client_id)[:16]>`.
- **Names** — slash-separated paths such as `github/prod`; each segment must
  match `[A-Za-z0-9._-]+`. `.` and `..` are rejected. The default maximum
  depth is three path segments and can be changed with
  `ORBITPORT_KMS_KEY_STORE_MAX_DEPTH`.
- **Tenant isolation** — enforced by the authenticated `client_id`, validated
  slash-separated names, and OpenBao paths constructed as
  `owners/<tenant>/<name>` after each path segment is revalidated.
- **Export safety** — `Export` asks OpenBao to response-wrap the read response
  and returns only `WrapToken`, `TtlSeconds`, and `ExpiresAt`. `Unwrap` first
  checks the token's OpenBao wrapping lookup path, then redeems it once.
- **TTL semantics** — the TTL applies only to the temporary wrap token. The
  stored key-store entry remains durable until overwritten or deleted.
- **Versioning** — `Put` uses KV v2 and returns the new version. A second `Put`
  with the same name intentionally overwrites the stored value with a new
  version.
- **List depth** — recursive `List` traversal is bounded by the same configured
  maximum name depth so listing cannot recurse through an unbounded hierarchy.

Authorization is enforced in the KMS plugin with Cedar. The default policy
is embedded from `cedar/key_store_default.cedar` and adds policy control on top
of path-based tenant isolation. It permits the authenticated owner to call
`kms_keystore.Put`, `kms_keystore.Export`, `kms_keystore.Unwrap`,
`kms_keystore.List`, and `kms_keystore.Delete` on their own key-store
namespace. Operators can append Cedar policies with
`ORBITPORT_KMS_KEY_STORE_CEDAR_POLICY_PATH`; Cedar `forbid` policies override
the default permit and can be used to block operations such as deleting
production entries.

## Capabilities

`GetCapabilities` (gateway-side) advertises the supported scheme matrix:

| Scheme | Key specs | Signing | Key agreement | Encrypt / Decrypt | Data keys | Rotate |
| --- | --- | --- | --- | --- | --- | --- |
| `TRANSIT` | `AES_256_GCM96`, `ECDSA_P256`, `ECDSA_P384`, `ED25519`, `RSA_4096` | ECDSA SHA-256/384, Ed25519, RSASSA PKCS1v15 / PSS SHA-256 (`RAW`, `DIGEST`) | no | yes | `AES_128`, `AES_256` | yes |
| `ETHEREUM` | `ECC_SECG_P256K1` | `ETHEREUM_SECP256K1` (`RAW`, `DIGEST`, `EIP191`) | no | no | no | no |
| `PQC` | `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`, `ML_KEM_768`, `ML_KEM_1024` | `ML_DSA` (`RAW`) | `ML_KEM` | no | no | no |

Clients should call this once at startup to discover what they can ask for.

## Dependencies

This plugin requires a reachable OpenBao instance with the Transit, KV v2,
key-store KV v2, Ethereum, and PQC mounts already provisioned for the schemes
you use. Both compose stacks (`docker-compose.yaml`, `dev.docker-compose.yaml`) ship the full stack:
`openbao` (dev mode), `openbao-bootstrap` (one-shot init of mounts and
tokens), `openbao-proxy` (handles auth headers in front of OpenBao), and
this plugin as `plugin-kms`. The compose stacks build the Ethereum plugin and
the PQC plugin from sibling repos, then the bootstrap registers both plugin
mounts when their binaries are available in the OpenBao plugin directory. The
PQC builder uses the OpenSSL backend by default; set
`ORBITPORT_OPENBAO_PQC_BACKEND=wolfssl` to switch the OpenBao PQC plugin
binary. The KMS plugin waits for `openbao-bootstrap` to complete and
`openbao-proxy` to report healthy before it starts.

Configuration: see [CONTEXT.md → Plugin: `kms`](../../../../CONTEXT.md#plugin-kms).
