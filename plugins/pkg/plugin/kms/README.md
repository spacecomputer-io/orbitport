# Orbitport Plugin / KMS

Multi-tenant Key Management Service. Wraps an OpenBao backend behind a small,
provider-agnostic gRPC contract so the gateway can offer encrypt / decrypt /
sign / key-agreement / data-key / key-rotation / BYOK operations to clients
without leaking the underlying engine.

## Overview

Implements `KmsPlugin` (`proto/plugins/kms.proto`) with the core KMS RPCs:

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
- `GetImportParameters(key_spec, key_usage, hash_function)` — returns the
  Transit wrapping public key and wrapping parameters a client/SDK/HSM must
  use before importing externally generated key material.
- `ImportKeyMaterial(alias, key_spec, key_usage, ciphertext, exportable?, …)` —
  imports wrapped BYOK material into Transit. Orbitport never accepts
  plaintext private or symmetric key material. If `exportable` is omitted, it
  defaults to `true`; set it to `false` only when the key should be locked
  inside KMS permanently.
- `ImportKeyMaterialVersion(key_id, ciphertext, …)` — imports a new wrapped
  version for an existing imported Transit key.
- `RegisterExportWrappingKey(alias, public_key, …)` — registers a public-only
  RSA wrapping key as the destination for secure BYOK export.
- `ExportKeyMaterial(key_id, destination_key_id, …)` — calls Transit
  `byok-export` and returns wrapped ciphertext by version, never plaintext
  key material.
- `DeleteKey(key_id)` — permanently deletes Transit key material in OpenBao
  and marks Orbitport metadata disabled/deleted. The plugin marks metadata
  disabled before the backend delete so failures fail closed.

The gateway-facing service proto (`proto/services/kms.proto`) mirrors these
RPCs and adds `GetCapabilities`, which the gateway answers locally without a
plugin round-trip — it advertises the static capability matrix below.

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
- Supports BYOK import/export for `AES_256_GCM96`, `ECDSA_P256`, `ED25519`,
  and `RSA_4096`. BYOK import requires the client, SDK, or HSM to wrap the
  raw key material locally with the Transit wrapping key returned by
  `GetImportParameters`; OpenBao unwraps internally during import.
- Imported keys are marked `origin = "IMPORTED"`,
  `allow_plaintext_backup = false`, and `allow_rotation = false`. Import
  defaults to `exportable = true` so `ExportKeyMaterial` can later use Transit
  `byok-export`; callers can explicitly send `Exportable: false` to create a
  non-exportable key. OpenBao does not allow exportability to be enabled later
  for a non-exportable key, so this choice must be made at import time.
  Versioning for imported keys uses `ImportKeyMaterialVersion`, not `RotateKey`.
- Secure export uses Transit `byok-export` with a registered public-only RSA
  destination key (`origin = "PUBLIC_ONLY"`, `key_usage = "KEY_WRAP"`). The
  plaintext Transit export API is intentionally not exposed.

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
- BYOK import/export is intentionally `Unimplemented` until the Ethereum
  OpenBao plugin supports an equivalent wrapped import/export model.

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
- BYOK import/export is intentionally `Unimplemented` until the PQC OpenBao
  plugin supports an equivalent wrapped import/export model.

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

BYOK import/export uses the same tenant model. The gateway passes the
account-resolved KMS tenant into every internal plugin request, the plugin
derives tenant-scoped provider key names with
`tenant_<sha256(client_id)[:16]>_<alias>`, and metadata reads/writes stay
under that tenant namespace.

Aliases are user-chosen, validated to `[A-Za-z0-9.-]{1,128}`, and may not
start with the reserved `kms:` prefix. The canonical external identifier is
always `kms:<alias>`; both forms resolve to the same backend key.

## Authorization

Legacy Auth0 customer tokens preserve the existing KMS behavior. PATs can
carry OAuth-style scopes and KMS enforces them before calling OpenBao:

- `kms:*` permits all KMS operations.
- `kms:import` permits `GetImportParameters`, `ImportKeyMaterial`, and
  `ImportKeyMaterialVersion`.
- `kms:export` permits `RegisterExportWrappingKey` and `ExportKeyMaterial`.
- `kms:delete` permits `DeleteKey`.
- `kms:rotate` permits `RotateKey`.
- Existing operation scopes such as `kms:create`, `kms:encrypt`,
  `kms:decrypt`, and `kms:sign` authorize the matching methods.

When `ORBITPORT_KMS_CEDAR_POLICY_PATH` is set, KMS also evaluates that Cedar
policy as an additional policy layer. The shipped compose stacks point this
to `/etc/orbitport/kms/kms_default.cedar`, which permits same-tenant legacy
tokens and scoped PATs. Operators can replace the file to add stricter rules.
If `ORBITPORT_KMS_CEDAR_POLICY_PATH` is unset, no Cedar policy layer is
evaluated; tenant isolation and PAT scope checks still apply.

## Capabilities

`GetCapabilities` (gateway-side) advertises the supported scheme matrix:

| Scheme | Key specs | Signing | Key agreement | Encrypt / Decrypt | Data keys | Rotate | BYOK |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `TRANSIT` | `AES_256_GCM96`, `ECDSA_P256`, `ECDSA_P384`, `ED25519`, `RSA_4096` | ECDSA SHA-256/384, Ed25519, RSASSA PKCS1v15 / PSS SHA-256 (`RAW`, `DIGEST`) | no | yes | `AES_128`, `AES_256` | generated keys only | import/export for `AES_256_GCM96`, `ECDSA_P256`, `ED25519`, `RSA_4096` |
| `ETHEREUM` | `ECC_SECG_P256K1` | `ETHEREUM_SECP256K1` (`RAW`, `DIGEST`, `EIP191`) | no | no | no | no | no |
| `PQC` | `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`, `ML_KEM_768`, `ML_KEM_1024` | `ML_DSA` (`RAW`) | `ML_KEM` | no | no | no | no |

Clients should call this once at startup to discover what they can ask for.

## Dependencies

This plugin requires a reachable OpenBao instance with the Transit, KV v2,
Ethereum, and PQC mounts already provisioned for the schemes you use. Both
compose stacks (`docker-compose.yaml`, `dev.docker-compose.yaml`) ship the full stack:
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
