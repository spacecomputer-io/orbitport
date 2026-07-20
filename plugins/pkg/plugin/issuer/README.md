# Issuer plugin

Mints **Personal Access Tokens** (Model B of the auth migration): compact
ES256 JWS carrying `iss/aud/sub/jti/iat/exp` (+ `kms_tenant` when provided),
with the Transit key version — or a stable hash of the local key — as the
`kid` header. Serves the public **JWKS** over gRPC so verifiers (the auth
plugin, via the gateway's `/.well-known/jwks.json`) never talk to the key
store.

The dashboard backend owns the PAT lifecycle (metadata row whose id is the
`jti`, charge flow, revocation flags); this plugin owns claims assembly and
signing only. Revocation is enforced per-request on the account plugin's
Hold path, keyed by `jti` — a signed token cannot be un-issued.

## RPCs

| RPC | Purpose |
| --- | --- |
| `IssueToken(jti, subject, kms_tenant, expires_at)` | Returns the compact JWS. Fail-closed validation: jti/subject required, expiry must be future and under `ORBITPORT_ISSUER_MAX_TTL_DAYS` |
| `GetJwks()` | RFC 7517 JWK Set (public keys only), kid-selected by verifiers |

## Key custody (`ORBITPORT_ISSUER_SIGNER`)

- `local` (default): EC P-256 key in process memory, from
  `ORBITPORT_ISSUER_LOCAL_KEY_PEM` (SEC1 or PKCS#8 PEM) or generated
  ephemerally at startup with a loud warning — ephemeral means **every
  restart invalidates all outstanding PATs**. Tokens and JWKS are real
  ES256 either way; only custody differs from production.
- `transit`: OpenBao Transit via the OpenBao proxy — hash-then-sign
  (`/sign/<key>/sha2-256`, `prehashed=false`, `marshaling_algorithm=jws`,
  `key_version` pinned to the `kid` so rotation can't race), JWKS built
  from every published key version. The proxy injects the vault token;
  this plugin holds no OpenBao credentials. Live-tested against the dev
  compose stack (`ORBITPORT_ISSUER_LIVE_TEST=1 go test ./pkg/plugin/issuer/
  -run TestTransitLive` with the stack up).

Env reference: see the repo-root `CONTEXT.md`.
