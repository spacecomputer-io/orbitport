# Orbitport Plugin / Account

Per-request credit gating against the dashboard backend account service.

## Overview

Implements the `AccountPlugin` gRPC service (`proto/plugins/account.proto`)
with three RPCs that form a hold / settle / release lifecycle:

- `Hold(client_id, units, operation)` — deducts `units * ORBITPORT_ACCOUNT_CREDITS_PER_UNIT`
  credits against the account that owns `client_id` and returns a ledger ID the
  gateway uses to settle on success or release on failure.
- `Settle(ledger_id)` — commits a previous hold so the dashboard sweeper no
  longer treats it as an orphan to refund. Balance is unchanged (the hold
  already deducted). The gateway calls this on a **successful** request.
  Idempotent on the backend.
- `Release(ledger_id)` — refunds a previous hold. The gateway calls this on a
  **failed** request. Idempotent on the backend.

Only the gateway knows whether a request succeeded, so it must report every
terminal outcome — settle on success, release on failure. A hold that gets
neither (gateway crashed mid-flight) is an orphan the dashboard sweeper refunds.

The RPCs translate into HTTP calls against the dashboard backend's
`POST /service/credits/hold`, `POST /service/credits/hold/:ledgerId/settle`, and
`POST /service/credits/hold/:ledgerId/release`
endpoints, authenticated via an Auth0 M2M `client_credentials` token cached in
memory and refreshed in the background ~5 min before expiry.

## Fail modes

- **Missing required env**: plugin refuses to start (mirrors the `auth`
  plugin pattern). The required vars are `ORBITPORT_ACCOUNT_DASHBOARD_URL`,
  `ORBITPORT_ACCOUNT_AUTH0_DOMAIN`, `ORBITPORT_ACCOUNT_AUTH0_AUDIENCE`,
  `ORBITPORT_ACCOUNT_AUTH0_CLIENT_ID`, `ORBITPORT_ACCOUNT_AUTH0_CLIENT_SECRET`.
- **Initial M2M token fetch fails**: plugin refuses to start. A misconfigured
  M2M app or wrong audience can't silently no-op.
- **Dashboard returns 422 `INSUFFICIENT_CREDITS`**: `Hold` returns gRPC
  `FailedPrecondition` with `HoldResponse.Error = "insufficient_credits"`. The
  gateway maps this to HTTP 402.
- **Dashboard 5xx or unreachable**: `Hold` returns gRPC `Unavailable`. The
  gateway maps this to HTTP 503 (fail-closed).
- **`Settle` failure**: returned as `Unavailable`. The gateway logs and ignores.
  The hold stays unresolved, so the dashboard sweeper refunds it as an orphan —
  the request goes uncharged (revenue loss), never overcharged.
- **`Release` failure**: returned as `Unavailable`. The gateway logs and
  ignores; the hold stays unresolved and the dashboard sweeper refunds it as an
  orphan after the sweeper TTL. Same end state as a successful release.

## Dev tip

The plugin requires a reachable dashboard backend plus a real Auth0 M2M app.
For local development without a dashboard, leave `ORBITPORT_ACCOUNT_PLUGIN`
unset on the gateway — the credit-gate filter becomes a no-op and JWT
authenticated routes run normally.

For local dev against a non-TLS dashboard (e.g. `http://localhost:3000`),
set `ORBITPORT_ACCOUNT_ALLOW_INSECURE=true`. The plugin refuses to start
otherwise — the Auth0 M2M bearer would leak in plaintext. Never enable in
production.

## MVP simplifications

- `operation` tag sent to the dashboard is the HTTP-method bucket
  (`rpc` / `service_get` / `service_post`), not the semantic op
  (`trng` / `kms_sign`). The warp filter chain doesn't surface the matched
  path at hold time today. Tracked as a TODO in `gateway/src/server.rs`.
- Allowlist of routes that bypass the credit hold is `/healthz`. There's no
  `/version` route in the gateway.

Configuration: see [CONTEXT.md → Plugin: `account`](../../../../CONTEXT.md#plugin-account).
