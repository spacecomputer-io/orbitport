# Orbitport Plugin / Auth

Fail-closed JWT validation plugin used by the gateway to authenticate incoming
requests.

## Overview

Implements the `AuthPlugin` gRPC service (`proto/plugins/auth.proto`) with a
single `ValidateToken(token)` RPC. Tokens are validated against an Auth0 tenant
using the `auth0/go-jwt-middleware` validator with RS256 and a JWKS caching
provider (5 min cache, 1 min allowed clock skew).

The plugin refuses to start if `ORBITPORT_AUTH0_DOMAIN` or
`ORBITPORT_AUTH0_AUDIENCE` is missing — this is deliberate so a misconfigured
deployment cannot silently run without authentication. For local development,
use the `authnoop` plugin instead.

Configuration: see [CONTEXT.md → Plugin: `auth`](../../../../CONTEXT.md#plugin-auth).
