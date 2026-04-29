# Orbitport Plugin / AuthNoop

Development-only drop-in replacement for the `auth` plugin that accepts every
token without validation.

## Overview

Implements the same `AuthPlugin` gRPC service as `auth` but always returns
`{ok: true}` from `ValidateToken`. It logs a warning at startup and on every
request so its use is impossible to miss in logs.

**Do not run this in production.** It exists so `dev.docker-compose.yaml` and
local test setups can skip Auth0 configuration. It replaces the old
`ORBITPORT_DEV_DISABLE_AUTH` toggle — disabling auth is now a matter of
selecting a different plugin binary rather than a runtime flag, making it
harder to ship to prod by accident.

Takes no configuration.
