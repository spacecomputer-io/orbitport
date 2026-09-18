# Orbitport Plugin / MasterSeed

Derives per-request random seeds from a rolling pool of satellite-harvested
master seeds.

## Overview

Implements `MasterSeedPlugin` (`proto/plugins/masterseed.proto`) with a single
`GetSeeds(count)` RPC that returns `count` derived 32-byte seeds as hex.

The plugin maintains an in-memory pool of master seeds and refreshes it on a
ticker (`ORBITPORT_MASTERSEED_PERIOD`, default 3600s) by calling the
`aptosorbital` plugin's `GetTrng` RPC for a fresh 32-byte chunk. The pool is
capped at `ORBITPORT_MASTERSEED_MAX_SEEDS` (FIFO eviction).

Optional `ORBITPORT_DEFAULT_MASTER_SEEDS` provides boot-time seeds that are
salted with the process boot nonce (`SHA256(seed || BE(bootNanos))`) so each
instance starts from a distinct state even with identical config.

On each `GetSeeds` call the plugin picks a master seed uniformly at random
(rejection-sampled `crypto/rand`, no modulo bias), reserves an offset range
large enough for `count * TRNGSize` bytes, and derives the outputs at that
offset. The per-seed offset cursor advances atomically, so concurrent callers
never share output ranges. Requests above
`ORBITPORT_MASTER_SEED_MAX_COUNT_PER_REQUEST` are rejected to bound CPU and
gRPC response size.

Depends on the `aptosorbital` plugin being reachable at
`ORBITPORT_APTOS_PLUGIN`.

Configuration: see [CONTEXT.md → Plugin: `masterseed`](../../../../CONTEXT.md#plugin-masterseed).
