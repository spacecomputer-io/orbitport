# Phase 1 Acceptance Record

## Build Identification

- Base: `origin/main` at `63ab44d` when the implementation branch was created.
- Synced with `origin/main` at `4486150` on 2026-11-05 after PR #161 merged.
- Branch: `kms-mcp-phase-1`.
- Reference implementation retained at commit `d3a94f0`.
- Binary package version: `0.1.0`.
- Executable: `kms-mcp`; advertised MCP server: `spacecomputer-kms`.
- Published binary tag: not released.
- Deployed gateway/plugin image versions for this change: not deployed.

## Automated Verification

Verified locally on macOS arm64 with Rust 1.96.0 and Go 1.26.0:

- Shared/local MCP tests: 19 passed on macOS, including executable HTTP tests
  for the Transit/key-store tool mappings, renamed CLI help and the POSIX
  file-backed PAT launcher. The five launcher tests are Unix-only.
- Gateway tests excluding live-stack E2E tests: 88 passed, including PR #161's
  11 account-filter tests and additional auth-status/suspension regressions.
  The old legacy-auth bypass tests were removed by that PR.
- Go account and auth plugin tests passed.
- Workspace Clippy across all targets with warnings denied passed.
- Workspace formatting and diff whitespace checks passed.
- After syncing with `4486150` on 2026-11-05, all 107 Rust tests above,
  Go auth/account tests, workspace Clippy and formatting checks passed again.
- Release executable built locally; `--version` reports `0.1.0`.
- Gateway Docker build stage passed with Rust 1.92 and the root workspace.
- Workflow YAML parses locally. Actionlint 1.7.12 passed before the executable
  rename; Actionlint and ShellCheck are not installed for the latest changes.
  The release workflow has not run on GitHub.
- Root lockfile retains all existing package versions; only the three new
  workspace packages and six Schemars dependencies were added.
- Executable/core names are now `kms-mcp` and `kms-mcp-core`. The file-backed
  PAT launcher is included in release archives; existing dependency versions
  are unchanged by the rename. Client configuration examples parse locally;
  this does not establish live acceptance in all four clients.

HTTP fixtures and subprocess tests do not establish real dashboard, OpenBao,
or harness acceptance. Other platform builds and release attestations remain
to be verified by the release workflow.

## Dev Acceptance

Status: pending.

Record the date, exact binary/tag, image versions and harness version here
when testing with real dev PATs. Do not record credentials or secret values.
All real-stack items in README's dev checklist remain pending, including
tenant isolation, billing parity, revocation and signature verification.

Suspension specifically depends on the dashboard returning HTTP 403 with
`code: ACCOUNT_INACTIVE`; until that is deployed it cannot be marked passed.

## PR #161 Integration

- PR #161 merged into main as `4486150`. Fast-forwarded this branch to that
  commit and restored the MCP work without conflicts, retaining additional
  MCP regression tests. Auth/account implementation changes now come from
  main rather than a duplicated patch in this branch.
- Suspension uses gRPC `PermissionDenied("account_inactive")`, not an
  `ok=false` response, so plugin and gateway behavior match that PR.
- Auth-plugin `Unauthenticated` maps to HTTP 401 `invalid_credential`;
  expiry keeps its separate `token_expired` mapping.
- The local executable reads `ORBITPORT_PAT` and performs no Auth0 login or
  token exchange. Credential validation remains at the gateway. Its transport
  needs no changes for the PAT-only gateway.
- Customer authentication is PAT-only. Legacy Auth0 customer tokens are
  rejected; internal Auth0 service-token authorization remains supported.
- The account plugin is required for customer calls. Client IDs pass through
  unchanged and tenancy always comes from Hold, with no legacy fallback.
- Manual JSON-RPC calls remain supported using PATs. The removed
  authentication/account bypasses have not been reintroduced.
- Final combined gateway/plugin images still require dev acceptance testing.

Phase 2 must not start until the dev acceptance checklist is completed.
