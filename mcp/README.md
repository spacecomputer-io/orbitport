# KMS MCP

This Rust executable implements ADR-0001 Step 1: your agent starts a local MCP
process over stdio; each tool call becomes one HTTPS request to the existing
Orbitport gateway `POST /api/v1/rpc`. KMS and secret storage remain remote.
The gateway owns authentication, tenant resolution, pricing and credit holds.
There is no hosted MCP endpoint, OAuth exchange or new cluster service.

## Install

Build from the repository root (Rust, a C build toolchain/CMake for TLS, and
`protoc` are required):

```sh
cargo build --locked --release -p kms-mcp
./target/release/kms-mcp --help
```

The release workflow publishes archives for macOS arm64/x64, Linux arm64/x64
and Windows x64 under `mcp-v*` tags. The release tag must match the version in
`mcp/Cargo.toml`. macOS and Linux archives (`kms-mcp-<target>.tar.gz`) contain
the executable and a POSIX file-based PAT launcher, `kms-mcp-from-file.sh`.
The Windows archive (`kms-mcp-x86_64-pc-windows-msvc.zip`) contains only
`kms-mcp.exe`.
Download your platform archive and `SHA256SUMS` from the same GitHub Release.
On Linux, verify with `sha256sum --check --ignore-missing SHA256SUMS`; on macOS,
compare `shasum -a 256 <archive>` with its entry. Verify provenance with:

```sh
gh attestation verify <archive> --repo spacecomputer-io/orbitport
```

Extract the executable to a user-owned location and configure its absolute
path in your harness. The macOS binaries are not signed or notarized. If the
archive was downloaded with a browser, macOS may block the executable; after
verifying it, clear the flag with `xattr -d com.apple.quarantine kms-mcp`.
Downloads with `gh release download` or `curl` are not flagged. Releases are built by CI; the executable is not an
OpenBao server or a replacement for the gateway.

## Configure

Follow [Client Setup](CLIENT_SETUP.md) for file-backed PAT storage and exact
configuration files/commands for Claude Desktop, Codex desktop, Claude Code
CLI and Codex CLI. It also covers manual terminal initialization,
`notifications/initialized`, `tools/list` and a live tool call.

The executable advertises the MCP server name `spacecomputer-kms`. The
optional file-based launcher loads `ORBITPORT_PAT` before starting `kms-mcp`;
the binary itself still reads credentials only from that environment variable.

The URL defaults to production, `https://op.spacecomputer.io`. HTTP is accepted
only for localhost/loopback development. The URL must be a base URL, not a
path ending in `/api/v1/rpc` or `/mcp`. Redirects are never followed.

Use the file-based launcher or your harness's secure environment-variable
mechanism rather than pasting a PAT into prompts or checked-in configuration.
A PAT cannot be provided as a CLI argument. Give agents separate named PATs
where the dashboard permits it, use a short practical lifetime, and revoke them in the
dashboard when access is no longer needed.

## Tools

Tool arguments retain the existing PascalCase JSON-RPC shapes. Call
`tools/list` for generated input/output schemas and `kms_get_capabilities`
for active algorithms. The latter is a gateway tool call, not a free local
protocol query. Current ML-KEM operations remain disabled.

| Tool | JSON-RPC method | Opt-in |
| --- | --- | --- |
| `kms_get_capabilities` | `kms.GetCapabilities` | default |
| `kms_create_key` | `kms.CreateKey` | default |
| `kms_get_key_metadata` | `kms.GetKeyMetadata` | default |
| `kms_get_public_key` | `kms.GetPublicKey` | default |
| `kms_encrypt` | `kms.Encrypt` | default |
| `kms_sign` | `kms.Sign` | default |
| `kms_rotate_key` | `kms.RotateKey` | default |
| `kms_keystore_put` | `kms_keystore.Put` | default |
| `kms_keystore_list` | `kms_keystore.List` | default |
| `kms_decrypt` | `kms.Decrypt` | `decrypt` |
| `kms_generate_data_key` | `kms.GenerateDataKey` | `generate-data-key` |
| `kms_encapsulate` | `kms.Encapsulate` | `encapsulate` (currently disabled) |
| `kms_decapsulate` | `kms.Decapsulate` | `decapsulate` (currently disabled) |
| `kms_keystore_get` | `kms_keystore.Get` | `keystore-get` |
| `kms_keystore_delete` | `kms_keystore.Delete` | `keystore-delete` |

Hidden tools are neither listed nor executable, even if an agent guesses
their names. The allowlist is fixed at startup and cannot be changed through
tool arguments. This protects against prompt injection; it is not a PAT scope.
Someone holding the PAT can still call the gateway directly.

Read-only lookups carry MCP annotations. Put and Delete are marked destructive:
Put overwrites the latest entry; Delete removes all versions. Annotations
are hints, and confirmation behavior depends on the harness.

Key-store secrets must be JSON objects and remain opaque JSON end to end,
preserving large integers and long decimals. Identity fields such as
`ClientId` and `kms_tenant` are refused; tenancy comes from the gateway.

## Protocol And Errors

The server handles legacy initialization (`2025-03-26`, `2025-06-18`,
`2025-11-25`) and modern `2026-07-28` discovery/per-request metadata.
Initialize, discovery, ping, listing and notifications are answered locally
without credits or gateway calls. Notifications produce no response.
Each successful tool invocation uses the same operation tag and price as a
manual call. The process keeps no persistent state or token cache.

Only JSON protocol messages are written to stdout. Diagnostics go to stderr;
raw arguments, responses and credentials are never logged. Input messages,
including framing, are limited to 64 KiB; gateway responses to 2 MiB.
The HTTP deadline is 30 seconds with a five-second connect timeout.
EOF exits after the active request finishes or times out; Ctrl-C interrupts.

| Failure | Action |
| --- | --- |
| Expired, invalid or revoked PAT | Create a new PAT in the dashboard |
| Insufficient credits | Top up the account |
| Account inactive | Contact your account administrator |
| Rate limit | Try again shortly |
| Backend outage | Try again later |
| KMS operation error | Check the resource, permissions and arguments |
| Timeout/interrupted response | Check whether the operation completed before retrying |

Requests are never automatically retried, including writes. Backend failure
details are sanitized. Successful tool results include text and raw structured
content; KMS failures use `isError: true`.

## External Prerequisites

Companion work is owned outside this repository:

- Dashboard: configurable five-active-PAT default; selectable 1–365 day
  lifetimes/default 90 days.
- Dashboard hold API: HTTP 403 with `code: ACCOUNT_INACTIVE`. Orbitport maps
  that exact code to `account_inactive`; a generic 400/403 is not treated as
  suspension. This distinction cannot be verified end to end until deployed.
- Existing frozen `kmsTenant` values must remain unchanged.
- Dashboard/Auth0: retire legacy customer credential endpoints and customer
  M2M apps as part of the coordinated PAT-only rollout; retain internal service
  clients used for PAT issuance and account-plugin access.

The main branch includes the PAT-only customer-authentication changes from
[PR #161](https://github.com/spacecomputer-io/orbitport/pull/161), merged as
`4486150`. Manual JSON-RPC calls remain supported with PATs; legacy Auth0
customer tokens are rejected. Internal Auth0 service-token authentication for PAT issuance remains
supported. The account plugin is required, and KMS tenancy always comes from
its Hold response, never a token claim or a legacy fallback. No MCP Helm
configuration or ingress path is required.

The suspension contract matches PR #161: dashboard HTTP 403
`code: ACCOUNT_INACTIVE` becomes gRPC `PermissionDenied("account_inactive")`,
then gateway HTTP 403 `error: account_inactive`. This branch is based on the
merged implementation and adds MCP regression tests without changing its
PAT-only behavior or restoring the former `ok=false` suspension representation.

## Dev Acceptance

Automated checks:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
make mcp-test
cd gateway
make test
```

Before phase 2, record these with real dev PATs and your target harness:

- Confirm default discovery and explicit opt-ins; guessed hidden tools fail.
- Create a signing key, sign a fixture and verify the signature externally.
- Create an encryption key and round-trip plaintext with Encrypt/Decrypt.
- Put/Get `{"max_wei":123456789012345678901234567890,"pi":3.14159265358979323846}`;
  verify exact numeric text in the wire response.
- Confirm tenant B cannot list or retrieve tenant A's entries.
- Compare credits/operation tags with equivalent manual JSON-RPC calls.
- Revoke a disposable PAT and confirm its next tool call fails.
- Test suspension after the dashboard error prerequisite is deployed.
- Confirm existing manual PAT callers still work, legacy Auth0 customer
  credentials return 401, and internal service-token PAT issuance still works.

No real dev credentials are bundled. Fixture success is not production/dev
acceptance. Record actual binary/image versions and outcomes in
[`ACCEPTANCE.md`](ACCEPTANCE.md); keep phase 2 blocked until this checklist passes.
