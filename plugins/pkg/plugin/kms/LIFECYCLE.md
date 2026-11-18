# Key Lifecycle and Listing

For the isolated integration test, start OpenBao 2.5.1 with
`bao server -dev -dev-no-store-token -dev-root-token-id=test-root -dev-listen-address=127.0.0.1:18391`.
Run `ORBITPORT_TEST_OPENBAO_ADDR=http://127.0.0.1:18391 ORBITPORT_TEST_OPENBAO_TOKEN=test-root go test ./pkg/plugin/kms -run TestTransitLifecycleOpenBaoIntegration`
from plugins/. Only use a disposable local dev instance, unique fixture mounts
are removed after the test. The no-store-token flag protects existing CLI logins.

`kms.ListKeys {Limit?, NextToken?}` returns sorted canonical key IDs across all
engines for the authenticated tenant. Limit defaults to 100 (range 1-1000).
One OpenBao LIST reads that tenant's existing metadata directory, validation,
sorting and pagination happen in the plugin, without per-key reads. The backend
still returns the whole folder. NextToken is opaque and null on the last page.
Listing is not a snapshot across concurrent changes, missing folders return [].

## Transit Lifecycle

These methods accept KeyId (canonical ID or alias), returning updated KeyMetadata:

| Method | Effect |
| --- | --- |
| `kms.DisableKey` | DISABLED, Enabled=false. Already disabled succeeds without a write. |
| `kms.EnableKey` | ENABLED/true. Pending deletion must first be cancelled. |
| `kms.ScheduleKeyDeletion` | PENDING_DELETION/false and DeletionDate. PendingWindowInDays is 7-30, default 30, returned in the response. Already pending is rejected. |
| `kms.CancelKeyDeletion` | Before the deadline and worker claim, clear the schedule and return DISABLED, not ENABLED. |

Other engines return Unimplemented before mutation. Transit crypto and rotation
check state before engine calls. Decrypt checks ciphertext ownership first.
Metadata/public-key reads remain allowed while material exists. In-flight requests
cannot be recalled, non-Transit crypto behavior is unchanged.

KeyMetadata adds nullable KeyState and DeletionDate. Legacy stored records derive
state from Enabled in memory, without a bulk migration. Invalid lifecycle records
fail closed. KV check-and-set (CAS) uses the metadata revision, not key version,
stale rotation writes cannot overwrite a newer disable/schedule. CAS conflicts
return Aborted: inspect current state before retrying mutations.

## Deletion Worker

ORBITPORT_KMS_DELETION_SWEEP_INTERVAL defaults to 1h, 0 disables it. One cancellable
goroutine per replica waits with up to 5% jitter, sweeps without overlap, then waits
again. No PAT, client request or credit charge is involved. Failed work is retried
on a later sweep. Future index deadlines are skipped without key metadata reads.

Schedule writes its index before CAS-updating metadata. An interrupted write keeps
the entry because the metadata may have committed. Cancel updates metadata first
and best-effort deletes only its original entry. Stale entries cannot delete keys.

Due deletion order is CAS claim, tombstone, Transit config deletion_allowed=true,
permanent Transit DELETE, all KV metadata versions, then index removal. Every
destructive reference is validated against its tenant. This uses neither Transit
soft-delete nor an OpenBao TTL. Tombstones contain no material/public key and
permanently block alias reuse by the tenant across all schemes.

Deletion is eligible at DeletionDate and completes on/after it when a sweep
succeeds. Cancellation is forbidden at/after the deadline even with sweeps off.
Infrastructure snapshots retain copies for up to 30 days, live deletion does not
erase backups immediately. Metrics orbitport_kms_deleted_keys_total and
orbitport_kms_failed_deletions_total have no tenant/key labels, lost claims and
stale entries are normal cleanup.

## Rollout

Apply the OpenBao permissions for Transit and KV metadata through openbao-kms-module
before enabling sweeps. Charts deliberately default the interval to 0. Deploy plugin, gateway,
then MCP, enable with 1h only after verification. The prepared global-infra v1.0.8
pin must not be applied before that policy-module release exists. No release,
deployment, commit or push is performed as part of preparing these changes.
