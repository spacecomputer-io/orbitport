# Suggested Schematics Changes

## Purpose

Handoff to the schematics author for the Orbitport `kms-capabilities-expansion`
implementation. These are proposed documentation changes, not edits to be
committed to schematics by us. The six original files have been restored.

Source repository: [spacecomputer-io/schematics](https://github.com/spacecomputer-io/schematics).
Base commit: `358f8e5e71ca2ae30fb9a5c21621e1184e7d7345`.
All paths below are relative to `infrastructure/kms/implemented-use-cases/transit/`.

## Proposed Changes by File

### disable-key.md

- Replace the claim that disabling works for every scheme with this delivery's
  TRANSIT-only boundary. Other engines return `Unimplemented` before mutation.
- Explain compatibility precisely: missing `key_state` is derived from the
  existing `enabled` boolean (true -> ENABLED, false -> DISABLED).
- Clarify that reading legacy metadata does not rewrite it and that
  unknown/inconsistent lifecycle state fails closed.

### enable-key.md

- State that this delivery supports TRANSIT only, rejecting other engines
  before changing metadata.

### schedule-key-deletion.md

- Replace the every-scheme claim with TRANSIT-only scheduling.
- State that other schemes are rejected before either metadata or index writes,
  so a key cannot be scheduled for an engine the worker cannot delete.

### cancel-key-deletion.md

- State that this delivery supports TRANSIT only, rejecting other engines
  before changing metadata.

### delete-scheduled-keys.md

- Change the sequence diagram's unsupported-scheme guard from "not TRANSIT or
  ETHEREUM" to "scheme != TRANSIT".
- Remove the Ethereum permanent-deletion branch from this delivery's diagram.
- Adjust retry and engine-support notes to describe Transit plus KV metadata
  operations, not Ethereum deletion.
- Mark Ethereum/PQC permanent deletion as outside this delivery.
- Scope the live-key deletion/backup wording to Transit. Retain the existing
  snapshot-retention caveat.
- Remove the unrelated Ethereum delete grant from the policy-change notes;
  retain the Transit and KV metadata delete grants and existing index/tombstone
  data permissions.

### list-keys.md

- Explicitly state that listing covers TRANSIT, ETHEREUM and PQC IDs belonging
  to the authenticated tenant only.
- Preserve one OpenBao LIST per page, with no per-key metadata reads.
- Correct the implication of constant cost: OpenBao returns the whole tenant
  name list on every page, so transfer, memory and sorting cost grow with key
  count, even though the number of backend calls stays at one.
- Explain that pagination is not a snapshot across concurrent creates/deletes.

## Existing Design Decisions Retained

The suggestions do not change the default list limit of 100 (range 1-1000),
local sorting and pagination, the 7-30 day deletion window/default 30 days,
CAS concurrency protection, cancellation returning DISABLED, tombstones,
permanent alias retirement, or the prescribed deletion ordering.

## Exact Proposed Patch

The patch below preserves every schematics edit that was made before restoring
the original files. It is supplied for the author's review, not automatically
applied or committed.

```diff
diff --git a/infrastructure/kms/implemented-use-cases/transit/cancel-key-deletion.md b/infrastructure/kms/implemented-use-cases/transit/cancel-key-deletion.md
index b895b54..9ecc999 100644
--- a/infrastructure/kms/implemented-use-cases/transit/cancel-key-deletion.md
+++ b/infrastructure/kms/implemented-use-cases/transit/cancel-key-deletion.md
@@ -1,5 +1,7 @@
 # Cancel Key Deletion (`kms.CancelKeyDeletion`)
 
+This delivery supports TRANSIT only; other engines return Unimplemented before mutation.
+
 Stops a scheduled deletion before its deletion date. The key returns to
 `DISABLED`, not `ENABLED`, so the owner decides explicitly when it is used
 again with `kms.EnableKey`.
diff --git a/infrastructure/kms/implemented-use-cases/transit/delete-scheduled-keys.md b/infrastructure/kms/implemented-use-cases/transit/delete-scheduled-keys.md
index 6d2c5b7..d9b5410 100644
--- a/infrastructure/kms/implemented-use-cases/transit/delete-scheduled-keys.md
+++ b/infrastructure/kms/implemented-use-cases/transit/delete-scheduled-keys.md
@@ -51,7 +51,7 @@ sequenceDiagram
                     Px->>B: forward
                     B-->>Px: 204
                     Note over S: Stale entry dropped (only this one),<br/>nothing else deleted, not a failure
-                else scheme not TRANSIT or ETHEREUM
+                else scheme != TRANSIT
                     Note over S: Cannot delete this key material:<br/>warn log, failed deletions counter + 1,<br/>record and entry kept
                 else this entry is current
                     rect rgb(227, 242, 253)
@@ -83,11 +83,6 @@ sequenceDiagram
                             Px->>B: forward
                             B->>B: Destroy every key version
                             B-->>Px: 204<br/>(400 if deletion_allowed is not set,<br/> or if the key vanished since the GET)
-                        else scheme == ETHEREUM
-                            S->>Px: DELETE /v1/ethereum/keys/{backend_key}
-                            Px->>B: forward
-                            B->>B: Destroy secp256k1 private key
-                            B-->>Px: 204 (also when the key is already gone)
                         end
                         Px-->>S: ok
                     end
@@ -169,13 +164,13 @@ sequenceDiagram
 - **Order matters.** Claim, tombstone, key material, metadata, then the
   index entry. If a step fails, the remaining records still point at the
   key and the next sweep retries. A retry finds earlier steps already done:
-  the Transit GET returns 404, and the Ethereum and KV deletes return 204
+  the Transit GET returns 404, and KV metadata deletes return 204
   for a missing entry.
   Writing the tombstone first means the alias is blocked before anything is
   removed, and deleting metadata before key material could leave key
   material in OpenBao with nothing pointing at it.
 - **Only known key engines.** The sweeper deletes key material for
-  `TRANSIT` and `ETHEREUM`. For any other scheme it counts a failed
+  `TRANSIT` only. For any other scheme it counts a failed
   deletion and keeps the record and the entry, so key material is never
   left behind without metadata.
 - **Aliases are used up for good.** `(KeyId, KeyVersion)` always names the
@@ -203,9 +198,8 @@ sequenceDiagram
 - **Verified on OpenBao 2.5.1** (the dev and prod version): Transit config
   200, Transit DELETE 204 (400 without `deletion_allowed`, 400 "not found"
   for a missing key), KV v2 `cas` mismatch 400, KV metadata DELETE 204 for
-  a missing entry. Ethereum DELETE returning 204 for a missing key is read
-  from the plugin source.
-- **Backups.** Transit and the Ethereum engine keep no copy after delete,
+  a missing entry. Ethereum/PQC permanent deletion is outside this delivery.
+- **Backups.** Transit keeps no live copy after delete,
   and the metadata delete removes every KV v2 version. OpenBao Raft
   snapshots are taken daily at 02:00 UTC and kept for 30 days in GCS, so a
   deleted key stays in backups for up to 30 days after its deletion. Client
@@ -214,7 +208,6 @@ sequenceDiagram
 - **Policy changes in `openbao-kms-module`** (`kms-api.hcl.tftpl`):
   - add `delete` to `transit/keys/*`
   - add `delete` to `orbitport-kv/metadata/kms/*`
-  - `orbitport-kv/data/kms/*` (tombstones, index) and Ethereum `delete` on
-    `ethereum/keys/*` are already granted
+  - `orbitport-kv/data/kms/*` (tombstones, index) are already granted
   - until the grant is applied, ship the image with the sweeper off
     (`ORBITPORT_KMS_DELETION_SWEEP_INTERVAL=0`)
diff --git a/infrastructure/kms/implemented-use-cases/transit/disable-key.md b/infrastructure/kms/implemented-use-cases/transit/disable-key.md
index 1f22b73..0644f64 100644
--- a/infrastructure/kms/implemented-use-cases/transit/disable-key.md
+++ b/infrastructure/kms/implemented-use-cases/transit/disable-key.md
@@ -2,7 +2,7 @@
 
 Turns a key off without touching its key material. A disabled key keeps its
 metadata, versions and public key, but every cryptographic operation on it is
-rejected until `kms.EnableKey` turns it back on. Works for every scheme.
+rejected until `kms.EnableKey` turns it back on. This delivery supports TRANSIT only; other engines return Unimplemented before mutation.
 
 Key states: `ENABLED` (default at `kms.CreateKey`), `DISABLED`,
 `PENDING_DELETION`.
@@ -86,5 +86,4 @@ any OpenBao key engine call.
 - **Writes use check-and-set.** Every metadata write (lifecycle calls and
   `kms.RotateKey`) sends `cas` with the version it read, so a concurrent
   rotation cannot undo a disable.
-- **Existing records.** A record without `key_state` reads as `ENABLED`,
-  because every key created so far has `enabled: true`.
+- **Existing records.** A record without `key_state` derives its state from the existing `enabled` boolean (true = ENABLED, false = DISABLED). Reading does not rewrite records. Unknown/inconsistent state fails closed.
diff --git a/infrastructure/kms/implemented-use-cases/transit/enable-key.md b/infrastructure/kms/implemented-use-cases/transit/enable-key.md
index 55d9eca..371e732 100644
--- a/infrastructure/kms/implemented-use-cases/transit/enable-key.md
+++ b/infrastructure/kms/implemented-use-cases/transit/enable-key.md
@@ -1,5 +1,7 @@
 # Enable Key (`kms.EnableKey`)
 
+This delivery supports TRANSIT only; other engines return Unimplemented before mutation.
+
 Turns a disabled key back on. All key versions are usable again exactly as
 before the disable. A key pending deletion cannot be enabled directly; it
 needs `kms.CancelKeyDeletion` first.
diff --git a/infrastructure/kms/implemented-use-cases/transit/list-keys.md b/infrastructure/kms/implemented-use-cases/transit/list-keys.md
index f7aa96d..d0d1df5 100644
--- a/infrastructure/kms/implemented-use-cases/transit/list-keys.md
+++ b/infrastructure/kms/implemented-use-cases/transit/list-keys.md
@@ -4,6 +4,8 @@ Lists the key IDs of the authenticated tenant, sorted, one page at a time.
 Every request makes exactly one OpenBao call, no matter how many keys the
 tenant has. Details per key come from `kms.GetKeyMetadata`.
 
+Listing includes TRANSIT, ETHEREUM and PQC IDs for the authenticated tenant only. There are no per-key metadata reads. OpenBao still returns the whole folder per page, so transfer, memory and sorting cost grow with tenant key count. Pages are not snapshots across concurrent changes.
+
 Example tenant contents: `kms:billing`, `kms:release-sign`, `kms:wallet`.
 
 ```mermaid
@@ -55,8 +57,7 @@ sequenceDiagram
 ## Notes
 
 - **Key IDs only.** The response carries no state, scheme or key spec. Clients
-  call `kms.GetKeyMetadata` per key for those, so the cost of one page never
-  grows with the number of keys.
+  call `kms.GetKeyMetadata` per key for those, so one page needs one backend call rather than one read per key. The whole folder is still transferred.
 - **All states are listed.** `ENABLED`, `DISABLED` and `PENDING_DELETION` keys
   appear. A key disappears from the list only once it has been deleted (see
   [delete-scheduled-keys.md](delete-scheduled-keys.md)).
diff --git a/infrastructure/kms/implemented-use-cases/transit/schedule-key-deletion.md b/infrastructure/kms/implemented-use-cases/transit/schedule-key-deletion.md
index d1d795a..6319605 100644
--- a/infrastructure/kms/implemented-use-cases/transit/schedule-key-deletion.md
+++ b/infrastructure/kms/implemented-use-cases/transit/schedule-key-deletion.md
@@ -4,7 +4,7 @@ Puts a key into `PENDING_DELETION` with a deletion date 7 to 30 days ahead
 (default 30). During that window the key cannot be used but can still be
 restored with `kms.CancelKeyDeletion`. Once the date passes, the deletion
 sweeper removes the key material and the metadata for good (see
-[delete-scheduled-keys.md](delete-scheduled-keys.md)). Works for every scheme.
+[delete-scheduled-keys.md](delete-scheduled-keys.md)). This delivery supports TRANSIT only; other engines are rejected before metadata/index writes.
 
 ```mermaid
 sequenceDiagram
```
