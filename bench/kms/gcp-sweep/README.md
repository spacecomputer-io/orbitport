# KMS machine-type sweep

Answers "what's the most cost-effective machine type for our KMS" by running the
existing `bench/kms` harness (see `../README.md`) against several candidate GCP
machine types and comparing `$/op`.

## Why it's shaped this way

In this org, **all GCP access is CI-only**: applies and any use of a privileged
GCP identity happen inside GitHub Actions via Workload Identity Federation
impersonating a `runner-*` service account. Humans — even project owners — can't
create infra or touch Terraform state. So this sweep can't run from a laptop; it
runs as a dispatch workflow in the **infra** repo (`spacecomputer-global-infra`),
which is where the GCP identity lives.

The runner (`runner-sandbox`) can create/delete VMs but **can't** IAP-SSH into
them. So each VM **benchmarks itself** via a startup script (`bench-startup.sh`)
and returns its result table over the **serial console**, which the workflow
scrapes. No SSH, no Terraform, no state — the VMs are ephemeral and imperative
(`gcloud compute instances create/delete`).

Everything runs on **one VM per machine type** (whole stack: OpenBao + proxy +
plugin-kms + the kmsbench load generator co-located). That measures the cost of
running the entire KMS stack on a box of size X — see the contention note below.

## Pieces

| File | Where | Role |
|------|-------|------|
| `bench-kms-sweep.yaml` | `spacecomputer-global-infra/.github/workflows/` | dispatch workflow: loops machine types, creates/polls/deletes a VM each |
| `bench-startup.sh` | here (orbitport) | GCE startup script: clones orbitport, runs the KMS stack + kmsbench, prints results to the serial console |
| `compare-machine-types.sh` | here | aggregates the per-machine `results-gcp-<type>.md` into a ranked `$/op` / RPS-per-$ table |
| `Dockerfile`, `run.sh`, `summarize.sh`, `entrypoint.sh` | `../` | the bench itself — **unchanged**, reused as-is |

## Running

Dispatch the workflow (GitHub UI → Actions → "KMS machine-type bench sweep" →
Run workflow, or `gh`):

```bash
gh workflow run bench-kms-sweep.yaml \
  --repo spacecomputer-io/spacecomputer-global-infra \
  -f machine_types='e2-medium,e2-standard-2,e2-standard-4,n2-standard-2,n2-standard-4,c3-standard-4' \
  -f concurrency_levels='1 5 20 50' \
  -f tenants='50' \
  -f zone='us-central1-a'
```

Defaults match the above. `concurrency_levels` is trimmed vs. the full `bench/kms`
default (`1 2 5 10 20 50 100 200`) to keep the sweep under the 6h job cap; re-run
the front-runners with the full set for final numbers.

The workflow, per machine type: creates a VM in `snet-playground` (egress via the
existing Cloud NAT; no external IP, no SSH, no service account), waits for the
serial console to emit `===KMSBENCH_DONE===`, extracts the table into
`results-gcp-<type>.md`, and deletes the VM. A final step runs
`compare-machine-types.sh` and writes the ranked comparison to the **job summary**
and the `kms-bench-results` **artifact**.

**Teardown is automatic and belt-and-suspenders**: each VM is deleted after its
run, and an `EXIT` trap deletes any `kms-bench-*` VM still standing if the job
fails or is cancelled. As a sanity check after a run you can still confirm:

```bash
gcloud compute instances list --project playground-485020 --filter="name~^kms-bench-"
# expect zero rows
```

## Comparing after the fact

The workflow already produces `results-gcp-compare.md`, but you can re-aggregate
downloaded artifacts locally:

```bash
./compare-machine-types.sh <dir-with-results-gcp-*.md> > results-gcp-compare.md
```

`$/op = VM-time/op(s) × ($/hour ÷ 3600)`, per `../README.md`'s "From numbers to
price", against a static, date-stamped GCP list-price table in the script
(re-verify before reuse). Sorted cheapest-`$/op`-first per operation; the headline
reads off `createkey-rsa_4096`, the strongest CPU-bound signal.

## Caveats

- **Co-located load generator.** The kmsbench client shares the VM with OpenBao,
  so on small boxes it competes for CPU and the measured max-RPS is a *lower
  bound* on OpenBao's isolated ceiling. `entrypoint.sh` logs the bench client's
  own CPU/cgroup limits at startup (visible in the serial console) — if it's
  saturating, discount that machine's number. This is inherent to the single-VM
  design; it measures "throughput of the whole stack on one box of size X", which
  is a legitimate (if different) question from "OpenBao's isolated ceiling".
- **Cross-family is the point.** e2 vs n2 vs c3 differ by CPU generation/clock —
  which is exactly what matters for CPU-bound crypto (RSA-4096 keygen). That's why
  this uses real VMs rather than local docker CPU limits, which can't simulate it.
- **secp256k1 / ethereum rows self-skip** — the bench VM doesn't have the sibling
  `openbao-eth-plugin-poc` checkout, so that mount is absent (graceful skip in
  `docker/openbao/build-eth-plugin.sh` and `bootstrap.sh`). Everything else runs.
- **Clone token in VM metadata.** The startup script clones the private orbitport
  repo with a token passed via metadata — acceptable for a throwaway, no-inbound,
  minutes-lived VM. Harden to a signed-URL tarball or short-lived App token if
  these VMs ever grow longer-lived.
