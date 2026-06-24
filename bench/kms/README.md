# KMS benchmark

End-to-end load test of the KMS gRPC service (client → plugin → OpenBao proxy →
OpenBao), used to inform customer pricing. Measures throughput and latency
percentiles per operation **and per key algorithm**, across a concurrency sweep,
so we can read off the throughput ceiling.

The KMS plugin is a thin shim over OpenBao, so these numbers reflect the whole
path — which is what we bill on.

## Pieces

- `plugins/cmd/kmsbench-bootstrap` — provisions tenants + keys and emits ghz data files.
- `run.sh` — runs [ghz](https://ghz.sh) for every (operation, algorithm) × concurrency.
- `summarize.sh` — turns the ghz JSON into a markdown table marking each op's max-RPS row.
- `Dockerfile` / `entrypoint.sh` — packages all of the above; runs bootstrap → sweep → table.
- `k8s/job.yaml` — runs the container in-cluster against the dev KMS.

## What it covers

| Operation | Algorithms |
|-----------|-----------|
| CreateKey | AES-256, ED25519, ECDSA P256/P384, RSA-4096, secp256k1 |
| Sign | ED25519, ECDSA P256/P384, RSA-4096, secp256k1 |
| Encrypt / Decrypt | AES-256-GCM96 |
| GenerateDataKey | AES-256 |
| RotateKey | transit key |

Load spans `TENANTS` distinct `client_id`s (default 50) to mirror multi-tenant
prod and exercise the per-tenant namespace path.

## Run locally

Start the KMS stack, then run the bench container on the same docker network:

```bash
docker compose up -d openbao openbao-proxy openbao-bootstrap plugin-kms
docker build -f bench/kms/Dockerfile -t kmsbench:local .
docker run --rm --network orbitport_default \
  -e KMS_ADDR=plugin-kms:50004 \
  kmsbench:local > bench/kms/results-local.md
```

The markdown table prints to stdout (here redirected to a file).

To iterate on the scripts without rebuilding the image, drive the host tools
directly — but the compose files only publish the KMS **metrics** port, not gRPC
`50004`. Publish gRPC first (add `- 50004:50004` under `plugin-kms.ports`, or
start a one-off forwarder), then:

```bash
go run ./plugins/cmd/kmsbench-bootstrap -addr localhost:50004 -out bench/kms/data
KMS_ADDR=localhost:50004 bench/kms/run.sh   # needs ghz on PATH
bench/kms/summarize.sh > bench/kms/results-local.md
```

## Run on GCP (dev)

KMS is ClusterIP-only, so the bench runs as an in-cluster Job. You drive it with
`kubectl` from your laptop — **no SSH into the cluster**.

1. Point kubectl at the dev cluster:

   ```bash
   gcloud container clusters get-credentials <dev-cluster> --region <region> --project <project>
   kubectl config current-context   # confirm it's the dev cluster
   ```

2. Build for the cluster arch (GKE nodes are amd64; a Mac is arm64) and push to
   ghcr (same registry/pull-secret the cluster already uses):

   ```bash
   docker build --platform linux/amd64 -f bench/kms/Dockerfile \
     -t ghcr.io/spacecomputer-io/orbitport/kmsbench:latest .
   docker push ghcr.io/spacecomputer-io/orbitport/kmsbench:latest
   ```

3. Run the Job and stream the table (the manifest already targets the dev KMS,
   `orbitport` namespace, and the `ghcr-secret` pull secret):

   ```bash
   kubectl apply -f bench/kms/k8s/job.yaml
   kubectl -n orbitport wait --for=condition=ready pod -l app=kmsbench --timeout=120s
   kubectl -n orbitport logs -f job/kmsbench | tee bench/kms/results-gcp.md
   kubectl -n orbitport delete job kmsbench   # or let ttlSecondsAfterFinished clean up
   ```

Compare `results-local.md` vs `results-gcp.md` — GCP adds the WireGuard hop to
the OpenBao VM, so expect higher latency / lower RPS. secp256k1 *is* covered here
(the ethereum mount exists on the cluster).

## Tuning

All env vars (defaults in parens): `KMS_ADDR`, `TENANTS` (50), `DURATION` (`10s`
per cell, ghz `-z`), `CONCURRENCY` (`1 2 5 10 20 50 100 200`), `CALL`
(`kmsapi.KmsPlugin`).

Each (op × concurrency) cell runs for `DURATION`, so total wall-clock is
predictable: `ops × concurrency-levels × DURATION`. This also keeps slow ops
(RSA-4096 keygen runs at ~1 RPS) bounded — they just complete fewer requests in
the window.

### Local results are CPU-bound — don't price off them

OpenBao runs in `-dev` mode in docker-compose and is single-process; under load
it pegs 6+ CPU cores on a laptop, so local RPS is low and noisy. On top of that
the local `openbao-proxy` (nginx) intermittently returns `502 Bad Gateway` to its
OpenBao upstream under sustained load — these show up as high `Err%` (rotate,
sign, createkey can read 50–90%). Both are local-dev artifacts: the GCP path is
WireGuard straight to a real OpenBao VM with no nginx dev proxy, so it won't see
either. Use local only to validate the harness; **get pricing numbers from the
GCP run**. The one locally-trustworthy signal is c=1 p50 latency for the cheap
ops (encrypt/decrypt/sign/gendatakey, ~3–10 ms) and the relative per-algo cost
ordering (RSA-4096 ≫ ECDSA ≈ ed25519).

Note: `RotateKey` shows errors at high concurrency because many requests rotate
the same per-tenant keys at once and OpenBao rejects the version conflicts —
that's a real property of concurrent rotation, not a harness bug. Raise
`TENANTS` to spread the load if you want a cleaner rotate ceiling.

## From numbers to price

Three axes, all read off the per-op tables:

- **Per-operation cost** = `monthly_$ / (max_RPS × 2.6e6)` where `monthly_$` is
  the KMS + OpenBao share of the GCP bill and `2.6e6` ≈ seconds/month. Do this
  per operation/algorithm — RSA-4096 sign is far more expensive per op than
  ed25519, and the table shows it.
- **Sustained-RPS tiers** = the max RPS per operation is the ceiling a tier can
  promise; read the p99 column at that row to set the SLO.
- **Per-key / storage** = the CreateKey/RotateKey rows give provisioning
  throughput; multiply expected keys/customer to size OpenBao storage (measure
  KV growth across a bootstrap run if a precise bytes-per-key figure is needed).
