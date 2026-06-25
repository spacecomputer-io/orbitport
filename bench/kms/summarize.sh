#!/usr/bin/env bash
# Turns the ghz JSON reports in $RESULTS into one markdown table per operation,
# with the full concurrency curve and a marker on the throughput ceiling
# (highest RPS with zero errors). Prints to stdout.
set -euo pipefail
RESULTS="${RESULTS:-bench/kms/results}"
MAXERR="${MAXERR:-10}" # rows above this Err% are saturated/poisoned — never the ceiling

rows=$(for f in "$RESULTS"/*.json; do
  [ -e "$f" ] || continue
  bn=$(basename "$f" .json); slug="${bn%-c*}"; conc="${bn##*-c}"
  jq -r --arg slug "$slug" --arg conc "$conc" '
    def pct($p): (.latencyDistribution[]? | select(.percentage==$p) | .latency);
    (.statusCodeDistribution // {}) as $s |
    ($s.OK // 0) as $ok |
    # ghz tears down connections at end of run (~1 per worker) -> benign "closed
    # network connection" errors. Exclude those; count only real failures
    # (e.g. OpenBao "context deadline exceeded") so Err% reflects saturation.
    ((.errorDistribution // {}) | to_entries) as $e |
    ([$e[] | select(.key | test("closed network connection")) | .value] | add // 0) as $benign |
    (([$e[] | .value] | add // 0) - $benign) as $err |
    [ $slug, ($conc|tonumber), (.rps // 0),
      ((pct(50) // 0)/1e6), ((pct(99) // 0)/1e6),
      (if ($ok+$err)>0 then 100*$err/($ok+$err) else 0 end)
    ] | @tsv' "$f"
done | sort -t$'\t' -k1,1 -k2,2n)

echo "# KMS benchmark results"
echo
echo "_RPS = requests/sec; latency in ms. Err% = real failures only (ghz's benign"
echo "end-of-run connection closes are excluded). Marker = max RPS among rows with"
echo "Err% <= ${MAXERR}; if an op has no such row it saturated at every tested concurrency._"
echo
printf '%s\n' "$rows" | awk -F'\t' -v maxerr="$MAXERR" '
  # p50==0 means the cell completed zero requests (in-flight closes only) -> fully
  # saturated, even though benign-close filtering leaves Err% at 0. Such a row is
  # neither clean nor a valid ceiling: force Err% to 100 and bar it from the marker.
  { slug=$1; n[slug]++; i=n[slug]; S[slug,i]=$0;
    if($4 > 0 && $6 <= maxerr && $3 > bestrps[slug]){ bestrps[slug]=$3; knee[slug]=i }
    if(!(slug in seen)){ seen[slug]=1; seq[++m]=slug } }
  END{
    # --- compute per operation (summary first): VM-time/op = 1/max-RPS (whole-VM occupancy at saturation) ---
    for(j=1;j<=m;j++){ if(bestrps[seq[j]]>maxb) maxb=bestrps[seq[j]]; ord[j]=j }
    for(p=1;p<=m;p++) for(q=p+1;q<=m;q++) if(bestrps[seq[ord[q]]]>bestrps[seq[ord[p]]]){t=ord[p];ord[p]=ord[q];ord[q]=t}
    print "## Compute per operation";
    print "";
    print "_VM-time/op = whole-VM time one op occupies at saturation (= 1/max-RPS, includes the WireGuard hop)._";
    print "_To cost it: $/op = VM-time/op(s) x (OpenBao-VM $/hour / 3600). Assumes the VM is dedicated to KMS._";
    print "";
    print "| Operation | max RPS | VM-time/op (ms) | rel. compute |";
    print "|---|---:|---:|---:|";
    for(x=1;x<=m;x++){ s=seq[ord[x]];
      if(bestrps[s]>0) printf "| %s | %.0f | %.2f | %.1f\xc3\x97 |\n", s, bestrps[s], 1000/bestrps[s], maxb/bestrps[s];
      else printf "| %s | \xe2\x80\x94 | N/A | N/A |\n", s; }
    print "";

    # --- per-op detail tables ---
    for(k=1;k<=m;k++){ s=seq[k];
      printf "## %s\n\n", s;
      print "| Conc | RPS | p50 ms | p99 ms | Err% | |";
      print "|---:|---:|---:|---:|---:|:--|";
      for(i=1;i<=n[s];i++){ split(S[s,i],a,"\t");
        mark=(i==knee[s])?"\xe2\x86\x90 max RPS":"";
        errd=(a[4]>0)?a[6]:100;
        printf "| %d | %.0f | %.2f | %.2f | %.1f | %s |\n", a[2],a[3],a[4],a[5],errd,mark; }
      if(knee[s]==0) printf "\n_no concurrency completed cleanly under %s%% errors (saturated throughout)._\n", maxerr;
      print ""; }
  }'
