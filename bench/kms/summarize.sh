#!/usr/bin/env bash
# Turns the ghz JSON reports in $RESULTS into one markdown table per operation,
# with the full concurrency curve and a marker on the throughput ceiling
# (highest RPS with zero errors). Prints to stdout.
set -euo pipefail
RESULTS="${RESULTS:-bench/kms/results}"

rows=$(for f in "$RESULTS"/*.json; do
  [ -e "$f" ] || continue
  bn=$(basename "$f" .json); slug="${bn%-c*}"; conc="${bn##*-c}"
  jq -r --arg slug "$slug" --arg conc "$conc" '
    def pct($p): (.latencyDistribution[]? | select(.percentage==$p) | .latency);
    (.statusCodeDistribution // {}) as $s |
    ($s.OK // 0) as $ok |
    ([$s | to_entries[] | select(.key!="OK") | .value] | add // 0) as $err |
    [ $slug, ($conc|tonumber), (.rps // 0),
      ((pct(50) // 0)/1e6), ((pct(99) // 0)/1e6),
      (if ($ok+$err)>0 then 100*$err/($ok+$err) else 0 end)
    ] | @tsv' "$f"
done | sort -t$'\t' -k1,1 -k2,2n)

echo "# KMS benchmark results"
echo
echo "_RPS = requests/sec; latency in ms. Err% includes ghz's benign end-of-run"
echo "connection closes (~1 per concurrent worker), so a few % is normal. Marker = max RPS._"
echo
printf '%s\n' "$rows" | awk -F'\t' '
  { slug=$1; n[slug]++; i=n[slug]; S[slug,i]=$0;
    if($3 > bestrps[slug]){ bestrps[slug]=$3; knee[slug]=i }
    if(!(slug in seen)){ seen[slug]=1; seq[++m]=slug } }
  END{
    for(k=1;k<=m;k++){ s=seq[k];
      printf "## %s\n\n", s;
      print "| Conc | RPS | p50 ms | p99 ms | Err% | |";
      print "|---:|---:|---:|---:|---:|:--|";
      for(i=1;i<=n[s];i++){ split(S[s,i],a,"\t");
        mark=(i==knee[s])?"\xe2\x86\x90 max RPS":"";
        printf "| %d | %.0f | %.2f | %.2f | %.1f | %s |\n", a[2],a[3],a[4],a[5],a[6],mark; }
      print ""; }
  }'
