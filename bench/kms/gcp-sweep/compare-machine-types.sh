#!/usr/bin/env bash
# Aggregates results-gcp-<machine_type>.md files (each the unmodified output of
# bench/kms/summarize.sh, one per machine type, produced by the bench-kms-sweep
# workflow) into a $/op and RPS-per-$ comparison across machine types, using the
# formula already documented in bench/kms/README.md's "From numbers to price":
#   $/op = VM-time/op(s) x ($/hour / 3600)
#
# Never touches run.sh/summarize.sh — purely a downstream aggregator over
# their output.
#
# Usage: ./compare-machine-types.sh <results-dir> > results-gcp-compare.md
#   <results-dir> holds the results-gcp-<machine_type>.md files (default: cwd).
set -euo pipefail

RESULTS_DIR="${1:-.}"

# GCP on-demand list price, us-central1, Linux, USD/hour — captured 2026-07-02.
# Re-verify at https://cloud.google.com/products/compute/pricing before reuse;
# add a case here for any new candidate added to sweep-machine-types.sh.
price_for() {
  case "$1" in
    e2-medium)     echo 0.0335 ;;
    e2-standard-2) echo 0.0670 ;;
    e2-standard-4) echo 0.1340 ;;
    n2-standard-2) echo 0.0971 ;;
    n2-standard-4) echo 0.1942 ;;
    c3-standard-4) echo 0.2016 ;;
    *) echo "" ;;
  esac
}

shopt -s nullglob
files=("$RESULTS_DIR"/results-gcp-*.md)
shopt -u nullglob
# drop the comparison output itself if it's colocated in the same dir
filtered=()
for f in "${files[@]}"; do
  [ "$(basename "$f")" = "results-gcp-compare.md" ] && continue
  filtered+=("$f")
done
files=("${filtered[@]}")
if [ "${#files[@]}" -eq 0 ]; then
  echo "no results-gcp-*.md files found in $RESULTS_DIR — run the bench-kms-sweep workflow first" >&2
  exit 1
fi

# flat table: operation \t machine_type \t max_rps \t vm_time_ms \t price_per_hr
rows="$(mktemp)"
trap 'rm -f "$rows"' EXIT

for f in "${files[@]}"; do
  mt="$(basename "$f" .md)"; mt="${mt#results-gcp-}"
  price="$(price_for "$mt")"
  if [ -z "$price" ]; then
    echo "!! no price for machine type '$mt' (from $f) — add it to price_for() in this script" >&2
    continue
  fi
  awk -v mt="$mt" -v price="$price" '
    /^## Compute per operation/ { grab=1; next }
    grab && /^## / { grab=0 }
    grab && /^\|/ {
      if ($0 ~ /Operation/ || $0 ~ /^\|---/) next
      n = split($0, c, "|")
      op = c[2]; rps = c[3]; vmtime = c[4]
      gsub(/^[ \t]+|[ \t]+$/, "", op)
      gsub(/^[ \t]+|[ \t]+$/, "", rps)
      gsub(/^[ \t]+|[ \t]+$/, "", vmtime)
      if (rps == "\xe2\x80\x94" || vmtime == "N/A") next  # no clean ceiling at this size, skip rather than fabricate a price
      print op "\t" mt "\t" rps "\t" vmtime "\t" price
    }
  ' "$f" >> "$rows"
done

if [ ! -s "$rows" ]; then
  echo "no usable Compute-per-operation rows found across the results" >&2
  exit 1
fi

echo "# Machine-type comparison — KMS whole-stack"
echo
echo "_Pricing: GCP on-demand list price, us-central1, captured 2026-07-02 — re-verify at"
echo "https://cloud.google.com/products/compute/pricing before reuse. \$/op = VM-time/op(s) x (\$/hour / 3600),"
echo "per bench/kms/README.md's \"From numbers to price\". RPS-per-\$ = max RPS / \$/hour. Sorted by \$/op ascending"
echo "(cheapest first) within each operation._"
echo

for op in $(cut -f1 "$rows" | sort -u); do
  echo "## $op"
  echo
  echo "| Machine type | max RPS | VM-time/op (ms) | \$/hour | \$/op | RPS-per-\$ |"
  echo "|---|---:|---:|---:|---:|---:|"
  awk -F'\t' -v op="$op" '
    $1==op {
      dollar_op = ($4/1000) * ($5/3600)
      rps_per_dollar = $3/$5
      printf "%s\t%.0f\t%s\t%.4f\t%.8f\t%.2f\n", $2,$3,$4,$5,dollar_op,rps_per_dollar
    }' "$rows" | sort -t $'\t' -k5,5g | \
    awk -F'\t' '{ printf "| %s | %s | %s | $%.4f | $%.8f | %.2f |\n", $1,$2,$3,$4,$5,$6 }'
  echo
done

echo "---"
echo
echo "**Headline (most cost-effective, per \`createkey-rsa_4096\` — the strongest CPU-bound signal in the existing data):**"
echo
winner="$(awk -F'\t' '$1=="createkey-rsa_4096" { printf "%.10f\t%s\n", ($4/1000)*($5/3600), $2 }' "$rows" | sort -g | head -1)"
if [ -n "$winner" ]; then
  printf '`%s` — $%.8f per RSA-4096 CreateKey\n' "$(cut -f2 <<< "$winner")" "$(cut -f1 <<< "$winner")"
else
  echo "_no createkey-rsa_4096 data in the results (row may have been skipped as saturated at every candidate)._"
fi
