#!/usr/bin/env bash
# Interleaved mojo-pg vs pgx runs; prints per-round medians and the median across rounds.
# usage: ROUNDS=5 bench/run.sh   (needs build/bench, build/gobench, bench/gen_data.sql loaded; env DSN, BENCH_TABLE)
set -euo pipefail
cd "$(dirname "$0")/.."
ROUNDS=${ROUNDS:-5}
OUT=$(mktemp -d)
echo "uptime: $(uptime)"
for r in $(seq "$ROUNDS"); do
  build/bench | tee -a "$OUT/mojo"
  build/gobench | tee -a "$OUT/go"
done
med() { rg "$2" "$1" | sed -E 's/.*median ([0-9.]+) ms.*/\1/' | sort -g | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}'; }
echo "uptime: $(uptime)"
printf '%-8s %12s %12s\n' query mojo-pg pgx
for q in series synth; do printf '%-8s %9s ms %9s ms\n' "$q" "$(med "$OUT/mojo" "$q")" "$(med "$OUT/go" "$q")"; done
