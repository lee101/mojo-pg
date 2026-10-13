#!/usr/bin/env bash
# Byte-compare mojo-pg (build/dump) against `psql -At` for one query, or a default suite when QUERY is unset.
# Connection: libpq env (PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE). Sessions are read-only.
#   QUERY='select ...' tests/parity.sh
#   QUERY="select ... where asset='x'" MQUERY='select ... where asset=$1' tests/parity.sh x   # mojo side uses bind params
# Needs: ./build.sh tests/dump.mojo; default suite needs bench/gen_data.sql loaded.
set -uo pipefail
cd "$(dirname "$0")/.."
DSN=${DSN:-"read_only=true application_name=mojo-pg-parity"}
OUT=${OUT:-$(mktemp -d)}
fail=0
cmpq() {
  local name=$1 q=$2 mq=$3; shift 3
  ./build/dump "$DSN" "$mq" "$@" > "$OUT/$name.mojo" 2> "$OUT/$name.err" || { echo "FAIL $name: $(cat "$OUT/$name.err")"; fail=1; return; }
  LC_ALL=C PGCLIENTENCODING=UTF8 PGDATESTYLE=ISO PGOPTIONS="-c default_transaction_read_only=on" psql -X -At -F$'\t' -v ON_ERROR_STOP=1 -c "$q" > "$OUT/$name.psql" || { echo "FAIL $name: psql"; fail=1; return; }
  if cmp -s "$OUT/$name.mojo" "$OUT/$name.psql"; then echo "ok   $name $(wc -l < "$OUT/$name.mojo") rows"
  else echo "FAIL $name (diff $OUT/$name.mojo $OUT/$name.psql)"; fail=1; fi
}
if [ -n "${QUERY:-}" ]; then
  cmpq query "$QUERY" "${MQUERY:-$QUERY}" "$@"
else
  T=${BENCH_TABLE:-ohlcv_daily}
  cmpq one_asset "select day,open,high,low,close,volume,source from $T where asset='asset_07' order by day" \
    "select day,open,high,low,close,volume,source from $T where asset=\$1 order by day" asset_07
  cmpq all_rows "select * from $T order by asset,day" "select * from $T order by asset,day"
  cmpq types "select g, g::float8/7, (g*1e-3)::float4, g::numeric/3, ('2000-01-01'::date + g), to_timestamp(g*86399.5), md5(g::text)::bytea, json_build_object('g',g), 'ü'||g from generate_series(-5000,5000) g" \
    "select g, g::float8/7, (g*1e-3)::float4, g::numeric/3, ('2000-01-01'::date + g), to_timestamp(g*86399.5), md5(g::text)::bytea, json_build_object('g',g), 'ü'||g from generate_series(-5000,5000) g"
fi
ro=$(./build/dump "$DSN" "create temp table mpg_ro_check(i int)" 2>&1); grep -q 25006 <<< "$ro" && echo "ok   read-only enforced" || { echo "FAIL read-only: $ro"; fail=1; }
exit $fail
