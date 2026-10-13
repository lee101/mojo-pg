#!/usr/bin/env bash
# Throwaway PG cluster on 127.0.0.1:$PORT with trust / password / md5 / scram users for test_auth.
# usage: tests/auth_cluster.sh start|stop   then: PG_AUTH=15433 build/test_pg
set -euo pipefail
PORT=${PORT:-15433}
BIN=${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}
BIN=${BIN:-$(dirname "$(command -v initdb)")}
DIR=${DIR:-${TMPDIR:-/tmp}/mojo-pg-auth}
SOCK=$DIR/sock
case ${1:-start} in
start)
  mkdir -p "$SOCK"
  if [ ! -d "$DIR/data" ]; then
    "$BIN/initdb" -D "$DIR/data" -U "${USER:-$(id -un)}" -A trust >/dev/null
    printf '%s\n' "local all all trust" "host all u_pass 127.0.0.1/32 password" "host all u_md5 127.0.0.1/32 md5" \
      "host all u_scram 127.0.0.1/32 scram-sha-256" "host all all 127.0.0.1/32 trust" > "$DIR/data/pg_hba.conf"
    fresh=1
  fi
  "$BIN/pg_ctl" -D "$DIR/data" -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" -l "$DIR/log" -w start >/dev/null
  if [ "${fresh:-0}" = 1 ]; then
    psql -h "$SOCK" -p "$PORT" -d postgres -qc "create role u_pass login password 'pw1'; create role u_scram login password 'pw3'; set password_encryption=md5; create role u_md5 login password 'pw2';"
  fi
  echo "auth cluster on 127.0.0.1:$PORT (trust user ${USER:-$(id -un)})";;
stop) "$BIN/pg_ctl" -D "$DIR/data" -m fast stop;;
esac
