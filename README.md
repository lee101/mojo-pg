# mojo-pg

PostgreSQL v3 wire-protocol client written in Mojo. No Python, no libpq: sockets, protocol, auth and type decoding
are all Mojo; libssl/libcrypto are called via FFI for TLS and SCRAM. Text format, fully buffered results.

```mojo
from pg import Conn, Params, sqlstate
from p2.gomath import nan64

def main() raises:
    # password from PGPASSWORD (or put it in the URL); unset parts fall back to PG* env vars like libpq
    var c = Conn.connect("postgres://app@127.0.0.1:5432/market?read_only=true&statement_timeout=5000")
    var r = c.query("select day, open, high, low, close, volume, source from ohlcv_daily where asset = $1 order by day",
                    Params("asset_07"))
    for i in range(r.nrows):
        var day = r.date_days(i, 0)            # days since 1970-01-01
        var close = r.float_or(i, 4, nan64())  # numeric -> Float64, bit-identical to Go strconv.ParseFloat
        var src = r.text(i, 6)
    try:
        _ = c.query("select 1/0")
    except e:
        print(sqlstate(e), c.last_error.message)  # 22012 division by zero; connection is still usable
    c.close()
```

## Build

Requires Linux x86-64, OpenSSL (`libssl`/`libcrypto` dev symlinks), [pixi](https://pixi.sh), and the
`vendor/mojo-parity` submodule ([lee101/mojo-parity](https://github.com/lee101/mojo-parity): Go-exact float
formatting/parsing, sockets).

```
git clone --recursive https://github.com/lee101/mojo-pg && cd mojo-pg
pixi install                      # Mojo pinned in pixi.toml: ==1.2.0.dev2026100805 (max-nightly channel)
./build.sh                        # tests/test_pg.mojo -> build/test_pg
./build.sh path/to/app.mojo build/app
```

`build.sh` runs `mojo build --fp-mode contract=off -O3 -I src -I vendor/mojo-parity/src ... -lssl -lcrypto`.
It uses `pixi run mojo` by default; set `MOJO=/path/to/mojo` to use another compiler. Builds are serialised with
`flock` on `$MOJO_BUILD_LOCK` (default `${TMPDIR:-/tmp}/mojo-build.lock`). To use the library from another project,
pass the same `-I` flags and linker flags.

## API

```
Conn.connect(dsn: String) raises -> Conn            Conn.connect(cfg: Config) raises -> Conn
conn.query(sql) / conn.query(sql, params: Params) raises -> Result   # extended protocol, per-conn statement cache
conn.query_unnamed(sql, params) raises -> Result    # Parse/Bind/Describe/Execute/Sync, unnamed stmt
conn.prepare(name, sql) raises -> List[Int]         # param type OIDs
conn.query_prepared(name, params) raises -> Result  conn.deallocate(name) raises
conn.exec(sql) raises -> List[Result]               # simple protocol, multi-statement, one Result per statement
conn.exec1(sql) raises -> Result                    # last statement's Result
conn.cancel() raises    conn.close()    conn.tx_status() -> "I"|"T"|"E"    conn.param(name) -> String
conn.pid  conn.secret  conn.auth_method  conn.last_error: Notice  conn.notices  conn.notifications  conn.broken

Params(*vals: String)   .add(String|Int|Float64|Bool)   .add_null()

Result: nrows  fields: List[Field]  tag  ncols()  rows_affected()  col(name)  names()  type_oid(c)
  is_null(r,c)  cell_len(r,c)  raw(r,c) -> Span  text  int  float  float32  bool  numeric(str)
  date_days  timestamp_us  json  bytea  int_or  float_or  float_col(c)  int_col(c)  text_col(c)
Field: name table_oid column type_oid type_size typmod format
Notice: severity code message detail hint position where_ schema table column constraint routine
sqlstate(e: Error) -> String

parse_dsn(dsn) raises -> Config    # postgres://user:pass@host:port/db?k=v  and  key=value 'quoted \' value'
Pool(cfg, size) / Pool.open(dsn, size)   .acquire() raises -> Conn   .release(var c)   .query(sql[, params])   .close()
pg.conv: parse_f64 parse_int parse_bool parse_date_days parse_ts_us decode_bytea fmt_date days_from_civil civil_from_days
```

More examples:

```mojo
var rs = c.exec("begin; insert into t values (1); select count(*) from t; commit")   # 4 Results
var n = rs[2].int(0, 0)

var p = Params()
p.add(42); p.add(1.5); p.add(True); p.add_null(); p.add("text")
var r = c.query("select $1::int8, $2::float8, $3::bool, $4::text, $5", p)

_ = c.prepare("by_asset", "select close from ohlcv_daily where asset = $1")
var closes = c.query_prepared("by_asset", Params("asset_01")).float_col(0)   # List[Float64], NULL -> NaN

var pool = Pool.open("host=/var/run/postgresql dbname=market", 4)
var conn = pool.acquire()
...
pool.release(conn^)
```

Errors raise `Error("pg: ERROR: <message> (SQLSTATE xxxxx) DETAIL: ...")`; all fields are in `conn.last_error`.
Server errors drain to ReadyForQuery, so the connection stays usable (a failed transaction reports `tx_status() == "E"`
until ROLLBACK).

## Features

- TCP (`host`, `port`) and unix socket (`host=/var/run/postgresql`, empty host, or a full `.s.PGSQL.N` path).
- Auth: trust, cleartext, MD5, SCRAM-SHA-256 (libcrypto PBKDF2/HMAC/SHA256/RAND_bytes; server signature verified;
  auth downgrade after SASL start refused).
- Startup: user, database, application_name, options, client_encoding=UTF8, DateStyle=ISO, extra_float_digits=3;
  unknown DSN keys are sent as runtime params.
- DSN keys: host hostaddr port user password dbname application_name fallback_application_name options sslmode
  connect_timeout (s), `read_only` (adds `-c default_transaction_read_only=on`), `statement_timeout` (ms, adds
  `-c statement_timeout=`), `read_timeout` (ms, client-side socket deadline: on expiry a CancelRequest is sent, the
  connection is marked broken and `pg: read: i/o timeout` is raised), `statement_cache`. `PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE PGAPPNAME PGOPTIONS
  PGSSLMODE PGCONNECT_TIMEOUT` are defaults, as in libpq.
- TLS: `sslmode=prefer|require` (no verification), `verify-ca|verify-full` (system trust store or `SSL_CERT_FILE`,
  plus hostname). TCP only.
- Messages: ParameterStatus, BackendKeyData, ReadyForQuery, Error/NoticeResponse, NotificationResponse,
  NegotiateProtocolVersion, RowDescription, DataRow, CommandComplete, EmptyQueryResponse, ParameterDescription, NoData,
  PortalSuspended, CancelRequest.
- Per-call deadline: `pool.query(sql, params, timeout_ms)` / `conn.set_read_timeout_ms(ms)` bound a request end to end
  (statement_timeout alone does not cover network stalls or multi-query requests).
- Statement cache: first use pipelines Parse+Describe+Bind+Execute+Sync, later uses Bind+Execute+Sync. Evicts on
  0A000/26000 (one retry when idle). Max 512 statements, then unnamed.
- Types (text format): int2/4/8, float4/8, numeric (string or Float64), bool, text/varchar/char, date (incl. BC,
  ±infinity), timestamp/timestamptz (unix micros UTC, any session TimeZone incl. second offsets), json/jsonb, bytea
  (hex and escape). Anything else via `text()`.

### Float parsing

float4/float8/numeric cells decode to the same bits as Go `strconv.ParseFloat` (and as `float8send` for float
columns). `pg.conv.parse_f64` scans the cell once into a 64-bit mantissa + decimal exponent, then:

1. exact float fast path (mantissa < 2^53, |exp10| <= 22, Clinger);
2. Eisel-Lemire with the 128-bit power-of-ten table read in place from a global constant (no per-call materialisation);
3. for the near-halfway inputs Eisel-Lemire rejects, exact correctly-rounded `m * 10^e` in 128-bit integer
   arithmetic for -21 <= e <= 19 (covers practically every `numeric` price/volume value);
4. only inputs with more than 19 significant digits or extreme exponents fall back to the big-decimal parser in
   `mojo-parity` (`p2.gofmt`).

Float parameters are formatted like Go `strconv.FormatFloat(x, 'g', -1, 64)` (shortest round-trip).

## Limits / known gaps

- Text format only (params and results); results are fully buffered (one memcpy per DataRow, 8 B/cell index).
  No cursors, no row-limited portals, no streaming row callback.
- No COPY (COPY TO output is discarded, COPY FROM is answered with CopyFail). No pipelining across calls, no
  multi-host failover (first host is used), protocol 3.0 only.
- SCRAM: no SASLprep (non-ASCII passwords must already be NFKC), no channel binding (-PLUS). No GSS/SSPI/Kerberos, no
  client certificates, no `.pgpass`, no service files.
- `DateStyle` must stay ISO for the date/time decoders.
- Thread-safety: `Conn` and `Pool` are not thread-safe. One `Conn` per thread, or guard a `Pool` with a lock;
  `Pool.acquire` raises when all conns are out (no waiting).
- No binary-format decoders, arrays, composite types, ranges, intervals, uuid helpers (read them with `text()`).
- Linux only so far; tested on x86-64 with PostgreSQL 17 and 18.
- The pinned compiler is a Mojo nightly; newer nightlies may need small source changes, and old nightlies
  can disappear from the channel.

## Tests

The suite needs a database (default `mojo_pg_test`) reachable both over TCP (`127.0.0.1:$PGPORT`) and a unix socket
(`$PG_SOCKET_DIR`, default `/var/run/postgresql`), as a user that can create temp tables. Connection settings come
from the usual env vars.

| env | default | |
|---|---|---|
| `PGUSER` `PGPASSWORD` `PGPORT` | `$USER`, none, 5432 | used by both TCP and unix connections |
| `PGDATABASE` | `mojo_pg_test` | |
| `PG_TCP_HOST` / `PG_SOCKET_DIR` | `127.0.0.1` / `/var/run/postgresql` | |
| `PG_TCP` / `PG_UNIX` | built from the above | full DSN overrides |
| `PG_AUTH` | unset (auth tests skipped) | port of the auth cluster |

Docker (TLS tests are skipped automatically when the server has `ssl=off`):

```
mkdir -p /tmp/pgsock && chmod 777 /tmp/pgsock
docker run -d --rm --name mojo-pg-test -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=mojo_pg_test \
  -p 127.0.0.1:5432:5432 -v /tmp/pgsock:/var/run/postgresql postgres:17
export PGUSER=postgres PGPASSWORD=postgres PGDATABASE=mojo_pg_test PG_SOCKET_DIR=/tmp/pgsock
./build.sh && build/test_pg
```

Auth methods (trust, cleartext, md5, scram) use a throwaway local cluster with fixed test users
(needs PostgreSQL server binaries, e.g. `postgresql-17`; data under `${TMPDIR:-/tmp}/mojo-pg-auth`):

```
tests/auth_cluster.sh start && PG_AUTH=15433 build/test_pg; tests/auth_cluster.sh stop
```

`test_pg` (202 checks with TLS and `PG_AUTH`): DSN forms/errors, TCP + unix, every message path, multi-statement +
empty query, NULLs, unicode (emoji/ZWJ/CJK/RTL, 70 kB text), errors mid-transaction and mid-row-stream, notices,
LISTEN/NOTIFY, COPY, cancel, read-only, statement_timeout, TLS, pool, all auth methods + wrong/missing password,
SCRAM RFC 7677 vector + tampered server signature, 40k float4/8 values bit-compared with `float*send`, 3M-input
float parser fuzz vs the Go-exact reference, 5k dates, 15k timestamps across 5 time zones, bytea, 1M-row and
12 MB-cell results.

Parity with `psql -At` (byte-for-byte, read-only session; connection from the PG* env vars):

```
./build.sh tests/dump.mojo
psql -v ON_ERROR_STOP=1 -f bench/gen_data.sql                 # synthetic dataset, see below
tests/parity.sh                                               # default suite: dataset + mixed-type query
QUERY='select * from pg_class order by oid limit 100' tests/parity.sh
QUERY="select * from ohlcv_daily where asset='asset_03'" MQUERY='select * from ohlcv_daily where asset=$1' tests/parity.sh asset_03
```

CI (`.github/workflows/test.yml`) runs the suite, auth cluster and parity on ubuntu-24.04 against the runner's
preinstalled PostgreSQL, with Mojo installed via pixi.

## Benchmark vs Go pgx v5

`bench/gen_data.sql` builds `ohlcv_daily`: 22 assets, 166,507 daily rows, `numeric` OHLCV columns with 10 decimal
places (~0.5% NULL volume), deterministic (hash-based, identical on PG 17 and 18). Two workloads, same code shape in
`bench/bench.mojo` and `bench/go/main.go`:

- **series**: for each asset, `select day,open,high,low,close,volume,source ... where asset=$1 order by day`, decoded
  into typed columns (days, 5x Float64 with NULL -> NaN, String). 10 timed passes after 2 warm-up passes.
- **synth**: `select g, g*1.5::float8, 'row'||g from generate_series(1,1000000) g` into Int/Float64/String lists.
  5 timed passes after 2 warm-up passes.

```
psql -v ON_ERROR_STOP=1 -f bench/gen_data.sql
./build.sh bench/bench.mojo && (cd bench/go && go build -o ../../build/gobench .)
ROUNDS=5 bench/run.sh          # interleaves build/bench and build/gobench; env DSN (default: PG* env), BENCH_TABLE
```

Results, 2026-10-14: AMD Ryzen 9 5950X (16C/32T), shared box under load (load average 31-50 during the run), Linux 6.8,
PostgreSQL 18.6 on the same host over the unix socket, Mojo 1.2.0.dev2026100805, Go 1.23.6, pgx v5.7.2.
Median across 5 interleaved rounds of each binary's per-round median (range of per-round mins in brackets):

| workload | mojo-pg | pgx v5.7.2 |
|---|---|---|
| series: 22 assets / 166,507 rows, 7 cols decoded (5 numeric -> Float64) | 279 ms (222-280) | 924 ms (801-895) |
| synth: 1M rows x 3 cols (int8, float8, text) | 665 ms (532-690) | 673 ms (582-664) |

pgx's `numeric` -> `float64` scan (via `pgtype.Numeric` / big.Int) dominates the series workload. On synth most of
the time is the server producing text output; pgx asks for binary results there, mojo-pg is text-only.

## License

MIT, see [LICENSE](LICENSE).
