from std.ffi import external_call
from std.os import getenv
from std.memory import bitcast
from std.time import perf_counter_ns
from pg import Conn, Params, Result, Pool, Config, parse_dsn, sqlstate
from pg.conv import fmt_date
from pg.crypto import hex_lower, Scram, md5_password
from p2.gomath import f64_bits, is_nan, inf64, neg_inf64
from p2.gofmt import go_parse_float
from pg.conv import parse_f64
from std.random import seed, random_ui64, random_si64, random_float64


struct T(Movable):
    var ok: Int
    var fail: Int

    def __init__(out self):
        self.ok = 0
        self.fail = 0

    def check(mut self, cond: Bool, what: String):
        if cond:
            self.ok += 1
        else:
            self.fail += 1
            print("FAIL " + what)

    def eq(mut self, a: String, b: String, what: String):
        if a == b:
            self.ok += 1
        else:
            self.fail += 1
            print("FAIL " + what + ": got [" + a + "] want [" + b + "]")

    def eqi(mut self, a: Int, b: Int, what: String):
        self.eq(String(a), String(b), what)


def hex16(v: UInt64) -> String:
    comptime H = "0123456789abcdef"
    var out = String("")
    for i in range(15, -1, -1):
        out += chr(Int(H.as_bytes()[Int((v >> UInt64(4 * i)) & 15)]))
    return out


def dbname() -> String:
    return getenv("PGDATABASE", "mojo_pg_test")


def tcp_base() -> String:
    return "postgres://" + getenv("PG_TCP_HOST", "127.0.0.1") + ":" + getenv("PGPORT", "5432")


def tcp_dsn() -> String:
    return getenv("PG_TCP", tcp_base() + "/" + dbname() + "?application_name=mojo-pg-test")


def unix_dsn() -> String:
    return getenv("PG_UNIX", "host=" + getenv("PG_SOCKET_DIR", "/var/run/postgresql") + " dbname=" + dbname())


def test_dsn(mut t: T) raises:
    var c = parse_dsn("postgres://us%40er:p%3Ass@db.example.com:6543/my%20db?sslmode=require&application_name=app&options=-c%20search_path%3Dx&read_only=true&statement_timeout=1500&search_path=foo")
    t.eq(c.user, "us@er", "dsn user")
    t.eq(c.password, "p:ss", "dsn password")
    t.eq(c.host, "db.example.com", "dsn host")
    t.eqi(c.port, 6543, "dsn port")
    t.eq(c.database, "my db", "dsn db")
    t.eq(c.sslmode, "require", "dsn sslmode")
    t.eq(c.application_name, "app", "dsn app")
    t.check(c.read_only, "dsn read_only")
    t.eqi(c.statement_timeout_ms, 1500, "dsn stmt timeout")
    t.eq(c.startup_options(), "-c search_path=x -c default_transaction_read_only=on -c statement_timeout=1500", "dsn options")
    t.eq(c.param_keys[0] + "=" + c.param_vals[0], "search_path=foo", "dsn runtime param")
    t.check(not c.is_unix(), "dsn tcp")
    var c2 = parse_dsn("postgresql://[::1]:5433/x")
    t.eq(c2.host + "|" + String(c2.port) + "|" + c2.database, "::1|5433|x", "dsn ipv6")
    var c3 = parse_dsn("postgres:///appdb?host=/var/run/postgresql&user=alice&port=5432")
    t.check(c3.is_unix(), "dsn unix via query")
    t.eq(c3.socket_path(), "/var/run/postgresql/.s.PGSQL.5432", "dsn socket path")
    t.eq(c3.db(), "appdb", "dsn unix db")
    var c4 = parse_dsn("host=localhost port=15432 user=alice password='a b\\'c' dbname = appdb  connect_timeout=3 read_only=1")
    t.eq(c4.password, "a b'c", "kv quoted password")
    t.eq(c4.database, "appdb", "kv spaced eq")
    t.eqi(c4.port, 15432, "kv port")
    t.eqi(c4.connect_timeout_ms, 3000, "kv connect_timeout")
    t.check(c4.read_only, "kv read_only")
    var c5 = parse_dsn("postgres://u@h1,h2:5432/d")
    t.eq(c5.host, "h1", "dsn multi host takes first")
    var bad = 0
    for s in ["host=x port=abc", "postgres://h:99999/d", "user='unterminated", "keyonly", "postgres://h/d?x=%zz"]:
        try:
            _ = parse_dsn(s)
        except:
            bad += 1
    t.eqi(bad, 5, "dsn errors")


def test_scram_vector(mut t: T) raises:
    var s = Scram("pencil", "rOprNGfwEbeRWgbNEkqO", "user")
    t.eq(s.client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO", "rfc7677 client-first")
    var fin = s.client_final("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
    t.eq(fin, "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", "rfc7677 client-final")
    s.verify_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
    t.ok += 1
    try:
        s.verify_final("v=7rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=")
        t.check(False, "tampered server signature accepted")
    except err:
        t.check(String(err).find("signature mismatch") >= 0, "tampered server signature rejected")
    var s2 = Scram("pencil", "abc")
    try:
        _ = s2.client_final("r=zzz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
        t.check(False, "nonce mismatch accepted")
    except:
        t.ok += 1
    t.eq(md5_password("u_md5", "pw2", "abcd".as_bytes()), "md5f8cf28d6b8fd6c3479729013c2216432", "md5 password")


def _digits(v: UInt64) -> String:
    return String(v)


def test_float_parse(mut t: T) raises:
    seed(12345)
    var bad = 0
    var n = 0
    for k in range(3000000):
        var shape = k % 4
        var s: String
        if shape == 0:
            var nd = Int(random_ui64(1, 19))
            var m = random_ui64(0, 9999999999999999999) % (UInt64(10) ** UInt64(nd)) if nd < 19 else random_ui64(0, 9999999999999999999)
            var ds = _digits(m)
            var dp = Int(random_ui64(0, UInt64(ds.byte_length())))
            s = String(ds[byte=0:dp]) + "." + String(ds[byte=dp:])
            if dp == 0:
                s = "0" + s
        elif shape == 1:
            var j = Int(random_ui64(1, 27))
            var a = random_ui64(1, (UInt64(1) << UInt64(min(63, 64 - 2 * j))) if j < 31 else 4)
            var num = UInt128(a)
            for _ in range(j):
                num *= 5
            if num >= UInt128(10) ** 19:
                continue
            var ds = _digits(UInt64(num))
            while ds.byte_length() <= j:
                ds = "0" + ds
            var cut = ds.byte_length() - j
            s = String(ds[byte=0:cut]) + "." + String(ds[byte=cut:])
        elif shape == 2:
            s = _digits(random_ui64(1, 9999999999999999999)) + "e" + String(Int(random_si64(-40, 40)))
        else:
            var x = random_float64(-1, 1) * (10.0 ** Float64(Int(random_si64(-30, 30))))
            s = String(x)
        if k % 7 == 0 and not s.startswith("-"):
            s = "-" + s
        n += 1
        var want = go_parse_float(s)
        var got = parse_f64(s.as_bytes())
        if f64_bits(got) != f64_bits(want.value):
            if bad < 5:
                print("float parse mismatch", s, hex16(f64_bits(got)), hex16(f64_bits(want.value)))
            bad += 1
    t.eqi(bad, 0, "parse_f64 vs go_parse_float (" + String(n) + " inputs)")


def test_connect(mut t: T, dsn: String, label: String) raises:
    var c = Conn.connect(dsn)
    t.eq(c.tx_status(), "I", label + " tx idle")
    t.check(c.pid > 0 and len(c.secret) == 4, label + " backend key")
    t.eq(c.param("client_encoding"), "UTF8", label + " client_encoding")
    t.check(c.param("DateStyle").startswith("ISO"), label + " DateStyle")
    t.check(c.param("server_version").byte_length() > 0, label + " server_version")
    var r = c.query("select current_user, current_database(), inet_server_port() is null")
    t.eq(r.text(0, 1), dbname(), label + " database")
    c.close()


def test_simple(mut t: T, mut c: Conn) raises:
    var rs = c.exec("create temp table s1(id int primary key, v text); insert into s1 values (1,'a'),(2,'b'),(3,null); select id, v from s1 order by id; update s1 set v='z' where id>1; delete from s1 where id=3")
    t.eqi(len(rs), 5, "multi count")
    t.eq(rs[0].tag, "CREATE TABLE", "tag create")
    t.eq(rs[1].tag, "INSERT 0 3", "tag insert")
    t.eqi(rs[1].rows_affected(), 3, "insert affected")
    t.eq(rs[2].tag, "SELECT 3", "tag select")
    t.eqi(rs[2].nrows, 3, "select rows")
    t.check(rs[2].is_null(2, 1), "simple null")
    t.eq(rs[2].text(1, 1), "b", "simple text")
    t.eqi(rs[3].rows_affected(), 2, "update affected")
    t.eqi(rs[4].rows_affected(), 1, "delete affected")
    var e = c.exec("")
    t.eqi(len(e), 1, "empty query result")
    t.eqi(e[0].ncols(), 0, "empty query cols")
    try:
        _ = c.exec("select 1; select * from nope_missing; select 3")
        t.check(False, "multi error should raise")
    except err:
        t.eq(sqlstate(err), "42P01", "multi error sqlstate")
        t.eq(c.last_error.severity, "ERROR", "error severity")
        t.check(c.last_error.message.find("nope_missing") >= 0, "error message")
        t.check(c.last_error.position.byte_length() > 0, "error position")
    t.eq(c.tx_status(), "I", "tx after multi error")
    t.eqi(c.exec1("select 42").int(0, 0), 42, "usable after multi error")
    var cp = c.exec("copy (select g from generate_series(1,3) g) to stdout; select 7")
    t.eq(cp[len(cp) - 1].text(0, 0), "7", "copy out drained")
    try:
        _ = c.exec("copy s1 from stdin")
        t.check(False, "copy in should raise")
    except err:
        t.eq(sqlstate(err), "57014", "copy in rejected")
    t.eqi(c.exec1("select 1").int(0, 0), 1, "usable after copy in")
    _ = c.exec("do $$ begin raise notice 'hello %', 42; end $$")
    t.eq(c.notices[len(c.notices) - 1].message, "hello 42", "notice")
    t.eq(c.notices[len(c.notices) - 1].severity, "NOTICE", "notice severity")
    _ = c.exec("listen mpg_chan; notify mpg_chan, 'payload1'")
    t.check(len(c.notifications) > 0 and c.notifications[len(c.notifications) - 1] == "mpg_chan:payload1", "notification")
    _ = c.exec("unlisten *")


def test_extended(mut t: T, mut c: Conn) raises:
    var p = Params("41")
    p.add_null()
    p.add("ünï 漢字 😀")
    var r = c.query("select $1::int + 1 as a, $2::text as b, $3::text as c, char_length($3) as n", p)
    t.eq(r.fields[0].name, "a", "col name")
    t.eqi(r.fields[0].type_oid, 23, "col oid int4")
    t.eqi(r.fields[1].type_oid, 25, "col oid text")
    t.eqi(r.int(0, 0), 42, "param int")
    t.check(r.is_null(0, 1), "param null")
    t.eq(r.text(0, 2), "ünï 漢字 😀", "param unicode")
    t.eqi(r.int(0, 3), 8, "unicode char_length")
    t.eqi(r.col("n"), 3, "col by name")
    var seq0 = c.seq
    for i in range(5):
        var r2 = c.query("select $1::int * 2", Params(String(i)))
        t.eqi(r2.int(0, 0), i * 2, "cached stmt result")
    t.eqi(c.seq - seq0, 1, "stmt cache reuse")
    t.check(len(c.stmts[c.cache["select $1::int * 2"]].param_oids) == 1, "cached param oids")
    try:
        _ = c.query("select $1::int, $2::int", Params("1"))
        t.check(False, "bind count mismatch should raise")
    except err:
        t.eq(sqlstate(err), "08P01", "bind mismatch sqlstate")
    t.eqi(c.query("select $1::int, $2::int", Params("1", "2")).int(0, 1), 2, "stmt usable after bind error")
    try:
        _ = c.query("selec 1")
        t.check(False, "syntax error should raise")
    except err:
        t.eq(sqlstate(err), "42601", "syntax sqlstate")
    t.check("selec 1" not in c.cache, "failed parse not cached")
    try:
        _ = c.query("select $1::int", Params("notint"))
        t.check(False, "bad param should raise")
    except err:
        t.eq(sqlstate(err), "22P02", "bad param sqlstate")
    var u = c.query_unnamed("select $1::text || 'x'", Params("ab"))
    t.eq(u.text(0, 0), "abx", "unnamed")
    var oids = c.prepare("named1", "select $1::int8 + $2::int8 as s, $3::text as t")
    t.eqi(len(oids), 3, "prepare param count")
    t.eqi(oids[0], 20, "prepare param oid")
    var p2 = Params()
    p2.add(40)
    p2.add(2)
    p2.add(True)
    var n = c.query_prepared("named1", p2)
    t.eqi(n.int(0, 0), 42, "named prepared")
    t.eq(n.text(0, 1), "t", "Params.add(Bool) as text")
    t.eq(n.fields[1].name, "t", "named fields")
    c.deallocate("named1")
    try:
        _ = c.exec("execute named1(1,2,'x')")
        t.check(False, "deallocated should raise")
    except err:
        t.eq(sqlstate(err), "26000", "deallocated sqlstate")
    _ = c.exec("create temp table e1(id int primary key, v text)")
    var ins = c.query("insert into e1 values ($1, $2), ($3, $4)", Params("1", "x", "2", "y"))
    t.eq(ins.tag, "INSERT 0 2", "extended insert tag")
    t.eqi(ins.ncols(), 0, "insert no fields")
    var ret = c.query("insert into e1 values ($1, $2) returning id, v", Params("3", "z"))
    t.eq(ret.text(0, 1), "z", "returning")
    t.eqi(c.query("select").ncols(), 0, "empty select")
    t.eqi(c.query("").nrows, 0, "empty extended query")


def test_tx(mut t: T, mut c: Conn) raises:
    _ = c.exec("create temp table t1(id int primary key, v text)")
    _ = c.exec("begin")
    t.eq(c.tx_status(), "T", "in tx")
    _ = c.query("insert into t1 values ($1, $2)", Params("1", "a"))
    try:
        _ = c.query("insert into t1 values ($1, $2)", Params("1", "b"))
        t.check(False, "dup should raise")
    except err:
        t.eq(sqlstate(err), "23505", "unique violation")
        t.eq(c.last_error.detail, "Key (id)=(1) already exists.", "error detail")
        t.eq(c.last_error.table, "t1", "error table")
        t.eq(c.last_error.constraint, "t1_pkey", "error constraint")
        t.check(String(err).find("DETAIL: Key (id)=(1)") >= 0, "detail in error text")
    t.eq(c.tx_status(), "E", "failed tx")
    try:
        _ = c.query("select 1")
        t.check(False, "aborted tx should raise")
    except err:
        t.eq(sqlstate(err), "25P02", "in failed tx")
    _ = c.exec("rollback")
    t.eq(c.tx_status(), "I", "after rollback")
    t.eqi(c.query("select count(*) from t1").int(0, 0), 0, "rolled back")
    try:
        _ = c.query("select case when g = 5000 then 1/0 else g end from generate_series(1, 10000) g")
        t.check(False, "mid-stream error should raise")
    except err:
        t.eq(sqlstate(err), "22012", "mid-stream div by zero")
    try:
        _ = c.exec("select case when g = 5000 then 1/0 else g end from generate_series(1, 10000) g")
        t.check(False, "mid-stream simple error should raise")
    except err:
        t.eq(sqlstate(err), "22012", "mid-stream simple")
    t.eqi(c.query("select 5").int(0, 0), 5, "usable after mid-stream error")
    _ = c.exec("begin")
    _ = c.exec("insert into t1 values (9, 'x')")
    _ = c.exec("commit")
    t.eqi(c.query("select count(*) from t1").int(0, 0), 1, "committed")


def test_types(mut t: T, mut c: Conn) raises:
    var r = c.query("select (-32768)::int2, 32767::int2, (-2147483648)::int4, 2147483647::int4, (-9223372036854775808)::int8, 9223372036854775807::int8, true, false, null::int8, 'vc'::varchar(5), null::bool")
    t.eqi(r.int(0, 0), -32768, "int2 min")
    t.eqi(r.int(0, 1), 32767, "int2 max")
    t.eqi(r.int(0, 2), -2147483648, "int4 min")
    t.eqi(r.int(0, 3), 2147483647, "int4 max")
    t.eqi(r.int(0, 4), Int(Int64.MIN), "int8 min")
    t.eqi(r.int(0, 5), Int(Int64.MAX), "int8 max")
    t.check(r.bool(0, 6) and not r.bool(0, 7), "bool")
    t.check(r.is_null(0, 8), "null int8")
    t.eqi(r.int_or(0, 8, -7), -7, "int_or")
    t.eq(r.text(0, 9), "vc", "varchar")
    t.eqi(r.fields[9].type_oid, 1043, "varchar oid")
    try:
        _ = r.int(0, 8)
        t.check(False, "NULL int should raise")
    except:
        t.ok += 1
    try:
        _ = r.bool(0, 10)
        t.check(False, "NULL bool should raise")
    except:
        t.ok += 1

    var f8 = c.query("select x, encode(float8send(x), 'hex') from (select ((random() - 0.5) * 10 ^ (floor(random() * 600) - 300))::float8 as x from generate_series(1, 20000) union all select unnest('{NaN,Infinity,-Infinity,-0,0,4.9e-324,2.2250738585072014e-308,2.225073858507201e-308,1.7976931348623157e308,0.1,1e23,123456.789,5e-324,9007199254740993}'::float8[])) s")
    var bad = 0
    var nan_ok = False
    for i in range(f8.nrows):
        var v = f8.float(i, 0)
        if is_nan(v):
            nan_ok = f8.text(i, 1) == "7ff8000000000000"
            continue
        if hex16(f64_bits(v)) != f8.text(i, 1):
            if bad < 5:
                print("float8 mismatch", f8.text(i, 0), hex16(f64_bits(v)), f8.text(i, 1))
            bad += 1
    t.eqi(bad, 0, "float8 exact bits (" + String(f8.nrows) + " values)")
    t.check(nan_ok, "float8 NaN")
    var f4 = c.query("select x, encode(float4send(x), 'hex') from (select ((random() - 0.5) * 10 ^ (floor(random() * 76) - 38))::float4 as x from generate_series(1, 20000) union all select unnest('{Infinity,-Infinity,-0,1.4e-45,1.17549435e-38,3.4028235e38,0.1,16777217}'::float4[])) s")
    bad = 0
    for i in range(f4.nrows):
        var v = f4.float32(i, 0)
        var bits = bitcast[DType.uint32](v)
        var h = hex16(UInt64(bits))
        var want = f4.text(i, 1)
        if String(h[byte=8:]) != want or f64_bits(f4.float(i, 0)) != f64_bits(Float64(v)):
            if bad < 5:
                print("float4 mismatch", f4.text(i, 0), h, want)
            bad += 1
    t.eqi(bad, 0, "float4 exact bits (" + String(f4.nrows) + " values)")

    var fp = Params()
    var fvals = List[Float64]()
    fvals.append(0.1)
    fvals.append(-1e-310)
    fvals.append(1.7976931348623157e308)
    fvals.append(1e21)
    fvals.append(-0.0)
    fvals.append(123456789.98765433)
    fvals.append(inf64())
    fvals.append(neg_inf64())
    var fsql = String("select ")
    for i in range(len(fvals)):
        fp.add(fvals[i])
        fsql += ("" if i == 0 else ", ") + "encode(float8send($" + String(i + 1) + "::float8), 'hex')"
    var fr = c.query(fsql, fp)
    bad = 0
    for i in range(len(fvals)):
        if fr.text(0, i) != hex16(f64_bits(fvals[i])):
            print("float param mismatch", fvals[i], fr.text(0, i))
            bad += 1
    t.eqi(bad, 0, "float8 params round trip")

    var nm = c.query("select 123456789012345678901234567890.123456789::numeric, 'NaN'::numeric, '-1.5e-10'::numeric, 0.1::numeric(10,4), 'Infinity'::numeric, null::numeric")
    t.eq(nm.numeric(0, 0), "123456789012345678901234567890.123456789", "numeric text")
    t.check(is_nan(nm.float(0, 1)), "numeric NaN")
    t.eq(nm.numeric(0, 2), "-0.00000000015", "numeric small")
    t.check(nm.float(0, 2) == -1.5e-10, "numeric to f64")
    t.eq(nm.numeric(0, 3), "0.1000", "numeric scale")
    t.check(nm.float(0, 4) > 1e308, "numeric inf")
    t.check(is_nan(nm.float_col(5)[0]), "float_col NULL NaN")
    t.eqi(nm.fields[0].type_oid, 1700, "numeric oid")

    var d = c.query("select d, d - '1970-01-01'::date from (select '1970-01-01'::date + (random() * 800000 - 400000)::int as d from generate_series(1, 5000) union all select unnest('{2000-02-29,1900-03-01,0001-01-01,0001-12-31 BC,4713-01-01 BC,5874897-12-31,1969-12-31}'::date[])) s")
    bad = 0
    for i in range(d.nrows):
        if d.date_days(i, 0) != d.int(i, 1):
            if bad < 5:
                print("date mismatch", d.text(i, 0), d.date_days(i, 0), d.text(i, 1))
            bad += 1
    t.eqi(bad, 0, "date days (" + String(d.nrows) + ")")
    t.eq(fmt_date(c.query("select '2024-02-29'::date").date_days(0, 0)), "2024-02-29", "fmt_date")
    var di = c.query("select 'infinity'::date, '-infinity'::timestamptz")
    t.eqi(di.date_days(0, 0), Int(Int64.MAX), "date infinity")
    t.eqi(di.timestamp_us(0, 1), Int(Int64.MIN), "ts -infinity")

    for tz in ["UTC", "Asia/Kolkata", "America/St_Johns", "Europe/Amsterdam", "Pacific/Chatham"]:
        _ = c.exec("set timezone = '" + tz + "'")
        var ts = c.query("select ts, (extract(epoch from ts) * 1000000)::int8, ts::timestamp, (extract(epoch from ts::timestamp) * 1000000)::int8 from (select to_timestamp(trunc((random() * 8e9 - 4e9) * 1e6) / 1e6) as ts from generate_series(1, 3000) union all select unnest('{1900-01-01 00:00:00+00,1970-01-01 00:00:00.000001+00,2024-03-10 02:30:00.5+00,0044-03-15 12:00:00+00 BC,1901-06-01 00:00:00+00}'::timestamptz[])) s")
        bad = 0
        for i in range(ts.nrows):
            if ts.timestamp_us(i, 0) != ts.int(i, 1) or ts.timestamp_us(i, 2) != ts.int(i, 3):
                if bad < 3:
                    print("ts mismatch", tz, ts.text(i, 0), ts.timestamp_us(i, 0), ts.text(i, 1), ts.text(i, 2), ts.timestamp_us(i, 2), ts.text(i, 3))
                bad += 1
        t.eqi(bad, 0, "timestamptz/timestamp in " + tz)
    _ = c.exec("set timezone = 'UTC'")
    t.eqi(c.query("select '2024-01-02'::date::timestamp").timestamp_us(0, 0), 1704153600000000, "date-only timestamp")

    var j = c.query("select '{\"a\": [1, 2], \"é\": \"😀\"}'::json, '{\"b\":1, \"a\":2}'::jsonb")
    t.eq(j.json(0, 0), "{\"a\": [1, 2], \"é\": \"😀\"}", "json verbatim")
    t.eq(j.json(0, 1), "{\"a\": 2, \"b\": 1}", "jsonb normalized")
    t.eqi(j.fields[1].type_oid, 3802, "jsonb oid")

    var b = c.query("select decode(md5(g::text), 'hex') || '\\x00ff'::bytea, md5(g::text) || '00ff' from generate_series(1, 1000) g union all select ''::bytea, ''")
    bad = 0
    for i in range(b.nrows):
        if hex_lower(b.bytea(i, 0)) != b.text(i, 1):
            bad += 1
    t.eqi(bad, 0, "bytea hex")
    _ = c.exec("set bytea_output = 'escape'")
    var be = c.query("select '\\x00015c27ff41'::bytea")
    t.eq(hex_lower(be.bytea(0, 0)), "00015c27ff41", "bytea escape format")
    _ = c.exec("set bytea_output = 'hex'")

    var strs = List[String]()
    strs.append("plain")
    strs.append("")
    strs.append("tab\there\nnewline\\back'quote\"dq")
    strs.append("𝄞 😀 👨‍👩‍👧 漢字 한국어 العربية é")
    strs.append("x" * 70000)
    _ = c.exec("create temp table u1(i int, s text)")
    for i in range(len(strs)):
        _ = c.query("insert into u1 values ($1, $2)", Params(String(i), strs[i]))
    var us = c.query("select s, octet_length(s) from u1 order by i")
    for i in range(len(strs)):
        t.check(us.text(i, 0) == strs[i] and us.int(i, 1) == strs[i].byte_length(), "unicode/text round trip " + String(i))
    var us2 = c.exec1("select s from u1 order by i")
    t.check(us2.text(3, 0) == strs[3], "unicode simple protocol")


def test_large(mut t: T, mut c: Conn) raises:
    var t0 = perf_counter_ns()
    var r = c.query("select g, g * 1.5::float8, 'row' || g, case when g % 7 = 0 then null else g end from generate_series(1, 1000000) g")
    var dt = (perf_counter_ns() - t0) // 1000000
    t.eqi(r.nrows, 1000000, "1M rows")
    var s = 0
    var nulls = 0
    var fs = 0.0
    for i in range(r.nrows):
        s += r.int(i, 0)
        fs += r.float(i, 1)
        if r.is_null(i, 3):
            nulls += 1
    t.eqi(s, 500000500000, "1M sum")
    t.check(fs == 750000750000.0, "1M float sum")
    t.eqi(nulls, 142857, "1M nulls")
    t.eq(r.text(999999, 2), "row1000000", "1M last text")
    print("  1M rows x4 extended:", dt, "ms")
    t0 = perf_counter_ns()
    var rs = c.exec("select g from generate_series(1, 1000000) g")
    print("  1M rows simple:", (perf_counter_ns() - t0) // 1000000, "ms")
    t.eqi(rs[0].nrows, 1000000, "1M simple rows")
    var big = c.query("select repeat('ab', 6000000), 1")
    t.eqi(big.cell_len(0, 0), 12000000, "12MB cell")
    t.eqi(big.int(0, 1), 1, "after 12MB cell")
    t.eqi(c.query("select 3").int(0, 0), 3, "after large")


def test_options(mut t: T) raises:
    var ro = Conn.connect(tcp_dsn() + "&read_only=true&statement_timeout=300")
    t.eq(ro.query("show default_transaction_read_only").text(0, 0), "on", "read_only option")
    t.eq(ro.query("show statement_timeout").text(0, 0), "300ms", "statement_timeout option")
    t.eq(ro.query("select current_setting('application_name')").text(0, 0), "mojo-pg-test", "application_name")
    try:
        _ = ro.exec("create table ro_should_fail(i int)")
        t.check(False, "read-only write should raise")
    except err:
        t.eq(sqlstate(err), "25006", "read-only sqlstate")
    try:
        _ = ro.query("select pg_sleep(2)")
        t.check(False, "timeout should raise")
    except err:
        t.eq(sqlstate(err), "57014", "statement timeout sqlstate")
    t.eqi(ro.query("select 1").int(0, 0), 1, "usable after timeout")
    ro.close()
    var nc = Conn.connect(unix_dsn() + " statement_cache=false options='-c search_path=pg_catalog'")
    t.eq(nc.query("show search_path").text(0, 0), "pg_catalog", "options passthrough")
    _ = nc.query("select 1")
    t.eqi(len(nc.cache), 0, "statement_cache off")
    nc._send_simple("select pg_sleep(5)")
    nc.cancel()
    try:
        _ = nc._read_simple()
        t.check(False, "cancel should raise")
    except err:
        t.eq(sqlstate(err), "57014", "cancel request")
    t.eqi(nc.query("select 2").int(0, 0), 2, "usable after cancel")
    nc.close()
    try:
        _ = Conn.connect(tcp_base() + "/no_such_db_mpg")
        t.check(False, "bad db should raise")
    except err:
        t.eq(sqlstate(err), "3D000", "bad database sqlstate")
    try:
        _ = Conn.connect("postgres://127.0.0.1:1/x?connect_timeout=2")
        t.check(False, "refused should raise")
    except err:
        t.check(String(err).find("connection refused") >= 0, "connection refused: " + String(err))
    var sc = Conn.connect(tcp_dsn())
    var ssl_on = sc.query("show ssl").text(0, 0) == "on"
    sc.close()
    if not ssl_on:
        print("  skip tls tests (server ssl=off)")
        return
    var tls = Conn.connect(tcp_dsn() + "&sslmode=require")
    t.check(tls.sock.ssl != 0, "tls established")
    t.eq(tls.query("select ssl::text from pg_stat_ssl where pid = pg_backend_pid()").text(0, 0), "true", "server sees tls")
    t.eqi(tls.query("select count(*) from generate_series(1, 100000)").int(0, 0), 100000, "tls query")
    tls.close()


def test_pool(mut t: T) raises:
    var p = Pool.open(unix_dsn(), 2)
    var a = p.acquire()
    var b = p.acquire()
    try:
        _ = p.acquire()
        t.check(False, "pool exhausted should raise")
    except:
        t.ok += 1
    _ = a.exec("begin")
    p.release(a^)
    p.release(b^)
    t.eqi(p.open_conns(), 2, "pool size")
    var c = p.acquire()
    t.eq(c.tx_status(), "I", "pool rolled back released tx")
    p.release(c^)
    t.eqi(p.query("select $1::int", Params("9")).int(0, 0), 9, "pool query")
    try:
        _ = p.query("select 1/0")
    except err:
        t.eq(sqlstate(err), "22012", "pool query error")
    t.eqi(p.open_conns(), 2, "pool keeps conn after server error")
    p.close()


def test_deadline(mut t: T) raises:
    var p = Pool.open(unix_dsn() + " read_timeout=0 application_name=mpg_deadline", 2)
    var t0 = perf_counter_ns()
    try:
        _ = p.query("select pg_sleep(3)", Params(), 300)
        t.check(False, "deadline should raise")
    except err:
        t.check(String(err).find("i/o timeout") >= 0, "deadline error text: " + String(err))
    var ms = Int(perf_counter_ns() - t0) // 1000000
    t.check(ms >= 250 and ms < 1500, "deadline elapsed " + String(ms) + " ms")
    t.eqi(p.open_conns(), 0, "timed-out conn dropped from pool")
    var running = 1
    for _ in range(40):
        running = Int(p.query("select count(*) from pg_stat_activity where application_name = 'mpg_deadline' and query like 'select pg_sleep%' and state = 'active'").int(0, 0))
        if running == 0:
            break
        _ = external_call["usleep", Int32](UInt32(50000))
    t.eqi(running, 0, "server query cancelled after client deadline")
    t.eqi(p.query("select $1::int", Params("5"), 1000).int(0, 0), 5, "pool usable after deadline")
    try:
        _ = p.query("select 1", Params(), 0)
        t.check(False, "expired deadline should raise")
    except:
        t.ok += 1
    var c = Conn.connect(unix_dsn() + " read_timeout=200")
    try:
        _ = c.query("select pg_sleep(1)")
        t.check(False, "dsn read_timeout should raise")
    except err:
        t.check(String(err).find("i/o timeout") >= 0 and c.broken, "dsn read_timeout")
    p.close()


def test_auth(mut t: T) raises:
    var host = getenv("PG_AUTH", "")
    if host.byte_length() == 0:
        print("  skip auth tests (PG_AUTH unset)")
        return
    var tu = getenv("PG_AUTH_TRUST_USER", getenv("USER", "postgres"))
    for u in [(tu, "", "trust"), ("u_pass", "pw1", "cleartext"), ("u_md5", "pw2", "md5"), ("u_scram", "pw3", "scram-sha-256")]:
        var dsn = "host=127.0.0.1 port=" + host + " dbname=postgres user=" + u[0] + " password=" + u[1]
        var c = Conn.connect(dsn if u[1].byte_length() > 0 else "host=127.0.0.1 port=" + host + " dbname=postgres user=" + tu)
        t.eq(c.query("select current_user").text(0, 0), u[0], "auth " + u[2])
        t.eq(c.auth_method, u[2], "auth method " + u[2])
        c.close()
        if u[1].byte_length() > 0:
            try:
                _ = Conn.connect("host=127.0.0.1 port=" + host + " dbname=postgres user=" + u[0] + " password=wrong")
                t.check(False, "wrong password should raise " + u[2])
            except err:
                t.eq(sqlstate(err), "28P01", "wrong password " + u[2])
            try:
                _ = Conn.connect("host=127.0.0.1 port=" + host + " dbname=postgres user=" + u[0] + " password=")
                t.check(False, "missing password should raise " + u[2])
            except err:
                t.check(String(err).find("none was supplied") >= 0, "missing password " + u[2])


def main() raises:
    var t = T()
    print("dsn")
    test_dsn(t)
    test_scram_vector(t)
    print("float parse fuzz")
    test_float_parse(t)
    print("connect")
    test_connect(t, tcp_dsn(), "tcp")
    test_connect(t, unix_dsn(), "unix")
    var c = Conn.connect(unix_dsn())
    print("simple")
    test_simple(t, c)
    print("extended")
    test_extended(t, c)
    print("tx/errors")
    test_tx(t, c)
    print("types")
    test_types(t, c)
    print("large")
    test_large(t, c)
    c.close()
    print("options/tls/cancel")
    test_options(t)
    print("pool")
    test_pool(t)
    test_deadline(t)
    print("auth")
    test_auth(t)
    print("ok", t.ok, "fail", t.fail)
    if t.fail > 0:
        raise Error("tests failed")
