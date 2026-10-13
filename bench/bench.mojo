from std.os import getenv
from std.time import perf_counter_ns
from pg import Conn, Params
from p2.gomath import nan64, is_nan
from p2.gofmt import go_format_float


def stats(mut ms: List[Float64]) -> String:
    sort(ms)
    return "min " + go_format_float(ms[0], "f", 1) + " ms  median " + go_format_float(ms[len(ms) // 2], "f", 1) + " ms"


def main() raises:
    var c = Conn.connect(getenv("DSN", ""))
    var tbl = getenv("BENCH_TABLE", "ohlcv_daily")
    var assets = c.query("select distinct asset from " + tbl + " order by 1").text_col(0)
    var sql = "select day,open,high,low,close,volume,source from " + tbl + " where asset=$1 order by day"
    var ms = List[Float64]()
    var total = 0
    var csum = 0.0
    for it in range(12):
        var t0 = perf_counter_ns()
        total = 0
        csum = 0.0
        for a in assets:
            var r = c.query(sql, Params(a))
            var day = List[Int](capacity=r.nrows)
            var o = List[Float64](capacity=r.nrows)
            var h = List[Float64](capacity=r.nrows)
            var l = List[Float64](capacity=r.nrows)
            var cl = List[Float64](capacity=r.nrows)
            var v = List[Float64](capacity=r.nrows)
            var src = List[String](capacity=r.nrows)
            for i in range(r.nrows):
                day.append(r.date_days(i, 0))
                o.append(r.float_or(i, 1, nan64()))
                h.append(r.float_or(i, 2, nan64()))
                l.append(r.float_or(i, 3, nan64()))
                cl.append(r.float_or(i, 4, nan64()))
                v.append(r.float_or(i, 5, nan64()))
                src.append(r.text(i, 6))
            total += len(day)
            for x in cl:
                if not is_nan(x):
                    csum += x
        if it >= 2:
            ms.append(Float64(perf_counter_ns() - t0) / 1e6)
    print("mojo-pg series", len(assets), "assets", total, "rows close_sum", go_format_float(csum, "g", 6) + ":", stats(ms))
    ms.clear()
    var gsum = 0
    for it in range(7):
        var t0 = perf_counter_ns()
        var r = c.query("select g, g*1.5::float8, 'row'||g from generate_series(1,1000000) g")
        var g = List[Int](capacity=r.nrows)
        var x = List[Float64](capacity=r.nrows)
        var s = List[String](capacity=r.nrows)
        for i in range(r.nrows):
            g.append(r.int(i, 0))
            x.append(r.float(i, 1))
            s.append(r.text(i, 2))
        gsum = 0
        for q in g:
            gsum += q
        if it >= 2:
            ms.append(Float64(perf_counter_ns() - t0) / 1e6)
    print("mojo-pg synth 1M rows g_sum", gsum, ":", stats(ms))
    c.close()
