"""Text-format value decoders (DateStyle=ISO)."""

from std.bit import count_leading_zeros
from std.builtin.globals import global_constant
from p2.gofmt import go_parse_float_bytes
from p2.gomath import f64_from_bits
from p2.eisel_lemire_tables import POW10_MIN_EXP10, POW10_MAX_EXP10, POW10_TABLE

comptime F64_POW10: Array[Float64, 23] = [
    1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
    1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22,
]

comptime INF_TS = Int(Int64.MAX)
comptime NEG_INF_TS = Int(Int64.MIN)


def parse_int(b: Span[UInt8, _]) raises -> Int:
    var n = len(b)
    var i = 0
    var neg = False
    if n > 0 and (b[0] == 45 or b[0] == 43):
        neg = b[0] == 45
        i = 1
    if i >= n:
        raise Error("pg: invalid integer \"" + String(unsafe_from_utf8=b) + "\"")
    var v = 0
    while i < n:
        var d = Int(b[i]) - 48
        if d < 0 or d > 9:
            raise Error("pg: invalid integer \"" + String(unsafe_from_utf8=b) + "\"")
        v = v * 10 - d
        i += 1
    return v if neg else -v


@always_inline
def _eisel_lemire(man_in: UInt64, exp10: Int, neg: Bool, mut ok: Bool) -> Float64:
    """Go strconv.eiselLemire64 with the table read in place (not materialized)."""
    ok = False
    if man_in == 0:
        ok = True
        return f64_from_bits(UInt64(0x8000000000000000) if neg else 0)
    if exp10 < POW10_MIN_EXP10 or POW10_MAX_EXP10 < exp10:
        return 0
    var clz = Int(count_leading_zeros(man_in))
    var man = man_in << UInt64(clz)
    var ret_exp2 = UInt64(((217706 * exp10) >> 16) + 64 + 1023) - UInt64(clz)
    ref tab = global_constant[POW10_TABLE]()
    var idx = exp10 - POW10_MIN_EXP10
    var px = UInt128(man) * UInt128(tab[2 * idx + 1])
    var x_hi = UInt64(px >> 64)
    var x_lo = UInt64(px & UInt128(UInt64.MAX))
    if (x_hi & 0x1FF) == 0x1FF and x_lo + man < man:
        var py = UInt128(man) * UInt128(tab[2 * idx])
        var y_hi = UInt64(py >> 64)
        var y_lo = UInt64(py & UInt128(UInt64.MAX))
        var merged_hi = x_hi
        var merged_lo = x_lo + y_hi
        if merged_lo < x_lo:
            merged_hi += 1
        if (merged_hi & 0x1FF) == 0x1FF and merged_lo + 1 == 0 and y_lo + man < man:
            return 0
        x_hi = merged_hi
        x_lo = merged_lo
    var msb = x_hi >> 63
    var ret_mant = x_hi >> (msb + 9)
    ret_exp2 -= 1 ^ msb
    if x_lo == 0 and (x_hi & 0x1FF) == 0 and (ret_mant & 3) == 1:
        return 0
    ret_mant += ret_mant & 1
    ret_mant >>= 1
    if (ret_mant >> 53) > 0:
        ret_mant >>= 1
        ret_exp2 += 1
    if ret_exp2 - 1 >= 0x7FF - 1:
        return 0
    var bits = (ret_exp2 << 52) | (ret_mant & 0x000FFFFFFFFFFFFF)
    if neg:
        bits |= 0x8000000000000000
    ok = True
    return f64_from_bits(bits)


def parse_f64(b: Span[UInt8, _]) raises -> Float64:
    """strconv.ParseFloat(s, 64)-exact. Fast path: <=19 significant digits
    (exact float math or Eisel-Lemire); everything else goes to p2.gofmt."""
    var n = len(b)
    var i = 0
    var neg = False
    if n > 0 and (b[0] == 45 or b[0] == 43):
        neg = b[0] == 45
        i = 1
    var mant: UInt64 = 0
    var nd = 0
    var nd_mant = 0
    var dp = 0
    var saw_dot = False
    var saw_digits = False
    var trunc = False
    while i < n:
        var c = b[i]
        if c == 46:
            if saw_dot:
                break
            saw_dot = True
            dp = nd
        elif c >= 48 and c <= 57:
            saw_digits = True
            if c == 48 and nd == 0:
                dp -= 1
            else:
                nd += 1
                if nd_mant < 19:
                    mant = mant * 10 + UInt64(c - 48)
                    nd_mant += 1
                else:
                    trunc = True
        else:
            break
        i += 1
    if not saw_dot:
        dp = nd
    if i < n and (b[i] == 101 or b[i] == 69) and saw_digits:
        i += 1
        var esign = 1
        if i < n and (b[i] == 43 or b[i] == 45):
            esign = -1 if b[i] == 45 else 1
            i += 1
        var e = 0
        var saw_e = False
        while i < n and b[i] >= 48 and b[i] <= 57:
            saw_e = True
            if e < 10000:
                e = e * 10 + Int(b[i] - 48)
            i += 1
        if not saw_e:
            i = -1
        dp += e * esign
    if saw_digits and not trunc and i == n:
        var exp = dp - nd_mant if mant != 0 else 0
        if (mant >> 52) == 0:
            var f = Float64(mant)
            if neg:
                f = -f
            ref p10 = global_constant[F64_POW10]()
            if exp == 0:
                return f
            if exp > 0 and exp <= 37:
                var e2 = exp
                if e2 > 22:
                    f *= p10[e2 - 22]
                    e2 = 22
                if f <= 1e15 and f >= -1e15:
                    return f * p10[e2]
            elif exp < 0 and exp >= -22:
                return f / p10[-exp]
        var ok = False
        var v = _eisel_lemire(mant, exp, neg, ok)
        if ok:
            return v
        v = _exact128(mant, exp, neg, ok)
        if ok:
            return v
    return _parse_f64_slow(b)


def _exact128(m: UInt64, exp: Int, neg: Bool, mut ok: Bool) -> Float64:
    """Correctly rounded m * 10^exp via 128-bit integer arithmetic, for
    -21 <= exp <= 19 (where Eisel-Lemire gives up on near-halfway inputs)."""
    ok = False
    if m == 0 or exp < -21 or exp > 19:
        return 0
    var p10: UInt128 = 1
    for _ in range(exp if exp > 0 else -exp):
        p10 *= 10
    var q: UInt128
    var rem_nz: Bool
    var e2: Int
    if exp >= 0:
        q = UInt128(m) * p10
        rem_nz = False
        e2 = 0
    else:
        var clz = Int(count_leading_zeros(m))
        var num = UInt128(m << UInt64(clz)) << 64
        q = num // p10
        rem_nz = (num - q * p10) != 0
        e2 = -(clz + 64)
    var nbits = 128 - Int(count_leading_zeros(q))
    if nbits <= 53:
        if rem_nz:
            return 0
        var f = Float64(UInt64(q))
        ok = True
        return -f if neg else f
    var sh = nbits - 53
    var mant = UInt64(q >> UInt128(sh))
    var rest = q & ((UInt128(1) << UInt128(sh)) - 1)
    var half = UInt128(1) << UInt128(sh - 1)
    if rest > half or (rest == half and (rem_nz or (mant & 1) == 1)):
        mant += 1
        if mant == (UInt64(1) << 53):
            mant >>= 1
            sh += 1
    var be = e2 + sh + 52 + 1023
    if be <= 0 or be >= 0x7FF:
        return 0
    var bits = (UInt64(be) << 52) | (mant & 0x000FFFFFFFFFFFFF)
    if neg:
        bits |= 0x8000000000000000
    ok = True
    return f64_from_bits(bits)


def _parse_f64_slow(b: Span[UInt8, _]) raises -> Float64:
    var r = go_parse_float_bytes(b)
    if not r.ok and not r.range_err:
        raise Error("pg: invalid float \"" + String(unsafe_from_utf8=b) + "\"")
    return r.value


def parse_bool(b: Span[UInt8, _]) raises -> Bool:
    if len(b) == 1:
        if b[0] == 116:
            return True
        if b[0] == 102:
            return False
    raise Error("pg: invalid bool \"" + String(unsafe_from_utf8=b) + "\"")


def days_from_civil(y0: Int, m: Int, d: Int) -> Int:
    var y = y0 - 1 if m <= 2 else y0
    var era = y // 400
    var yoe = y - era * 400
    var mp = m - 3 if m > 2 else m + 9
    var doy = (153 * mp + 2) // 5 + d - 1
    var doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z0: Int) -> Tuple[Int, Int, Int]:
    var z = z0 + 719468
    var era = z // 146097
    var doe = z - era * 146097
    var yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    var y = yoe + era * 400
    var doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    var mp = (5 * doy + 2) // 153
    var d = doy - (153 * mp + 2) // 5 + 1
    var m = mp + 3 if mp < 10 else mp - 9
    return (y + 1 if m <= 2 else y, m, d)


def _num(b: Span[UInt8, _], mut i: Int, maxd: Int) raises -> Int:
    var s = i
    var v = 0
    while i < len(b) and i - s < maxd and b[i] >= 48 and b[i] <= 57:
        v = v * 10 + Int(b[i] - 48)
        i += 1
    if i == s:
        raise Error("pg: invalid date/time \"" + String(unsafe_from_utf8=b) + "\"")
    return v


def _expect(b: Span[UInt8, _], mut i: Int, c: UInt8) raises:
    if i >= len(b) or b[i] != c:
        raise Error("pg: invalid date/time \"" + String(unsafe_from_utf8=b) + "\"")
    i += 1


def _is_inf(b: Span[UInt8, _]) -> Int:
    if len(b) == 8 and b[0] == 105:
        return 1
    if len(b) == 9 and b[0] == 45 and b[1] == 105:
        return -1
    return 0


def _date_part(b: Span[UInt8, _], mut i: Int) raises -> Int:
    var y = _num(b, i, 9)
    _expect(b, i, 45)
    var m = _num(b, i, 2)
    _expect(b, i, 45)
    var d = _num(b, i, 2)
    if m < 1 or m > 12 or d < 1 or d > 31:
        raise Error("pg: invalid date \"" + String(unsafe_from_utf8=b) + "\"")
    if len(b) >= 3 and b[len(b) - 1] == 67 and b[len(b) - 2] == 66 and b[len(b) - 3] == 32:
        y = 1 - y
    return days_from_civil(y, m, d)


def parse_date_days(b: Span[UInt8, _]) raises -> Int:
    """Days since 1970-01-01; +-infinity map to Int64 max/min."""
    var inf = _is_inf(b)
    if inf != 0:
        return INF_TS if inf > 0 else NEG_INF_TS
    var i = 0
    return _date_part(b, i)


def parse_ts_us(b: Span[UInt8, _]) raises -> Int:
    """timestamp / timestamptz / date text to unix microseconds (UTC)."""
    var inf = _is_inf(b)
    if inf != 0:
        return INF_TS if inf > 0 else NEG_INF_TS
    var i = 0
    var days = _date_part(b, i)
    var us = days * 86400_000_000
    if i >= len(b) or b[i] != 32 or (i + 1 < len(b) and b[i + 1] == 66):
        return us
    i += 1
    var hh = _num(b, i, 2)
    _expect(b, i, 58)
    var mi = _num(b, i, 2)
    _expect(b, i, 58)
    var ss = _num(b, i, 2)
    us += (hh * 3600 + mi * 60 + ss) * 1_000_000
    if i < len(b) and b[i] == 46:
        i += 1
        var f = 0
        var nd = 0
        while i < len(b) and b[i] >= 48 and b[i] <= 57:
            if nd < 6:
                f = f * 10 + Int(b[i] - 48)
                nd += 1
            i += 1
        while nd < 6:
            f *= 10
            nd += 1
        us += f
    if i < len(b) and (b[i] == 43 or b[i] == 45):
        var sign = 1 if b[i] == 43 else -1
        i += 1
        var oh = _num(b, i, 2)
        var om = 0
        var os = 0
        if i < len(b) and b[i] == 58:
            i += 1
            om = _num(b, i, 2)
            if i < len(b) and b[i] == 58:
                i += 1
                os = _num(b, i, 2)
        us -= sign * (oh * 3600 + om * 60 + os) * 1_000_000
    return us


def _hexn(c: UInt8) raises -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    raise Error("pg: invalid bytea hex digit")


def decode_bytea(b: Span[UInt8, _]) raises -> List[UInt8]:
    """bytea_output=hex ('\\x...'); escape format is also accepted."""
    var n = len(b)
    if n >= 2 and b[0] == 92 and b[1] == 120:
        if (n - 2) % 2 != 0:
            raise Error("pg: odd-length bytea hex")
        var out = List[UInt8](capacity=(n - 2) // 2)
        var i = 2
        while i < n:
            out.append((_hexn(b[i]) << 4) | _hexn(b[i + 1]))
            i += 2
        return out^
    var out = List[UInt8](capacity=n)
    var i = 0
    while i < n:
        if b[i] == 92:
            if i + 1 < n and b[i + 1] == 92:
                out.append(92)
                i += 2
            elif i + 3 < n:
                out.append(UInt8((Int(b[i + 1]) - 48) * 64 + (Int(b[i + 2]) - 48) * 8 + (Int(b[i + 3]) - 48)))
                i += 4
            else:
                raise Error("pg: invalid bytea escape")
        else:
            out.append(b[i])
            i += 1
    return out^


def fmt_date(days: Int) -> String:
    var t = civil_from_days(days)
    return _pad(t[0], 4) + "-" + _pad(t[1], 2) + "-" + _pad(t[2], 2)


def _pad(v: Int, w: Int) -> String:
    var s = String(v)
    while s.byte_length() < w:
        s = "0" + s
    return s
