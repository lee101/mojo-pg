"""Postgres v3 wire-protocol connection (simple + extended query, text format)."""

from std.ffi import external_call
from std.collections import Dict
from std.memory import unsafe_memcpy, unsafe_memmove
from net.sock import Conn as Sock, strerror
from p2.ptr import keep, raw
from p2.gofmt import go_format_float
from pg.dsn import Config, parse_dsn
from pg.result import Result, Field, Notice
from pg.crypto import Scram, md5_password

comptime PB = Pointer[UInt8, MutUntrackedOrigin]
comptime PROTO_30 = 196608
comptime SSL_REQUEST = 80877103
comptime CANCEL_REQUEST = 80877102
comptime CACHE_MAX = 512
comptime RBUF = 1 << 18


def _errno() -> Int:
    return Int(external_call["__errno_location", Pointer[Int32, MutUntrackedOrigin]]()[])


@always_inline
def _be32(p: PB, off: Int) -> Int:
    return Int(Int32((UInt32(p[unsafe_offset=off]) << 24) | (UInt32(p[unsafe_offset=off + 1]) << 16) | (UInt32(p[unsafe_offset=off + 2]) << 8) | UInt32(p[unsafe_offset=off + 3])))


@always_inline
def _be16(p: PB, off: Int) -> Int:
    return Int(Int16((UInt16(p[unsafe_offset=off]) << 8) | UInt16(p[unsafe_offset=off + 1])))


def _cstr_at(p: PB, mut i: Int, end: Int) -> String:
    var s = i
    while i < end and p[unsafe_offset=i] != 0:
        i += 1
    var out = String(unsafe_from_utf8=Span(unsafe_ptr=p.unsafe_offset(s), length=i - s))
    i += 1
    return out


def _unix_socket(path: String, timeout_ms: Int) raises -> Int32:
    var pb = path.as_bytes()
    if len(pb) > 107:
        raise Error("pg: unix socket path too long: " + path)
    _ = external_call["signal", Int](Int32(13), Int(1))
    var fd = external_call["socket", Int32](Int32(1), Int32(1 | 0x80000), Int32(0))
    if fd < 0:
        raise Error("pg: socket: " + strerror(_errno()))
    var tv = List[Int](length=2, fill=0)
    tv[0] = timeout_ms // 1000
    tv[1] = (timeout_ms % 1000) * 1000
    _ = external_call["setsockopt", Int32](fd, Int32(1), Int32(20), tv.unsafe_ptr(), UInt32(16))
    _ = external_call["setsockopt", Int32](fd, Int32(1), Int32(21), tv.unsafe_ptr(), UInt32(16))
    keep(tv)
    var addr = List[UInt8](length=110, fill=0)
    addr[0] = 1
    for i in range(len(pb)):
        addr[2 + i] = pb[i]
    if external_call["connect", Int32](fd, Int(addr.unsafe_ptr()), UInt32(2 + len(pb) + 1)) != 0:
        var en = _errno()
        _ = external_call["close", Int32](fd)
        raise Error("pg: dial unix " + path + ": connect: " + strerror(en))
    keep(addr)
    return fd


def _dial(cfg: Config) raises -> Sock:
    if cfg.is_unix():
        return Sock(_unix_socket(cfg.socket_path(), cfg.connect_timeout_ms), "localhost")
    return Sock.dial(cfg.host, cfg.port, False, cfg.connect_timeout_ms)


struct Params(Movable, Sized):
    """Text-format bind parameters; NULLs allowed."""

    var vals: List[String]
    var nulls: List[Bool]

    def __init__(out self):
        self.vals = List[String]()
        self.nulls = List[Bool]()

    def __init__(out self, *vals: String):
        self.vals = List[String]()
        self.nulls = List[Bool]()
        for v in vals:
            self.vals.append(v)
            self.nulls.append(False)

    def add(mut self, v: String):
        self.vals.append(v)
        self.nulls.append(False)

    def add(mut self, v: Int):
        self.add(String(v))

    def add(mut self, v: Float64):
        """Shortest round-trip text (Go strconv 'g', -1)."""
        self.add(go_format_float(v, "g", -1))

    def add(mut self, v: Bool):
        self.add(String("t") if v else String("f"))

    def add_null(mut self):
        self.vals.append("")
        self.nulls.append(True)

    def __len__(self) -> Int:
        return len(self.vals)


struct Stmt(Movable):
    var name: String
    var fields: List[Field]
    var param_oids: List[Int]

    def __init__(out self, name: String):
        self.name = name
        self.fields = List[Field]()
        self.param_oids = List[Int]()


struct Conn(Movable):
    """One server session. Not thread-safe: use from one thread at a time."""

    var cfg: Config
    var sock: Sock
    var rbuf: List[UInt8]
    var rpos: Int
    var rend: Int
    var wbuf: List[UInt8]
    var server_params: Dict[String, String]
    var pid: Int
    var secret: List[UInt8]
    var tx: UInt8
    var notices: List[Notice]
    var notifications: List[String]
    var last_error: Notice
    var stmts: List[Stmt]
    var cache: Dict[String, Int]
    var named: Dict[String, Int]
    var seq: Int
    var broken: Bool
    var auth_method: String
    var _parsed: Bool
    var _pdesc: List[Int]

    def __init__(out self, var cfg: Config, var sock: Sock):
        self.cfg = cfg^
        self.sock = sock^
        self.rbuf = List[UInt8](length=RBUF, fill=0)
        self.rpos = 0
        self.rend = 0
        self.wbuf = List[UInt8](capacity=4096)
        self.server_params = Dict[String, String]()
        self.pid = 0
        self.secret = List[UInt8]()
        self.tx = 0
        self.notices = List[Notice]()
        self.notifications = List[String]()
        self.last_error = Notice()
        self.stmts = List[Stmt]()
        self.cache = Dict[String, Int]()
        self.named = Dict[String, Int]()
        self.seq = 0
        self.broken = False
        self.auth_method = "trust"
        self._parsed = False
        self._pdesc = List[Int]()

    @staticmethod
    def connect(dsn: String) raises -> Conn:
        return Conn.connect(parse_dsn(dsn))

    @staticmethod
    def connect(cfg: Config) raises -> Conn:
        var c = Conn(cfg.copy(), _dial(cfg))
        if cfg.sslmode != "disable" and cfg.sslmode != "allow" and not cfg.is_unix():
            c._ssl_request()
        c._startup()
        c.sock.set_timeout_ms(0)
        return c^

    def _ssl_request(mut self) raises:
        """TLS hook: SSLRequest then OpenSSL handshake (verify-full verifies the cert + host)."""
        self._put_i32(8)
        self._put_i32(SSL_REQUEST)
        self._flush()
        var b = List[UInt8](length=1, fill=0)
        var n = external_call["recv", Int](self.sock.fd, b.unsafe_ptr(), 1, Int32(0))
        if n != 1:
            raise Error("pg: SSLRequest: no response")
        if b[0] == 83:
            self.sock._handshake(self.cfg.sslmode != "verify-full" and self.cfg.sslmode != "verify-ca")
        elif self.cfg.sslmode != "prefer":
            raise Error("pg: server does not support SSL, but SSL was required")

    # ---- write side

    @always_inline
    def _put_u8(mut self, v: Int):
        self.wbuf.append(UInt8(v))

    def _put_i16(mut self, v: Int):
        self.wbuf.append(UInt8((v >> 8) & 255))
        self.wbuf.append(UInt8(v & 255))

    def _put_i32(mut self, v: Int):
        self.wbuf.append(UInt8((v >> 24) & 255))
        self.wbuf.append(UInt8((v >> 16) & 255))
        self.wbuf.append(UInt8((v >> 8) & 255))
        self.wbuf.append(UInt8(v & 255))

    def _put_bytes(mut self, b: Span[UInt8, _]):
        self.wbuf.extend(b)

    def _put_cstr(mut self, s: String) raises:
        var b = s.as_bytes()
        for x in b:
            if x == 0:
                raise Error("pg: string contains NUL byte")
        self.wbuf.extend(b)
        self.wbuf.append(0)

    def _begin(mut self, t: UInt8) -> Int:
        self.wbuf.append(t)
        var pos = len(self.wbuf)
        self._put_i32(0)
        return pos

    def _end(mut self, pos: Int):
        var n = len(self.wbuf) - pos
        self.wbuf[pos] = UInt8((n >> 24) & 255)
        self.wbuf[pos + 1] = UInt8((n >> 16) & 255)
        self.wbuf[pos + 2] = UInt8((n >> 8) & 255)
        self.wbuf[pos + 3] = UInt8(n & 255)

    def _flush(mut self) raises:
        try:
            self.sock.write_all(self.wbuf)
        except e:
            self.broken = True
            self.wbuf.clear()
            raise Error("pg: " + String(e))
        self.wbuf.clear()

    # ---- read side

    def _recv(mut self, off: Int, n: Int) raises -> Int:
        var p = raw(self.rbuf.unsafe_ptr()).unsafe_offset(off)
        while True:
            var r: Int
            if self.sock.ssl != 0:
                r = Int(external_call["SSL_read", Int32](self.sock.ssl, p, Int32(n)))
                if r <= 0:
                    var e = Int(external_call["SSL_get_error", Int32](self.sock.ssl, Int32(r)))
                    if e == 6 or (e == 5 and _errno() == 0):
                        return 0
                    self.broken = True
                    raise Error("pg: tls read error " + String(e))
                return r
            r = external_call["recv", Int](self.sock.fd, p, n, Int32(0))
            if r >= 0:
                return r
            var en = _errno()
            if en == 4:
                continue
            self.broken = True
            if en == 11:
                raise Error("pg: read: i/o timeout")
            raise Error("pg: read: " + strerror(en))

    def _fill(mut self, need: Int) raises:
        var avail = self.rend - self.rpos
        if avail >= need:
            return
        if self.rpos > 0:
            if avail > 0:
                var p = raw(self.rbuf.unsafe_ptr())
                unsafe_memmove(dest=p, src=p.unsafe_offset(self.rpos), count=avail)
            self.rpos = 0
            self.rend = avail
        if need > len(self.rbuf):
            self.rbuf.resize(max(need, 2 * len(self.rbuf)), 0)
        while self.rend < need:
            var n = self._recv(self.rend, len(self.rbuf) - self.rend)
            if n == 0:
                self.broken = True
                raise Error("pg: server closed the connection unexpectedly")
            self.rend += n

    def _shrink(mut self):
        if len(self.rbuf) > 16 * RBUF and self.rpos == self.rend:
            self.rbuf = List[UInt8](length=RBUF, fill=0)
            self.rpos = 0
            self.rend = 0

    def _next(mut self) raises -> Tuple[UInt8, Int, Int]:
        """Next backend message: (type, payload offset in rbuf, payload length).
        The payload is valid until the next call."""
        self._fill(5)
        var p = raw(self.rbuf.unsafe_ptr())
        var t = p[unsafe_offset=self.rpos]
        var n = _be32(p, self.rpos + 1)
        if n < 4:
            self.broken = True
            raise Error("pg: invalid message length")
        self._fill(1 + n)
        var off = self.rpos + 5
        self.rpos += 1 + n
        return (t, off, n - 4)

    def _p(self) -> PB:
        return raw(self.rbuf.unsafe_ptr())

    def _notice(self, off: Int, n: Int) -> Notice:
        var p = self._p()
        var i = off
        var end = off + n
        var r = Notice()
        while i < end:
            var code = p[unsafe_offset=i]
            i += 1
            if code == 0:
                break
            var v = _cstr_at(p, i, end)
            if code == 86 or (code == 83 and r.severity.byte_length() == 0):
                r.severity = v
            elif code == 67:
                r.code = v
            elif code == 77:
                r.message = v
            elif code == 68:
                r.detail = v
            elif code == 72:
                r.hint = v
            elif code == 80:
                r.position = v
            elif code == 87:
                r.where_ = v
            elif code == 115:
                r.schema = v
            elif code == 116:
                r.table = v
            elif code == 99:
                r.column = v
            elif code == 110:
                r.constraint = v
            elif code == 82:
                r.routine = v
        return r^

    def _async(mut self, t: UInt8, off: Int, n: Int) raises -> Bool:
        """Handles messages that may arrive at any time. True if consumed."""
        if t == 78:
            if len(self.notices) >= 256:
                _ = self.notices.pop(0)
            self.notices.append(self._notice(off, n))
            return True
        if t == 83:
            var i = off
            var p = self._p()
            var k = _cstr_at(p, i, off + n)
            var v = _cstr_at(p, i, off + n)
            self.server_params[k] = v
            return True
        if t == 65:
            var p = self._p()
            var i = off + 4
            var ch = _cstr_at(p, i, off + n)
            var pl = _cstr_at(p, i, off + n)
            self.notifications.append(ch + ":" + pl)
            return True
        return False

    def _fields(self, off: Int, n: Int) -> List[Field]:
        var p = self._p()
        var cnt = _be16(p, off)
        var i = off + 2
        var end = off + n
        var out = List[Field](capacity=cnt)
        for _ in range(cnt):
            var name = _cstr_at(p, i, end)
            out.append(Field(name, Int(UInt32(_be32(p, i))), _be16(p, i + 4), Int(UInt32(_be32(p, i + 6))), _be16(p, i + 10), _be32(p, i + 12), _be16(p, i + 16)))
            i += 18
        return out^

    def _row(mut self, mut res: Result, off: Int, n: Int) raises:
        var p = self._p()
        var nc = _be16(p, off)
        if nc != len(res.fields):
            self.broken = True
            raise Error("pg: DataRow has " + String(nc) + " columns, expected " + String(len(res.fields)))
        var base = len(res.data) - off
        var old = len(res.data)
        res.data.resize(unsafe_uninit_length=old + n)
        unsafe_memcpy(dest=raw(res.data.unsafe_ptr()).unsafe_offset(old), src=p.unsafe_offset(off), count=n)
        var i = off + 2
        var end = off + n
        for _ in range(nc):
            if i + 4 > end:
                self.broken = True
                raise Error("pg: truncated DataRow")
            var l = _be32(p, i)
            i += 4
            res.offs.append(base + i)
            if l > 0:
                i += l
        res.nrows += 1

    def _proto_err(mut self, t: UInt8) -> Error:
        self.broken = True
        return Error("pg: unexpected message '" + chr(Int(t)) + "'")

    # ---- startup / auth

    def _startup(mut self) raises:
        var pos = len(self.wbuf)
        self._put_i32(0)
        self._put_i32(PROTO_30)
        var ks = List[String]()
        var vs = List[String]()
        ks.append("user")
        vs.append(self.cfg.user)
        ks.append("database")
        vs.append(self.cfg.db())
        if self.cfg.application_name.byte_length() > 0:
            ks.append("application_name")
            vs.append(self.cfg.application_name)
        ks.append("client_encoding")
        vs.append("UTF8")
        ks.append("DateStyle")
        vs.append("ISO")
        ks.append("extra_float_digits")
        vs.append("3")
        var opts = self.cfg.startup_options()
        if opts.byte_length() > 0:
            ks.append("options")
            vs.append(opts)
        for i in range(len(self.cfg.param_keys)):
            ks.append(self.cfg.param_keys[i])
            vs.append(self.cfg.param_vals[i])
        for i in range(len(ks)):
            self._put_cstr(ks[i])
            self._put_cstr(vs[i])
        self._put_u8(0)
        var n = len(self.wbuf) - pos
        self.wbuf[pos] = UInt8((n >> 24) & 255)
        self.wbuf[pos + 1] = UInt8((n >> 16) & 255)
        self.wbuf[pos + 2] = UInt8((n >> 8) & 255)
        self.wbuf[pos + 3] = UInt8(n & 255)
        self._flush()
        var scram = Scram("")
        var scram_state = 0
        while True:
            var m = self._next()
            var t = m[0]
            var off = m[1]
            var n2 = m[2]
            if t == 82:
                var code = _be32(self._p(), off)
                if code == 0:
                    if scram_state == 1:
                        raise Error("pg: SCRAM: server skipped final message")
                elif code == 3:
                    self._need_pw()
                    self.auth_method = "cleartext"
                    var pw = self.cfg.password
                    var q = self._begin(112)
                    self._put_cstr(pw)
                    self._end(q)
                    self._flush()
                elif code == 5:
                    self._need_pw()
                    self.auth_method = "md5"
                    var salt = List[UInt8]()
                    for k in range(4):
                        salt.append(self._p()[unsafe_offset=off + 4 + k])
                    var q = self._begin(112)
                    self._put_cstr(md5_password(self.cfg.user, self.cfg.password, salt))
                    self._end(q)
                    self._flush()
                elif code == 10:
                    var i = off + 4
                    var ok = False
                    var mechs = String("")
                    while i < off + n2 and self._p()[unsafe_offset=i] != 0:
                        var mech = _cstr_at(self._p(), i, off + n2)
                        mechs += mech + " "
                        if mech == "SCRAM-SHA-256":
                            ok = True
                    if not ok:
                        raise Error("pg: no supported SASL mechanism in: " + mechs)
                    self._need_pw()
                    scram = Scram(self.cfg.password)
                    var first = scram.client_first()
                    var q = self._begin(112)
                    self._put_cstr("SCRAM-SHA-256")
                    self._put_i32(first.byte_length())
                    self._put_bytes(first.as_bytes())
                    self._end(q)
                    self._flush()
                    scram_state = 1
                elif code == 11:
                    if scram_state != 1:
                        raise Error("pg: unexpected SASLContinue")
                    var sf = String(unsafe_from_utf8=Span(unsafe_ptr=self._p().unsafe_offset(off + 4), length=n2 - 4))
                    var fin = scram.client_final(sf)
                    var q = self._begin(112)
                    self._put_bytes(fin.as_bytes())
                    self._end(q)
                    self._flush()
                elif code == 12:
                    if scram_state != 1:
                        raise Error("pg: unexpected SASLFinal")
                    scram.verify_final(String(unsafe_from_utf8=Span(unsafe_ptr=self._p().unsafe_offset(off + 4), length=n2 - 4)))
                    scram_state = 2
                    self.auth_method = "scram-sha-256"
                else:
                    raise Error("pg: unsupported authentication method " + String(code))
            elif t == 75:
                self.pid = _be32(self._p(), off)
                self.secret = List[UInt8]()
                for k in range(4, n2):
                    self.secret.append(self._p()[unsafe_offset=off + k])
            elif t == 90:
                self.tx = self._p()[unsafe_offset=off]
                return
            elif t == 69:
                self.last_error = self._notice(off, n2)
                self.broken = True
                raise Error(self.last_error.error_text())
            elif t == 118:
                pass
            elif not self._async(t, off, n2):
                raise self._proto_err(t)

    def _need_pw(self) raises:
        if self.cfg.password.byte_length() == 0:
            raise Error("pg: server requested a password but none was supplied")

    # ---- simple query

    def exec(mut self, sql: String) raises -> List[Result]:
        """Simple-query protocol: may hold several ';'-separated statements; one Result each."""
        self._send_simple(sql)
        return self._read_simple()

    def _send_simple(mut self, sql: String) raises:
        self._check()
        var q = self._begin(81)
        self._put_cstr(sql)
        self._end(q)
        self._flush()

    def _read_simple(mut self) raises -> List[Result]:
        var out = List[Result]()
        var cur = Result()
        var err = False
        var en = Notice()
        while True:
            var m = self._next()
            var t = m[0]
            if t == 68:
                self._row(cur, m[1], m[2])
            elif t == 84:
                cur = Result()
                cur.fields = self._fields(m[1], m[2])
            elif t == 67:
                var i = m[1]
                cur.tag = _cstr_at(self._p(), i, m[1] + m[2])
                out.append(cur^)
                cur = Result()
            elif t == 73:
                out.append(Result())
                cur = Result()
            elif t == 69:
                en = self._notice(m[1], m[2])
                err = True
            elif t == 90:
                self.tx = self._p()[unsafe_offset=m[1]]
                self._shrink()
                break
            elif t == 71:
                var f = self._begin(102)
                self._put_cstr("COPY FROM STDIN is not supported")
                self._end(f)
                self._flush()
            elif t == 72 or t == 100 or t == 99:
                pass
            elif not self._async(t, m[1], m[2]):
                raise self._proto_err(t)
        if err:
            self.last_error = en.copy()
            raise Error(en.error_text())
        return out^

    def exec1(mut self, sql: String) raises -> Result:
        """Simple query returning the last statement's Result."""
        var rs = self.exec(sql)
        if len(rs) == 0:
            return Result()
        return rs.pop()

    # ---- extended query

    def _check(self) raises:
        if self.broken:
            raise Error("pg: connection is broken")

    def _send_parse(mut self, name: String, sql: String) raises:
        var q = self._begin(80)
        self._put_cstr(name)
        self._put_cstr(sql)
        self._put_i16(0)
        self._end(q)

    def _send_describe(mut self, kind: UInt8, name: String) raises:
        var q = self._begin(68)
        self._put_u8(Int(kind))
        self._put_cstr(name)
        self._end(q)

    def _send_bind(mut self, stmt: String, params: Params) raises:
        var q = self._begin(66)
        self._put_u8(0)
        self._put_cstr(stmt)
        self._put_i16(0)
        self._put_i16(len(params))
        for i in range(len(params)):
            if params.nulls[i]:
                self._put_i32(-1)
            else:
                var b = params.vals[i].as_bytes()
                self._put_i32(len(b))
                self._put_bytes(b)
        self._put_i16(0)
        self._end(q)

    def _send_exec_sync(mut self) raises:
        var q = self._begin(69)
        self._put_u8(0)
        self._put_i32(0)
        self._end(q)
        self._send_sync()

    def _send_sync(mut self):
        self.wbuf.append(83)
        self._put_i32(4)

    def _read_ext(mut self, mut res: Result) raises:
        self._parsed = False
        var err = False
        var en = Notice()
        while True:
            var m = self._next()
            var t = m[0]
            if t == 68:
                self._row(res, m[1], m[2])
            elif t == 84:
                res.fields = self._fields(m[1], m[2])
            elif t == 67:
                var i = m[1]
                res.tag = _cstr_at(self._p(), i, m[1] + m[2])
            elif t == 49:
                self._parsed = True
            elif t == 50 or t == 110 or t == 73 or t == 115 or t == 51:
                pass
            elif t == 116:
                var p = self._p()
                var cnt = _be16(p, m[1])
                self._pdesc = List[Int](capacity=cnt)
                for k in range(cnt):
                    self._pdesc.append(Int(UInt32(_be32(p, m[1] + 2 + 4 * k))))
            elif t == 69:
                en = self._notice(m[1], m[2])
                err = True
            elif t == 90:
                self.tx = self._p()[unsafe_offset=m[1]]
                self._shrink()
                break
            elif t == 71:
                var f = self._begin(102)
                self._put_cstr("COPY FROM STDIN is not supported")
                self._end(f)
                self._flush()
            elif t == 72 or t == 100 or t == 99:
                pass
            elif not self._async(t, m[1], m[2]):
                raise self._proto_err(t)
        if err:
            self.last_error = en.copy()
            raise Error(en.error_text())

    def query(mut self, sql: String) raises -> Result:
        return self.query(sql, Params())

    def query(mut self, sql: String, params: Params) raises -> Result:
        """Extended protocol, text params/results. Uses the per-conn statement cache
        unless cfg.statement_cache is off."""
        self._check()
        if not self.cfg.statement_cache:
            return self.query_unnamed(sql, params)
        var idx = self.cache.get(sql, -1)
        if idx >= 0:
            var res = Result()
            res.fields = self.stmts[idx].fields.copy()
            var sname = self.stmts[idx].name
            self._send_bind(sname, params)
            self._send_exec_sync()
            self._flush()
            try:
                self._read_ext(res)
            except e:
                var code = self.last_error.code
                if code == "0A000" or code == "26000":
                    _ = self.cache.pop(sql, -1)
                    if self.tx == 73:
                        return self.query(sql, params)
                raise e^
            return res^
        if len(self.cache) >= CACHE_MAX:
            return self.query_unnamed(sql, params)
        var st = Stmt("mpg_" + String(self.seq))
        self.seq += 1
        var sname = st.name
        self._send_parse(sname, sql)
        self._send_describe(83, sname)
        self._send_bind(sname, params)
        self._send_exec_sync()
        self._flush()
        var res = Result()
        try:
            self._read_ext(res)
        except e:
            if self._parsed:
                self._remember(sql, st^, res)
            raise e^
        self._remember(sql, st^, res)
        return res^

    def _remember(mut self, sql: String, var st: Stmt, res: Result):
        st.fields = res.fields.copy()
        st.param_oids = self._pdesc.copy()
        self.cache[sql] = len(self.stmts)
        self.stmts.append(st^)

    def query_unnamed(mut self, sql: String, params: Params) raises -> Result:
        """Parse/Bind/Describe/Execute/Sync on the unnamed statement (one round trip)."""
        self._check()
        self._send_parse("", sql)
        self._send_bind("", params)
        self._send_describe(80, "")
        self._send_exec_sync()
        self._flush()
        var res = Result()
        self._read_ext(res)
        return res^

    def prepare(mut self, name: String, sql: String) raises -> List[Int]:
        """Named server-side prepared statement; returns parameter type OIDs."""
        self._check()
        self._send_parse(name, sql)
        self._send_describe(83, name)
        self._send_sync()
        self._flush()
        var res = Result()
        self._read_ext(res)
        var st = Stmt(name)
        st.fields = res.fields.copy()
        st.param_oids = self._pdesc.copy()
        self.named[name] = len(self.stmts)
        self.stmts.append(st^)
        return self._pdesc.copy()

    def query_prepared(mut self, name: String, params: Params) raises -> Result:
        self._check()
        var idx = self.named.get(name, -1)
        if idx < 0:
            raise Error("pg: unknown prepared statement \"" + name + "\"")
        var res = Result()
        res.fields = self.stmts[idx].fields.copy()
        self._send_bind(name, params)
        self._send_exec_sync()
        self._flush()
        self._read_ext(res)
        return res^

    def deallocate(mut self, name: String) raises:
        self._check()
        _ = self.named.pop(name, -1)
        var q = self._begin(67)
        self._put_u8(83)
        self._put_cstr(name)
        self._end(q)
        self._send_sync()
        self._flush()
        var res = Result()
        self._read_ext(res)

    # ---- misc

    def tx_status(self) -> String:
        """"I" idle, "T" in transaction, "E" failed transaction."""
        return chr(Int(self.tx))

    def param(self, key: String) -> String:
        return self.server_params.get(key, String(""))

    def cancel(self) raises:
        """Out-of-band CancelRequest for the query running on this session."""
        var s = _dial(self.cfg)
        var b = List[UInt8]()
        for v in [16, CANCEL_REQUEST, self.pid]:
            b.append(UInt8((v >> 24) & 255))
            b.append(UInt8((v >> 16) & 255))
            b.append(UInt8((v >> 8) & 255))
            b.append(UInt8(v & 255))
        for x in self.secret:
            b.append(x)
        s.write_all(b)
        s.close()

    def close(mut self):
        if not self.sock.closed and not self.broken:
            self.wbuf.clear()
            self.wbuf.append(88)
            self._put_i32(4)
            try:
                self.sock.write_all(self.wbuf)
            except:
                pass
        self.sock.close()
        self.broken = True
