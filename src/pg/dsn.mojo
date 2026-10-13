"""Connection config and DSN parsing (URL and libpq key=value forms)."""

from std.os import getenv


struct Config(Copyable, Movable):
    var host: String
    var port: Int
    var user: String
    var password: String
    var database: String
    var application_name: String
    var options: String
    var sslmode: String
    var connect_timeout_ms: Int
    var statement_timeout_ms: Int
    var read_only: Bool
    var statement_cache: Bool
    var param_keys: List[String]
    var param_vals: List[String]

    def __init__(out self):
        self.host = getenv("PGHOST", "")
        self.port = _atoi_or(getenv("PGPORT", "5432"), 5432)
        self.user = getenv("PGUSER", getenv("USER", "postgres"))
        self.password = getenv("PGPASSWORD", "")
        self.database = getenv("PGDATABASE", "")
        self.application_name = getenv("PGAPPNAME", "")
        self.options = getenv("PGOPTIONS", "")
        self.sslmode = getenv("PGSSLMODE", "disable")
        var ct = getenv("PGCONNECT_TIMEOUT", "")
        self.connect_timeout_ms = 10000 if ct.byte_length() == 0 else _atoi_or(ct, 10) * 1000
        self.statement_timeout_ms = 0
        self.read_only = False
        self.statement_cache = True
        self.param_keys = List[String]()
        self.param_vals = List[String]()

    def is_unix(self) -> Bool:
        return self.host.byte_length() == 0 or self.host.startswith("/") or self.host.startswith("@")

    def socket_path(self) -> String:
        var dir = self.host if self.host.byte_length() > 0 else String("/var/run/postgresql")
        if dir.find(".s.PGSQL.") >= 0:
            return dir
        return dir + "/.s.PGSQL." + String(self.port)

    def db(self) -> String:
        return self.database if self.database.byte_length() > 0 else self.user

    def startup_options(self) -> String:
        var o = self.options
        if self.read_only:
            o = _join_opt(o, "-c default_transaction_read_only=on")
        if self.statement_timeout_ms > 0:
            o = _join_opt(o, "-c statement_timeout=" + String(self.statement_timeout_ms))
        return o

    def set(mut self, key: String, val: String) raises:
        if key == "host" or key == "hostaddr":
            var h = val
            var comma = h.find(",")
            if comma >= 0:
                h = String(val[byte=0:comma])
            self.host = h
        elif key == "port":
            var p = val
            var comma = p.find(",")
            if comma >= 0:
                p = String(val[byte=0:comma])
            self.port = _atoi_or(p, -1)
            if self.port <= 0 or self.port > 65535:
                raise Error("pg: invalid port " + val)
        elif key == "user":
            self.user = val
        elif key == "password":
            self.password = val
        elif key == "dbname" or key == "database":
            self.database = val
        elif key == "application_name":
            self.application_name = val
        elif key == "fallback_application_name":
            if self.application_name.byte_length() == 0:
                self.application_name = val
        elif key == "options":
            self.options = val
        elif key == "sslmode":
            if val != "disable" and val != "allow" and val != "prefer" and val != "require" and val != "verify-ca" and val != "verify-full":
                raise Error("pg: invalid sslmode " + val)
            self.sslmode = val
        elif key == "connect_timeout":
            self.connect_timeout_ms = _atoi_or(val, 10) * 1000
        elif key == "statement_timeout":
            self.statement_timeout_ms = _atoi_or(val, 0)
        elif key == "read_only" or key == "default_transaction_read_only":
            self.read_only = _truthy(val)
        elif key == "statement_cache":
            self.statement_cache = _truthy(val)
        elif key == "client_encoding" or key == "target_session_attrs" or key == "sslrootcert" or key == "sslcert" or key == "sslkey" or key == "sslnegotiation":
            pass
        else:
            self.param_keys.append(key)
            self.param_vals.append(val)


def _sub(s: String, a: Int, b: Int) -> String:
    return String(s[byte=a:b])


def _join_opt(a: String, b: String) -> String:
    if a.byte_length() == 0:
        return b
    return a + " " + b


def _truthy(v: String) -> Bool:
    var l = v.lower()
    return l == "1" or l == "true" or l == "on" or l == "yes" or l == "t"


def _atoi_or(s: String, d: Int) -> Int:
    var b = s.as_bytes()
    if len(b) == 0:
        return d
    var v = 0
    var i = 0
    var neg = False
    if b[0] == 45:
        neg = True
        i = 1
    if i >= len(b):
        return d
    while i < len(b):
        if b[i] < 48 or b[i] > 57:
            return d
        v = v * 10 + Int(b[i] - 48)
        i += 1
    return -v if neg else v


def _hexv(c: UInt8) raises -> Int:
    if c >= 48 and c <= 57:
        return Int(c - 48)
    if c >= 97 and c <= 102:
        return Int(c - 87)
    if c >= 65 and c <= 70:
        return Int(c - 55)
    raise Error("pg: invalid percent-encoding in DSN")


def pct_decode(s: String) raises -> String:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    var i = 0
    while i < len(b):
        if b[i] == 37:
            if i + 2 >= len(b):
                raise Error("pg: invalid percent-encoding in DSN")
            out.append(UInt8(_hexv(b[i + 1]) * 16 + _hexv(b[i + 2])))
            i += 3
        else:
            out.append(b[i])
            i += 1
    return String(unsafe_from_utf8=out)


def parse_dsn(dsn: String) raises -> Config:
    var cfg = Config()
    if dsn.startswith("postgres://") or dsn.startswith("postgresql://"):
        _parse_url(dsn, cfg)
    else:
        _parse_kv(dsn, cfg)
    return cfg^


def _parse_url(dsn: String, mut cfg: Config) raises:
    var rest = String(dsn[byte = dsn.find("://") + 3 :])
    var query = String("")
    var q = rest.find("?")
    if q >= 0:
        query = String(rest[byte = q + 1 :])
        rest = _sub(rest, 0, q)
    var path = String("")
    var slash = rest.find("/")
    if slash >= 0:
        path = String(rest[byte = slash + 1 :])
        rest = _sub(rest, 0, slash)
    var at = rest.rfind("@")
    if at >= 0:
        var ui = String(rest[byte=0:at])
        rest = _sub(rest, at + 1, rest.byte_length())
        var colon = ui.find(":")
        if colon >= 0:
            cfg.user = pct_decode(String(ui[byte=0:colon]))
            cfg.password = pct_decode(String(ui[byte = colon + 1 :]))
        else:
            cfg.user = pct_decode(ui)
    if rest.byte_length() > 0:
        var comma = rest.find(",")
        if comma >= 0:
            rest = _sub(rest, 0, comma)
        var host = rest
        var port = String("")
        if rest.startswith("["):
            var rb = rest.find("]")
            if rb < 0:
                raise Error("pg: invalid IPv6 host in DSN")
            host = String(rest[byte=1:rb])
            if rest.byte_length() > rb + 1 and rest.as_bytes()[rb + 1] == 58:
                port = String(rest[byte = rb + 2 :])
        else:
            var colon = rest.rfind(":")
            if colon >= 0:
                host = String(rest[byte=0:colon])
                port = String(rest[byte = colon + 1 :])
        if host.byte_length() > 0:
            cfg.host = pct_decode(host)
        if port.byte_length() > 0:
            cfg.set("port", port)
    if path.byte_length() > 0:
        cfg.database = pct_decode(path)
    if query.byte_length() > 0:
        for kv in query.split("&"):
            var s = String(kv)
            if s.byte_length() == 0:
                continue
            var eq = s.find("=")
            if eq < 0:
                raise Error("pg: invalid DSN query parameter " + s)
            cfg.set(pct_decode(String(s[byte=0:eq])), pct_decode(String(s[byte = eq + 1 :])))


def _parse_kv(dsn: String, mut cfg: Config) raises:
    var b = dsn.as_bytes()
    var n = len(b)
    var i = 0
    while True:
        while i < n and (b[i] == 32 or b[i] == 9 or b[i] == 10 or b[i] == 13):
            i += 1
        if i >= n:
            break
        var ks = i
        while i < n and b[i] != 61 and b[i] != 32:
            i += 1
        var key = String(unsafe_from_utf8=b[ks:i])
        while i < n and b[i] == 32:
            i += 1
        if i >= n or b[i] != 61:
            raise Error("pg: missing \"=\" after \"" + key + "\" in DSN")
        i += 1
        while i < n and b[i] == 32:
            i += 1
        var val = List[UInt8]()
        if i < n and b[i] == 39:
            i += 1
            var closed = False
            while i < n:
                if b[i] == 92 and i + 1 < n:
                    val.append(b[i + 1])
                    i += 2
                elif b[i] == 39:
                    closed = True
                    i += 1
                    break
                else:
                    val.append(b[i])
                    i += 1
            if not closed:
                raise Error("pg: unterminated quoted string in DSN")
        else:
            while i < n and b[i] != 32 and b[i] != 9 and b[i] != 10 and b[i] != 13:
                if b[i] == 92 and i + 1 < n:
                    val.append(b[i + 1])
                    i += 2
                else:
                    val.append(b[i])
                    i += 1
        cfg.set(key, String(unsafe_from_utf8=val))
