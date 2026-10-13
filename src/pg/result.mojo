"""Query results: column metadata plus row cells stored as raw DataRow payloads."""

from pg.conv import parse_int, parse_f64, parse_bool, parse_date_days, parse_ts_us, decode_bytea
from p2.gomath import nan64

comptime OID_BOOL = 16
comptime OID_BYTEA = 17
comptime OID_INT8 = 20
comptime OID_INT2 = 21
comptime OID_INT4 = 23
comptime OID_TEXT = 25
comptime OID_OID = 26
comptime OID_JSON = 114
comptime OID_FLOAT4 = 700
comptime OID_FLOAT8 = 701
comptime OID_VARCHAR = 1043
comptime OID_DATE = 1082
comptime OID_TIMESTAMP = 1114
comptime OID_TIMESTAMPTZ = 1184
comptime OID_NUMERIC = 1700
comptime OID_JSONB = 3802


@fieldwise_init
struct Field(Copyable, Movable):
    var name: String
    var table_oid: Int
    var column: Int
    var type_oid: Int
    var type_size: Int
    var typmod: Int
    var format: Int


struct Notice(Copyable, Movable):
    """ErrorResponse / NoticeResponse fields."""

    var severity: String
    var code: String
    var message: String
    var detail: String
    var hint: String
    var position: String
    var where_: String
    var schema: String
    var table: String
    var column: String
    var constraint: String
    var routine: String

    def __init__(out self):
        self.severity = ""
        self.code = ""
        self.message = ""
        self.detail = ""
        self.hint = ""
        self.position = ""
        self.where_ = ""
        self.schema = ""
        self.table = ""
        self.column = ""
        self.constraint = ""
        self.routine = ""

    def error_text(self) -> String:
        var s = "pg: " + self.severity + ": " + self.message + " (SQLSTATE " + self.code + ")"
        if self.detail.byte_length() > 0:
            s += " DETAIL: " + self.detail
        return s


def sqlstate(e: Error) -> String:
    """SQLSTATE of an error raised by this library, or "" if not a server error."""
    var s = String(e)
    var p = s.find("(SQLSTATE ")
    if p < 0 or s.byte_length() < p + 15:
        return ""
    return String(s[byte = p + 10 : p + 15])


@always_inline
def _be32(p: Pointer[UInt8, _], off: Int) -> Int:
    return Int(Int32((UInt32(p[unsafe_offset=off]) << 24) | (UInt32(p[unsafe_offset=off + 1]) << 16) | (UInt32(p[unsafe_offset=off + 2]) << 8) | UInt32(p[unsafe_offset=off + 3])))


struct Result(Movable, Sized):
    """Rows of one statement. Cell k = r*ncols + c starts at data[offs[k]]; its
    4-byte big-endian length (-1 = NULL) sits just before it."""

    var fields: List[Field]
    var data: List[UInt8]
    var offs: List[Int]
    var nrows: Int
    var tag: String

    def __init__(out self):
        self.fields = List[Field]()
        self.data = List[UInt8]()
        self.offs = List[Int]()
        self.nrows = 0
        self.tag = ""

    def ncols(self) -> Int:
        return len(self.fields)

    def __len__(self) -> Int:
        return self.nrows

    def rows_affected(self) -> Int:
        var sp = self.tag.rfind(" ")
        if sp < 0:
            return 0
        try:
            return parse_int(self.tag.as_bytes()[sp + 1 :])
        except:
            return 0

    def col(self, name: String) raises -> Int:
        for i in range(len(self.fields)):
            if self.fields[i].name == name:
                return i
        raise Error("pg: no column \"" + name + "\"")

    def names(self) -> List[String]:
        var out = List[String]()
        for f in self.fields:
            out.append(f.name)
        return out^

    def type_oid(self, c: Int) -> Int:
        return self.fields[c].type_oid

    @always_inline
    def _pos(self, r: Int, c: Int) -> Int:
        return self.offs[r * len(self.fields) + c]

    @always_inline
    def cell_len(self, r: Int, c: Int) -> Int:
        """Byte length of the text value, -1 for NULL."""
        return _be32(self.data.unsafe_ptr(), self._pos(r, c) - 4)

    def is_null(self, r: Int, c: Int) -> Bool:
        return self.cell_len(r, c) < 0

    def raw(self, r: Int, c: Int) -> Span[UInt8, origin_of(self.data)]:
        var p = self._pos(r, c)
        var n = self.cell_len(r, c)
        return Span(self.data)[p : p + (n if n > 0 else 0)]

    def _nn(self, r: Int, c: Int) raises -> Span[UInt8, origin_of(self.data)]:
        if self.cell_len(r, c) < 0:
            raise Error("pg: NULL in column \"" + self.fields[c].name + "\" row " + String(r))
        return self.raw(r, c)

    def text(self, r: Int, c: Int) -> String:
        """Text value; NULL reads as ""."""
        return String(unsafe_from_utf8=self.raw(r, c))

    def int(self, r: Int, c: Int) raises -> Int:
        return parse_int(self._nn(r, c))

    def float(self, r: Int, c: Int) raises -> Float64:
        """float8/numeric/int text to Float64; float4 columns yield Float64(Float32)."""
        var v = parse_f64(self._nn(r, c))
        if self.fields[c].type_oid == OID_FLOAT4:
            return Float64(Float32(v))
        return v

    def float32(self, r: Int, c: Int) raises -> Float32:
        return Float32(parse_f64(self._nn(r, c)))

    def bool(self, r: Int, c: Int) raises -> Bool:
        return parse_bool(self._nn(r, c))

    def numeric(self, r: Int, c: Int) raises -> String:
        return String(unsafe_from_utf8=self._nn(r, c))

    def date_days(self, r: Int, c: Int) raises -> Int:
        return parse_date_days(self._nn(r, c))

    def timestamp_us(self, r: Int, c: Int) raises -> Int:
        return parse_ts_us(self._nn(r, c))

    def json(self, r: Int, c: Int) raises -> String:
        return String(unsafe_from_utf8=self._nn(r, c))

    def bytea(self, r: Int, c: Int) raises -> List[UInt8]:
        return decode_bytea(self._nn(r, c))

    def int_or(self, r: Int, c: Int, d: Int) raises -> Int:
        return d if self.is_null(r, c) else self.int(r, c)

    def float_or(self, r: Int, c: Int, d: Float64) raises -> Float64:
        return d if self.is_null(r, c) else self.float(r, c)

    def float_col(self, c: Int) raises -> List[Float64]:
        """Whole column as Float64; NULL -> NaN."""
        var out = List[Float64](capacity=self.nrows)
        var f4 = self.fields[c].type_oid == OID_FLOAT4
        for r in range(self.nrows):
            if self.is_null(r, c):
                out.append(nan64())
            else:
                var v = parse_f64(self.raw(r, c))
                out.append(Float64(Float32(v)) if f4 else v)
        return out^

    def int_col(self, c: Int) raises -> List[Int]:
        var out = List[Int](capacity=self.nrows)
        for r in range(self.nrows):
            out.append(self.int(r, c))
        return out^

    def text_col(self, c: Int) -> List[String]:
        var out = List[String](capacity=self.nrows)
        for r in range(self.nrows):
            out.append(self.text(r, c))
        return out^
