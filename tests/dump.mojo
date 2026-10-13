from std.sys import argv
from std.os import getenv
from pg import Conn, Params
from p2.sysio import c_write


def main() raises:
    var args = argv()
    if len(args) < 3:
        raise Error("usage: dump DSN SQL [PARAM...]")
    var c = Conn.connect(String(args[1]))
    var p = Params()
    for i in range(3, len(args)):
        p.add(String(args[i]))
    if getenv("DUMP_AUTH", "") == "1":
        var msg = "auth=" + c.auth_method + "\n"
        _ = c_write(2, msg.as_bytes().unsafe_ptr(), msg.byte_length())
    var r = c.query(String(args[2]), p)
    var out = List[UInt8](capacity=1 << 20)
    for i in range(r.nrows):
        for j in range(r.ncols()):
            if j > 0:
                out.append(9)
            out.extend(r.raw(i, j))
        out.append(10)
    _ = c_write(1, out.unsafe_ptr(), len(out))
    c.close()
