"""Fixed-size connection pool. Not thread-safe: guard with a lock or use one pool per thread."""

from pg.conn import Conn, Params
from pg.dsn import Config, parse_dsn
from pg.result import Result


struct Pool(Movable):
    var cfg: Config
    var size: Int
    var idle: List[Conn]
    var outstanding: Int

    def __init__(out self, var cfg: Config, size: Int):
        self.cfg = cfg^
        self.size = size
        self.idle = List[Conn]()
        self.outstanding = 0

    @staticmethod
    def open(dsn: String, size: Int) raises -> Pool:
        return Pool(parse_dsn(dsn), size)

    def acquire(mut self) raises -> Conn:
        """Idle conn, or a new one while fewer than size are open; raises when exhausted."""
        if len(self.idle) > 0:
            self.outstanding += 1
            return self.idle.pop()
        if self.outstanding + len(self.idle) >= self.size:
            raise Error("pg: pool exhausted (size " + String(self.size) + ")")
        var c = Conn.connect(self.cfg)
        self.outstanding += 1
        return c^

    def release(mut self, var c: Conn):
        """Returns c to the pool; rolls back an open transaction, drops broken conns."""
        self.outstanding -= 1
        if not c.broken and c.tx != 73:
            try:
                _ = c.exec("ROLLBACK")
            except:
                c.close()
        if c.broken:
            c.close()
            return
        self.idle.append(c^)

    def query(mut self, sql: String, params: Params) raises -> Result:
        var c = self.acquire()
        try:
            var r = c.query(sql, params)
            self.release(c^)
            return r^
        except e:
            self.release(c^)
            raise e^

    def query(mut self, sql: String) raises -> Result:
        return self.query(sql, Params())

    def open_conns(self) -> Int:
        return self.outstanding + len(self.idle)

    def close(mut self):
        for i in range(len(self.idle)):
            self.idle[i].close()
        self.idle.clear()
