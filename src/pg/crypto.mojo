"""libcrypto (OpenSSL 3) primitives for MD5 and SCRAM-SHA-256 auth."""

from std.ffi import external_call
from std.base64 import b64encode, b64decode
from p2.ptr import keep


def sha256(data: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](length=32, fill=0)
    _ = external_call["SHA256", Int](data.unsafe_ptr(), len(data), out.unsafe_ptr())
    keep(data)
    return out^


def hmac_sha256(key: Span[UInt8, _], msg: Span[UInt8, _]) -> List[UInt8]:
    var out = List[UInt8](length=32, fill=0)
    var olen = List[UInt32](length=1, fill=0)
    var md = external_call["EVP_sha256", Int]()
    _ = external_call["HMAC", Int](md, key.unsafe_ptr(), Int32(len(key)), msg.unsafe_ptr(), len(msg), out.unsafe_ptr(), olen.unsafe_ptr())
    keep(key)
    keep(msg)
    keep(olen)
    return out^


def pbkdf2_sha256(password: Span[UInt8, _], salt: Span[UInt8, _], iters: Int) raises -> List[UInt8]:
    var out = List[UInt8](length=32, fill=0)
    var md = external_call["EVP_sha256", Int]()
    var rc = external_call["PKCS5_PBKDF2_HMAC", Int32](password.unsafe_ptr(), Int32(len(password)), salt.unsafe_ptr(), Int32(len(salt)), Int32(iters), md, Int32(32), out.unsafe_ptr())
    keep(password)
    keep(salt)
    if rc != 1:
        raise Error("pg: PKCS5_PBKDF2_HMAC failed")
    return out^


def rand_bytes(n: Int) raises -> List[UInt8]:
    var out = List[UInt8](length=n, fill=0)
    if external_call["RAND_bytes", Int32](out.unsafe_ptr(), Int32(n)) != 1:
        raise Error("pg: RAND_bytes failed")
    return out^


def hex_lower(b: Span[UInt8, _]) -> String:
    comptime H = "0123456789abcdef"
    var out = List[UInt8](capacity=len(b) * 2)
    var h = H.as_bytes()
    for x in b:
        out.append(h[Int(x >> 4)])
        out.append(h[Int(x & 15)])
    return String(unsafe_from_utf8=out)


def md5_hex(data: Span[UInt8, _]) -> String:
    var out = List[UInt8](length=16, fill=0)
    _ = external_call["MD5", Int](data.unsafe_ptr(), len(data), out.unsafe_ptr())
    keep(data)
    return hex_lower(out)


def md5_password(user: String, password: String, salt: Span[UInt8, _]) -> String:
    """'md5' + md5hex(md5hex(password + user) + salt)."""
    var inner = md5_hex((password + user).as_bytes())
    var b = List[UInt8]()
    for x in inner.as_bytes():
        b.append(x)
    for x in salt:
        b.append(x)
    return "md5" + md5_hex(b)


def b64(b: Span[UInt8, _]) -> String:
    return b64encode(b)


def unb64(s: String) raises -> List[UInt8]:
    return b64decode(s)


def ct_equal(a: Span[UInt8, _], b: Span[UInt8, _]) -> Bool:
    if len(a) != len(b):
        return False
    var d: UInt8 = 0
    for i in range(len(a)):
        d |= a[i] ^ b[i]
    return d == 0


struct Scram(Movable):
    """SCRAM-SHA-256 client (RFC 5802/7677), no channel binding."""

    var password: String
    var nonce: String
    var client_first_bare: String
    var auth_message: String
    var server_sig: List[UInt8]

    def __init__(out self, password: String, nonce: String = "", user: String = "") raises:
        self.password = password
        self.nonce = nonce if nonce.byte_length() > 0 else b64(rand_bytes(18))
        self.client_first_bare = "n=" + user + ",r=" + self.nonce
        self.auth_message = ""
        self.server_sig = List[UInt8]()

    def client_first(self) -> String:
        return "n,," + self.client_first_bare

    def client_final(mut self, server_first: String) raises -> String:
        var r = String("")
        var s = String("")
        var it = 0
        for part in server_first.split(","):
            var p = String(part)
            if p.startswith("r="):
                r = String(p[byte=2:])
            elif p.startswith("s="):
                s = String(p[byte=2:])
            elif p.startswith("i="):
                it = atol(String(p[byte=2:]))
            elif p.startswith("m="):
                raise Error("pg: SCRAM mandatory extension not supported")
        if not r.startswith(self.nonce) or r.byte_length() <= self.nonce.byte_length():
            raise Error("pg: SCRAM server nonce mismatch")
        if s.byte_length() == 0 or it < 1:
            raise Error("pg: SCRAM invalid server-first-message")
        var salt = unb64(s)
        var salted = pbkdf2_sha256(self.password.as_bytes(), salt, it)
        var client_key = hmac_sha256(salted, "Client Key".as_bytes())
        var stored_key = sha256(client_key)
        var without_proof = "c=biws,r=" + r
        self.auth_message = self.client_first_bare + "," + server_first + "," + without_proof
        var client_sig = hmac_sha256(stored_key, self.auth_message.as_bytes())
        var proof = List[UInt8](length=32, fill=0)
        for i in range(32):
            proof[i] = client_key[i] ^ client_sig[i]
        var server_key = hmac_sha256(salted, "Server Key".as_bytes())
        self.server_sig = hmac_sha256(server_key, self.auth_message.as_bytes())
        return without_proof + ",p=" + b64(proof)

    def verify_final(self, server_final: String) raises:
        if server_final.startswith("e="):
            raise Error("pg: SCRAM server error: " + String(server_final[byte=2:]))
        var v = String("")
        for part in server_final.split(","):
            var p = String(part)
            if p.startswith("v="):
                v = String(p[byte=2:])
        if v.byte_length() == 0:
            raise Error("pg: SCRAM missing server signature")
        if not ct_equal(unb64(v), self.server_sig):
            raise Error("pg: SCRAM server signature mismatch")
