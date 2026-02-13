import hashlib


b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, q-2, q) % q
I = pow(2, (q-1)//4, q)

def H(m):
    return hashlib.sha512(m).digest()

def xrecover(y):
    xx = (y * y - 1) * pow(d * y * y + 1, q-2, q) % q
    x = pow(xx, (q+3)//8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x

By = 4 * pow(5, q-2, q) % q
Bx = xrecover(By)
B = (Bx % q, By % q, 1, (Bx * By) % q)
ident = (0, 1, 1, 0)

def edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % q
    b = (y1 + x1) * (y2 + x2) % q
    c = t1 * 2 * d * t2 % q
    dd = z1 * 2 * z2 % q
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % q, g * h % q, f * g % q, e * h % q)

def edwards_double(P):
    x1, y1, z1, t1 = P
    a = x1 * x1 % q
    b = y1 * y1 % q
    c = 2 * z1 * z1 % q
    e = ((x1 + y1) * (x1 + y1) - a - b) % q
    g = -a + b
    f = g - c
    h = -a - b
    return (e * f % q, g * h % q, f * g % q, e * h % q)

def scalarmult(P, e):
    if e == 0:
        return ident
    Q = scalarmult(P, e // 2)
    Q = edwards_double(Q)
    if e & 1:
        Q = edwards_add(Q, P)
    return Q


Bpow = []
def make_Bpow():
    P = B
    for _ in range(253):
        Bpow.append(P)
        P = edwards_double(P)
make_Bpow()

def scalarmult_B(e):
    e %= l
    P = ident
    for i in range(253):
        if e & 1:
            P = edwards_add(P, Bpow[i])
        e //= 2
    return P

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes(sum(bits[i*8 + j] << j for j in range(8)) for i in range(b//8))

def encodepoint(P):
    x, y, z, _ = P
    zi = pow(z, q-2, q)
    x = (x * zi) % q
    y = (y * zi) % q
    bits = [(y >> i) & 1 for i in range(b-1)] + [x & 1]
    return bytes(sum(bits[i*8 + j] << j for j in range(8)) for i in range(b//8))

def bit(h, i):
    return (h[i//8] >> (i % 8)) & 1

def publickey_unsafe(sk):
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h, i) for i in range(3, b-2))
    A = scalarmult_B(a)
    return encodepoint(A)

def Hint(m):
    h = H(m)
    return sum(2**i * bit(h, i) for i in range(2*b))

def signature_unsafe(m, sk, pk):
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h, i) for i in range(3, b-2))
    inter = bytes(h[b//8 : b//4]) + m
    r = Hint(inter)
    R = scalarmult_B(r)
    hram = Hint(encodepoint(R) + pk + m)
    S = (r + hram * a) % l
    return encodepoint(R) + encodeint(S)

def isoncurve(P):
    x, y, z, t = P
    return (z % q != 0 and
            x * y % q == z * t % q and
            (y*y - x*x - z*z - d*t*t) % q == 0)

def decodeint(s):
    return sum(2**i * bit(s, i) for i in range(b))

def decodepoint(s):
    y = sum(2**i * bit(s, i) for i in range(b-1))
    x = xrecover(y)
    if x & 1 != bit(s, b-1):
        x = q - x
    P = (x, y, 1, (x*y) % q)
    if not isoncurve(P):
        raise ValueError("Invalid point")
    return P

class SignatureMismatch(Exception):
    pass

def checkvalid(s, m, pk):
    if len(s) != b//4:
        raise ValueError("Signature length invalid")
    if len(pk) != b//8:
        raise ValueError("Public key length invalid")
    R = decodepoint(s[:b//8])
    A = decodepoint(pk)
    S = decodeint(s[b//8:])
    h = Hint(encodepoint(R) + pk + m)
    P = scalarmult_B(S)
    Q = edwards_add(R, scalarmult(A, h))
    if not isoncurve(P) or not isoncurve(Q) or P != Q:
        raise SignatureMismatch("Invalid signature")


class SigningKey:
    def __init__(self, secret_seed_bytes: bytes):
        if len(secret_seed_bytes) != 32:
            raise ValueError("Seed must be 32 bytes")
        self.sk = secret_seed_bytes
        self.vk = publickey_unsafe(self.sk)

    def get_verifying_key(self):
        return VerifyingKey(self.vk)

    def sign(self, message: bytes) -> bytes:
        return signature_unsafe(message, self.sk, self.vk)

class VerifyingKey:
    def __init__(self, vk_bytes: bytes):
        if len(vk_bytes) != 32:
            raise ValueError("Verifying key must be 32 bytes")
        self.vk = vk_bytes

    def to_bytes(self) -> bytes:
        return self.vk

    def verify(self, signature: bytes, message: bytes):
        checkvalid(signature, message, self.vk)
