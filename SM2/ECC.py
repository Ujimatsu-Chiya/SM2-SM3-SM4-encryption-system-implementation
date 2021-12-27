from Math import *


class ECCurve:
    def __init__(self, p=None, a=None, b=None, xG=None, yG=None, n=None, h=1):
        self.p = mpz(p)
        self.a = mpz(a)
        self.b = mpz(b)
        self.xG = mpz(xG)
        self.yG = mpz(yG)
        self.n = mpz(n)
        self.h = mpz(h)
        self.l = (p.bit_length() + 7) >> 3

    def __eq__(self, other):
        return self.p == other.p and self.a == other.a and self.b == other.b

    def create_point(self, x, y, z=1):
        return ECPoint(self, x, y, z)

    def create_identity(self):
        return ECPoint(self, 1, 1, 0)

    def get_g(self):
        return ECPoint(self, self.xG, self.yG)

    # 1-5.2.2
    def is_valid(self):
        return self.p > 3 and is_prime(self.p) and \
               0 <= min(self.a, self.b, self.xG, self.yG) and max(self.a, self.b, self.xG, self.yG) <= self.p - 1 and \
               (4 * self.a ** 3 - 27 * self.b ** 2) % self.p != 0 and \
               (self.yG ** 2 - (self.xG ** 3 + self.a * self.xG + self.b)) % self.p == 0 and \
               is_prime(self.n) and self.n > (1 << 191) and self.n ** 2 > 16 * self.p and \
               (self.get_g() * self.n).is_identity() and ((int_sqrt(self.p) + 1) ** 2 // self.n) == self.h

    # 1-A.1.2.3.2
    def double(self, Q):
        if Q.is_identity():
            return Q
        m1 = (3 * Q.x ** 2 + self.a * Q.z ** 4) % self.p
        m2 = 4 * Q.x * Q.y ** 2
        m3 = 8 * Q.y ** 4
        x3 = (m1 ** 2 - 2 * m2) % self.p
        y3 = (m1 * (m2 - x3) - m3) % self.p
        z3 = 2 * Q.y * Q.z % self.p
        return self.create_point(x3, y3, z3)

    # 1-A.1.2.3.2
    def add(self, Q1, Q2):
        if Q1.is_identity():
            return Q2
        if Q2.is_identity():
            return Q1
        m1 = Q1.x * Q2.z ** 2 % self.p
        m2 = Q2.x * Q1.z ** 2 % self.p
        m4 = Q1.y * Q2.z ** 3 % self.p
        m5 = Q2.y * Q1.z ** 3 % self.p
        if m1 == m2:
            if m4 == m5:
                return self.double(Q1)
            else:
                return self.create_identity()
        m3 = m1 - m2
        m6 = m4 - m5
        m7 = m1 + m2
        # m8 = m4 + m5
        x3 = (m6 ** 2 - m7 * m3 ** 2) % self.p
        y3 = (m6 * (m1 * m3 ** 2 - x3) - m4 * m3 ** 3) % self.p
        z3 = Q1.z * Q2.z * m3 % self.p
        return self.create_point(x3, y3, z3)

    # 1-A.3.2
    def mul(self, Q, k):
        S = self.create_identity()
        while k:
            if k & 1:
                S += Q
            k >>= 1
            if k == 0:
                break
            Q += Q
        return S


class ECPoint:
    def __init__(self, curve, x, y, z=1):
        self.curve = curve
        self.x, self.y, self.z = mpz(x), mpz(y), mpz(z)

    def is_identity(self):
        return self.z == 0

    def is_valid(self):
        if self.is_identity():
            return True
        x, y = self.get_x(), self.get_y()
        return (y ** 2 - (x ** 3 + self.curve.a * x + self.curve.b)) % self.curve.p == 0

    # 1-A.1.2.3.2
    def get_x(self):
        return self.x * inverse(self.z ** 2, self.curve.p) % self.curve.p

    # 1-A.1.2.3.2
    def get_y(self):
        return self.y * inverse(self.z ** 3, self.curve.p) % self.curve.p

    def normalize(self):
        if self.z == 0:
            return self.curve.create_point(1, 1, 0)
        else:
            return self.curve.create_point(self.get_x(), self.get_y(), 1)

    # 1-A.1.2.3.2
    def __add__(self, other):
        return self.curve.add(self, other)

    # 1-A.3.2
    def __mul__(self, other):
        return self.curve.mul(self, other)

    # 1-A.1.2.3.2
    def __neg__(self):
        return self.curve.create_point(self.x, self.curve.p - self.y, self.z)

    def __str__(self):
        if self.is_identity():
            return "Infinity"
        else:
            Q = self.normalize()
            return "({}, {})".format(Q.x, Q.y)
