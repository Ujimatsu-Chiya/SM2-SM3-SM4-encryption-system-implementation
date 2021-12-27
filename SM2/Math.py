from Crypto.Random import random
import gmpy2

'''
# 1-B.1.1
# pow(a,b,mod)

def ex_gcd(a: int, b: int):
    if b == 0:
        return 1, 0, a
    else:
        x, y, g = ex_gcd(b, a % b)
        return y, x - (a // b) * y, g


# 1-B.1.2
def inverse(a: int, m: int):
    x, y, g = ex_gcd(a, m)
    if g != 1:
        return None
    if x < 0:
        x += m
    return x
'''


def is_prime(n):
    return gmpy2.is_prime(n, 50)


def int_sqrt(n):
    return gmpy2.isqrt(n)


def inverse(a, m):
    return gmpy2.invert(a, m)


def randint(l, r):
    return mpz(random.randint(int(l), int(r)))


# 1-B.1.3
def gen_lucas(p, X, Y, k):
    inv2 = (p + 1) >> 1
    d = (X * X - Y * 4) % p
    U, V = 1, X
    for i in range(k.bit_length() - 2, -1, -1):
        U, V = U * V % p, (V * V + d * U * U) * inv2 % p
        if k >> i & 1:
            U, V = (X * U + V) * inv2 % p, (X * V + d * U) * inv2 % p
    return U, V


# 1-B.1.4
def get_quadratic_residue(p, g):
    if g == 0:
        return 0
    if p % 4 == 3:
        u = (p - 3) >> 2
        y = pow(g, u + 1, p)
        z = y * y % p
        if z == g:
            return y
        else:
            raise ValueError("g不是p内的二次剩余。")
    elif p % 8 == 5:
        u = (p - 5) >> 3
        z = pow(g, 2 * u + 1, p)
        if z == 1:
            return pow(g, u + 1, p)
        elif z == p - 1:
            return 2 * g * pow(4 * g, u, p) % p
        else:
            raise ValueError("g不是p内的二次剩余。")
    else:
        u = (p - 1) >> 3
        inv2 = (p + 1) >> 1
        Y = g
        while True:
            X = randint(1, p - 1)
            U, V = gen_lucas(p, X, Y, 4 * u + 1)
            assert (0 <= U < p)
            assert (0 <= V < p)
            if (V * V - 4 * Y) % p == 0:
                return V * inv2 % p
            elif U != 1 and U != p - 1:
                raise ValueError("g不是p内的二次剩余。")


mpz = gmpy2.mpz
