import Math
import SM2
from ECC import ECPoint
from SM3 import SM3


def join(*bytes_lists: bytes):
    ans = bytearray()
    for bytes_list in bytes_lists:
        ans += bytes_list
    return ans


# 1-4.2.2 & 1-4.2.6
def int_2_bytes(n, l):
    return int(n).to_bytes(l, byteorder="big", signed=False)


# 1-4.2.3 & 1-4.2.7
def bytes_2_int(b: bytes):
    return int.from_bytes(b, byteorder="big", signed=False)


# 1-4.2.9
def ECPoint_2_bytes(p: ECPoint, op):
    x, y = p.get_x(), p.get_y()
    l = p.curve.l
    if op == 0:
        if y & 1:
            b = b"\x03"
        else:
            b = b"\x02"
        return join(b, int_2_bytes(x, l))
    elif op == 1:
        return join(b"\x04", int_2_bytes(x, l), int_2_bytes(y, l))
    else:
        if y & 1:
            b = b"\x07"
        else:
            b = b"\x06"
        return join(b, int_2_bytes(x, l), int_2_bytes(y, l))


# 1-4.2.10
def bytes_2_ECPoint(b: bytes):
    l = SM2.sm2.l
    if len(b) == l + 1:
        x = bytes_2_int(b[1:l + 1])
        alpha = (x ** 3 + SM2.sm2.a * x + SM2.sm2.b) % SM2.sm2.p
        y = Math.get_quadratic_residue(SM2.sm2.p, alpha)
        if y & 1 != b[0] & 1:
            y = SM2.sm2.p - y
        return SM2.sm2.create_point(x, y)
    elif len(b) == l * 2 + 1:
        x = bytes_2_int(b[1:l + 1])
        y = bytes_2_int(b[l + 1:])
        return SM2.sm2.create_point(x, y)


def bytes_2_hex(b: bytearray):
    print("".join("{:02X}".format(x) for x in b))


def is_all_zero(b: bytearray):
    for x in b:
        if x != 0:
            return False
    return True


def xor_two_array(a: bytearray, b: bytearray):
    return bytearray(a[i] ^ b[i] for i in range(len(a)))


# 3-5.4.3 & 4-5.4.3
def KDF(Z: bytearray, klen):
    cnt = (klen + 255) // 256
    bytes_len = (klen + 7) // 8
    K = bytearray()
    for ct in range(1, cnt + 1):
        K += SM3.hash(join(Z, int_2_bytes(ct, 4)))
    return K[:bytes_len]
