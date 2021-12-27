from Math import randint

import SM2
import Util
from SM2KeyPair import SM2KeyPair
from SM3 import SM3
from User import User


# 1-6.1
def generator_key_pair():
    d = randint(1, SM2.sm2.n - 2)
    P = SM2.sm2.get_g() * d
    return SM2KeyPair(d, P)


# 4-6.1
def encrypt(user: User, message: bytearray, op):
    PB = user.sm2_key_pair.public_key.P
    curve = PB.curve
    while True:
        # A1
        k = randint(1, curve.n - 1)
        # A2
        C1 = curve.get_g() * k
        C1 = Util.ECPoint_2_bytes(C1, op)

        # A3
        S = PB * curve.h
        if S.is_identity():
            raise ValueError("S是单位元")
        # A4
        kPB = PB * k
        x2, y2 = kPB.get_x(), kPB.get_y()
        x2 = Util.int_2_bytes(x2, curve.l)
        y2 = Util.int_2_bytes(y2, curve.l)
        # A5
        t = Util.KDF(Util.join(x2, y2), len(message) << 3)
        if not Util.is_all_zero(t):
            break
    # A6
    C2 = Util.xor_two_array(message, t)
    # A7
    C3 = SM3.hash(Util.join(x2, message, y2))
    return Util.join(C1, C3, C2)


# 4-7.1
def decrypt(user: User, cipher: bytearray, klen):
    PB = user.sm2_key_pair.public_key.P
    curve = PB.curve
    byte_len = (klen + 7) // 8
    # B1
    if cipher[0] < 0x04:
        C1, C3, C2 = cipher[:curve.l + 1], cipher[curve.l + 1:len(cipher) - byte_len], cipher[len(cipher) - byte_len:]
    else:
        C1, C3, C2 = cipher[:curve.l * 2 + 1], cipher[curve.l * 2 + 1:len(cipher) - byte_len], cipher[
                                                                                               len(cipher) - byte_len:]
    C1 = Util.bytes_2_ECPoint(C1)
    if not C1.is_valid():
        raise ValueError("C1不满足椭圆曲线方程")
    # B2
    S = C1 * curve.h
    if S.is_identity():
        raise ValueError("S是无穷远点")
    # B3
    dB = user.sm2_key_pair.private_key.d
    dBC1 = C1 * dB
    x2 = Util.int_2_bytes(dBC1.get_x(), curve.l)
    y2 = Util.int_2_bytes(dBC1.get_y(), curve.l)
    # B4
    t = Util.KDF(Util.join(x2, y2), klen)
    if Util.is_all_zero(t):
        raise ValueError("t为全0串")
    # B5
    M = Util.xor_two_array(C2, t)
    # B6
    u = SM3.hash(Util.join(x2, M, y2))
    if u != C3:
        raise ValueError("明文信息M被篡改")
    # B7
    return M


if __name__ == "__main__":
    ID = "ALICE123@YAHOO.COM".encode()
    db = 0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
    xb = 0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A
    yb = 0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42
    d = db
    P = SM2.sm2.create_point(xb, yb)
    msg = "encryption standard".encode()
    u = User(ID, SM2KeyPair(d, P))

    c = encrypt(u, msg, 0)
    plain = decrypt(u, c, len(msg) * 8)
    print(plain.decode())
    c = encrypt(u, msg, 1)
    plain = decrypt(u, c, len(msg) * 8)
    print(plain.decode())
    c = encrypt(u, msg, 2)
    plain = decrypt(u, c, len(msg) * 8)
    print(plain.decode())
