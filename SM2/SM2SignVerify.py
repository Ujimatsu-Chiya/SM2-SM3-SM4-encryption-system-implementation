

import Math
import SM2
import Util
from SM2KeyPair import SM2KeyPair
from SM3 import SM3
from User import User


# 6.1
def sign(user: User, message: bytearray):
    # A1
    M1 = Util.join(user.get_z(), message)
    # A2
    e = Util.bytes_2_int(SM3.hash(M1))
    curve = user.sm2_key_pair.public_key.P.curve

    while True:
        # A3
        k = Math.randint(1, curve.n - 1)
        kG = curve.get_g() * k
        # A4
        x1 = kG.get_x()
        # y1 = kG.get_y()
        # A5
        r = (e + x1) % curve.n
        if r == 0 or r + k == curve.n:
            continue
        # A6
        dA = user.sm2_key_pair.private_key.d
        s = Math.inverse(1 + dA, curve.n) * (k - r * dA) % curve.n
        if s != 0:
            break
    return Util.int_2_bytes(r, curve.l), Util.int_2_bytes(s, curve.l)


# 7.1
def verify(user: User, message: bytearray, signature):
    r, s = signature
    r = Util.bytes_2_int(r)
    s = Util.bytes_2_int(s)
    curve = user.sm2_key_pair.public_key.P.curve
    # B1, B2
    if not (1 <= min(r, s) and max(r, s) <= curve.n - 1):
        return False
    # B3
    M1 = Util.join(user.get_z(), message)
    # B4
    e = Util.bytes_2_int(SM3.hash(M1))
    # B5
    t = (r + s) % curve.n
    if t == 0:
        return False
    # B6
    PA = user.sm2_key_pair.public_key.P
    sGtPA = (curve.get_g() * s) + (PA * t)
    x1 = sGtPA.get_x()
    # y1 = sGtPA.get_y()
    # B7
    R = (e + x1) % curve.n
    if R == r:
        return True
    else:
        return False


if __name__ == "__main__":
    ID = "ALICE123@YAHOO.COM".encode()
    da = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
    xa = 0x0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A
    ya = 0x7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857
    u = User(ID, SM2KeyPair(da, SM2.sm2.create_point(xa, ya)))
    msg = "message digest".encode()
    r, s = sign(u, msg)
    Util.bytes_2_hex(r)
    Util.bytes_2_hex(s)
    print(verify(u, msg, (r, s)))
