import SM2
import Util
from ECC import *
from SM2KeyPair import SM2KeyPair
from SM3.SM3 import SM3
from User import User


def key_exchange(uA: User, uB: User, klen):
    curve = uA.sm2_key_pair.public_key.P.curve
    byte_len = (klen + 7) // 8
    w = ((curve.n - 1).bit_length() - 1) // 2
    # A1
    rA = randint(1, curve.n - 1)
    # A2
    RA = curve.get_g() * rA
    x1, y1 = RA.get_x(), RA.get_y()
    # A3 A---->B: TA
    # --------------------------------------------------
    # B1
    rB = randint(1, curve.n - 1)
    # B2
    RB = curve.get_g() * rB
    x2, y2 = RB.get_x(), RB.get_y()
    x21 = (1 << w) + (x2 & ((1 << w) - 1))
    # B4
    tB = (uB.sm2_key_pair.private_key.d + x21 * rB) % curve.n
    # B5
    if not RA.is_valid():
        return False
    x11 = (1 << w) + (x1 & ((1 << w) - 1))
    # B6
    V = (uA.sm2_key_pair.public_key.P + RA * x11) * (curve.h * tB)
    if V.is_identity():
        return False
    xV, yV = V.get_x(), V.get_y()
    # B7
    KB = Util.KDF(Util.join(
        Util.int_2_bytes(xV, curve.l),
        Util.int_2_bytes(yV, curve.l),
        uA.get_z(),
        uB.get_z()
    ), klen)
    # B8
    SB = SM3().hash(Util.join(
        b'\x02',
        Util.int_2_bytes(yV, curve.l),
        SM3().hash(Util.join(
            Util.int_2_bytes(xV, curve.l),
            uA.get_z(),
            uB.get_z(),
            Util.int_2_bytes(x1, curve.l),
            Util.int_2_bytes(y1, curve.l),
            Util.int_2_bytes(x2, curve.l),
            Util.int_2_bytes(y2, curve.l),
        ))))
    # B9 B---->AB: RB, SB
    # --------------------------------------------------
    # A4
    x1, y1 = RA.get_x(), RA.get_y()
    x11 = (1 << w) + (x1 & ((1 << w) - 1))
    # A5
    tA = (uA.sm2_key_pair.private_key.d + x11 * rA) % curve.n
    # A6
    if not RB.is_valid():
        return False
    x2, y2 = RB.get_x(), RB.get_y()
    x21 = (1 << w) + (x2 & ((1 << w) - 1))
    # A7
    U = (uB.sm2_key_pair.public_key.P + RB * x21) * (curve.h * tA)
    if U.is_identity():
        return False
    xU, yU = V.get_x(), V.get_y()
    # A8
    KA = Util.KDF(Util.join(
        Util.int_2_bytes(xU, curve.l),
        Util.int_2_bytes(yU, curve.l),
        uA.get_z(),
        uB.get_z()
    ), klen)
    # A9
    S1 = SM3().hash(Util.join(
        b'\x02',
        Util.int_2_bytes(yU, curve.l),
        SM3().hash(Util.join(
            Util.int_2_bytes(xU, curve.l),
            uA.get_z(),
            uB.get_z(),
            Util.int_2_bytes(x1, curve.l),
            Util.int_2_bytes(y1, curve.l),
            Util.int_2_bytes(x2, curve.l),
            Util.int_2_bytes(y2, curve.l),
        ))))
    if S1 != SB:
        return False
    # A10
    SA = SM3().hash(Util.join(
        b'\x03',
        Util.int_2_bytes(yU, curve.l),
        SM3().hash(Util.join(
            Util.int_2_bytes(xU, curve.l),
            uA.get_z(),
            uB.get_z(),
            Util.int_2_bytes(x1, curve.l),
            Util.int_2_bytes(y1, curve.l),
            Util.int_2_bytes(x2, curve.l),
            Util.int_2_bytes(y2, curve.l),
        ))))
    # A---->B SA
    # --------------------------------------------------
    # B10
    S2 = SM3().hash(Util.join(
        b'\x03',
        Util.int_2_bytes(yV, curve.l),
        SM3().hash(Util.join(
            Util.int_2_bytes(xV, curve.l),
            uA.get_z(),
            uB.get_z(),
            Util.int_2_bytes(x1, curve.l),
            Util.int_2_bytes(y1, curve.l),
            Util.int_2_bytes(x2, curve.l),
            Util.int_2_bytes(y2, curve.l),
        ))))
    if S2 != SA:
        return False
    # print("A和B共享了{}字节的密钥: ".format(byte_len))
    # 此时KA=KB
    # Util.bytes_2_hex(KA)
    return True, KA


if __name__ == "__main__":
    IDA = "ALICE123@YAHOO.COM".encode()
    IDB = "BILL456@YAHOO.COM".encode()
    dA = 0x6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE
    xA = 0x3099093BF3C137D8FCBBCDF4A2AE50F3B0F216C3122D79425FE03A45DBFE1655
    yA = 0x3DF79E8DAC1CF0ECBAA2F2B49D51A4B387F2EFAF482339086A27A8E05BAED98B
    dB = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
    xB = 0x245493D446C38D8CC0F118374690E7DF633A8A4BFB3329B5ECE604B2B4F37F43
    yB = 0x53C0869F4B9E17773DE68FEC45E14904E0DEA45BF6CECF9918C85EA047C60A4C
    uA = User(IDA, SM2KeyPair(dA, SM2.sm2.create_point(xA, yA)))
    uB = User(IDB, SM2KeyPair(dB, SM2.sm2.create_point(xB, yB)))
    klen = 128
    print(key_exchange(uA, uB, klen))
