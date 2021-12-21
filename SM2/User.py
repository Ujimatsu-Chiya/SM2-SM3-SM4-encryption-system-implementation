from SM3.SM3 import SM3
from SM2KeyPair import SM2KeyPair
import Util, SM2


class User:
    def __init__(self, ID: bytearray, sm2_key_pair: SM2KeyPair):
        self.ID = ID
        self.sm2_key_pair = sm2_key_pair

    # 2-5.5
    def get_z(self):
        P = self.sm2_key_pair.public_key.P
        xa = P.get_x()
        ya = P.get_y()
        return SM3().hash(Util.join(
            Util.int_2_bytes(len(self.ID) << 3, 2),
            self.ID,
            Util.int_2_bytes(P.curve.a, P.curve.l),
            Util.int_2_bytes(P.curve.b, P.curve.l),
            Util.int_2_bytes(P.curve.xG, P.curve.l),
            Util.int_2_bytes(P.curve.yG, P.curve.l),
            Util.int_2_bytes(xa, P.curve.l),
            Util.int_2_bytes(ya, P.curve.l)
        ))


if __name__ == "__main__":
    ID = "ALICE123@YAHOO.COM".encode()
    da = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
    xa = 0x0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A
    ya = 0x7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857
    u = User(ID, SM2KeyPair(da, SM2.sm2.create_point(xa, ya)))
    Util.bytes_2_hex(u.get_z())
