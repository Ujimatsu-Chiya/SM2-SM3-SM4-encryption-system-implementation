from ECC import ECPoint


class SM2PublicKey:
    def __init__(self, P: ECPoint):
        self.P = P


class SM2PrivateKey:
    def __init__(self, d):
        self.d = d


class SM2KeyPair:
    def __init__(self, d, P: ECPoint):
        self.private_key = SM2PrivateKey(d)
        self.public_key = SM2PublicKey(P)

    # 6.2.1
    def public_key_is_valid(self):
        d, P = self.private_key.d, self.public_key.P
        if P.is_identity():
            return False
        xp, yp = P.get_x(), P.get_y()
        return 0 <= min(xp, yp) and max(xp, yp) <= P.curve.p - 1 and \
               P.is_valid() and \
               (P * P.curve.n).is_identity()

