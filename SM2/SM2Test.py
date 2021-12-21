import SM2
import SM2GenEncDec
import SM2KeyExchange
import SM2SignVerify
import Util
from SM2KeyPair import SM2KeyPair
from User import User

dA = 0x81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029
xA = 0x160E12897DF4EDB61DD812FEB96748FBD3CCF4FFE26AA6F6DB9540AF49C94232
yA = 0x4A7DAD08BB9A459531694BEB20AA489D6649975E1BFCF8C4741B78B4B223007F
dB = 0x785129917D45A9EA5437A59356B82338EAADDA6CEB199088F14AE10DEFA229B5
xB = 0x6AE848C57C53C7B1B5FA99EB2286AF078BA64C64591B8B566F7357D576F16DFB
yB = 0xEE489D771621A27B36C5C7992062E9CD09A9264386F3FBEA54DFF69305621C4D
IDA = "1234567812345678".encode()
IDB = "1234567812345678".encode()
uA = User(IDA, SM2KeyPair(dA, SM2.sm2.create_point(xA, yA)))
uB = User(IDB, SM2KeyPair(dB, SM2.sm2.create_point(xB, yB)))

print("-------------------------签名与验签-------------------------")
msg = "message digest".encode()
print("{}的十六进制：".format(msg.decode()))
Util.bytes_2_hex(msg)
r, s = SM2SignVerify.sign(uA, msg)
print("对消息{}签名的两个分量r和s: ".format(msg.decode()))
Util.bytes_2_hex(r)
Util.bytes_2_hex(s)
print("对消息{}和签名(r, s)验签结果:", SM2SignVerify.verify(uA, msg, (r, s)))
print("-------------------------密钥交换-------------------------")
klen = 128
result = SM2KeyExchange.key_exchange(uA, uB, klen)
print("uA和uB交换密钥结果:", result[0])
if result[0]:
    print("交换了密钥: ")
    Util.bytes_2_hex(result[1])
print("-------------------------加密与解密-------------------------")
msg = "encryption standard".encode()
print("{}的十六进制：".format(msg.decode()))
Util.bytes_2_hex(msg)

c = SM2GenEncDec.encrypt(uA, msg, 0)
print("对消息{}加密的结果(操作0): ".format(msg.decode()))
Util.bytes_2_hex(c)
m = SM2GenEncDec.decrypt(uA, c, len(msg) * 8)
print("对密文解密结果:", m.decode())

c = SM2GenEncDec.encrypt(uA, msg, 1)
print("对消息{}加密的结果(操作1): ".format(msg.decode()))
Util.bytes_2_hex(c)
m = SM2GenEncDec.decrypt(uA, c, len(msg) * 8)
print("对密文解密结果:", m.decode())

c = SM2GenEncDec.encrypt(uA, msg, 2)
print("对消息{}加密的结果(操作2): ".format(msg.decode()))
Util.bytes_2_hex(c)
m = SM2GenEncDec.decrypt(uA, c, len(msg) * 8)
print("对密文解密结果:", m.decode())

