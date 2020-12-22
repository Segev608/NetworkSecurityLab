from Crypto.Cipher import AES
import Crypto
from core import DirectoryUnit

d = DirectoryUnit()


# cipher1 = AES.new('32keysize', AES.MODE_ECB)
# payload = cipher1.encrypt('message')
#
# cipher2 = AES.new('32keysize', AES.MODE_ECB)
# dec = cipher2.decrypt(payload)
#
# print(payload)
# print(dec)