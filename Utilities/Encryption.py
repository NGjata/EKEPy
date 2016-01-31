import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES

CHAR_ENCODING = 'utf-8'


class Encryption(object):
    BS = 16
    secret = ""

    def __init__(self, secret):
        newKey = hashlib.md5()
        newKey.update(secret.encode(CHAR_ENCODING))
        self.secret = newKey.digest()

    def encrypt(self, text):
        pad_text = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        text = pad_text(text)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.secret, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(text))

    def decrypt(self, enc):
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.secret, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))

    def get_newKey(self, key):
        newKey = hashlib.md5()
        newKey.update(key.encode(CHAR_ENCODING))
        return newKey.digest()
