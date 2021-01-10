import struct
from .utils import RSA
from .constants import *
from baseconv import base64

# strong flag to separate cell content and padding
SEP = b'\r\n'*15


def from_bytes(data: bytes):
    i, cmd = data[:2], data[2:3]
    i = struct.unpack('!H', i)[0]
    if cmd in classes:
        return classes[cmd].create(i, data[3:])
    return PayloadCell(i, cmd, data[3:].split(SEP)[0])


# base class, contains all the information
# which described in the cell.py file
class Cell:
    def __init__(self, cid, command):
        self.cid: int = cid
        self.command: Commands.TYPE = command

    def __str__(self):
        return f'id: {self.cid} | command: {self.command}'

    # creates bytes object containing the values of the
    # cid as unsigned short and the cell's command
    def raw(self):
        data = struct.pack('!H', self.cid) + self.command
        return data

    # converts the cell into byte object and handles the padding
    # for the AES encryption (plaintext must be multiple of 16)
    def relay(self):
        data = self.raw() + SEP
        return data + b'0' * (16 - (len(data) % 16))


# dealing with payload cells
class PayloadCell(Cell):
    def __init__(self, cid, command, payload: bytes):
        super().__init__(cid, command)
        self.payload = payload

    def raw(self):
        data = super().raw()
        data += self.payload
        return data


class CreateCell(Cell):
    def __init__(self, cid, enc_dh_key: bytes):
        super().__init__(cid, Commands.CREATE)
        self.enc_dh_key = enc_dh_key

    def raw(self):
        data = super().raw()
        data += self.enc_dh_key
        return data

    @classmethod
    def create(cls, cid: int, data: bytes):
        # RSA payload is encrypted using the first OR's
        # public key, RSA demands that plaintext size will be 256 byte long
        return CreateCell(cid, data[:RSA.SIZE])


class ExtendCell(Cell):
    def __init__(self, cid, orid: int, enc_dh_key: bytes):
        super().__init__(cid, Commands.EXTEND)
        self.enc_dh_key = enc_dh_key
        self.OR = orid

    def raw(self):
        data = super().raw()
        data += struct.pack('!H', self.OR) + self.enc_dh_key
        return data

    @classmethod
    def create(cls, cid: int, data: bytes):
        # the next onion router identifier located in the first two bytes
        orid = struct.unpack('!H', data[:2])[0]
        return ExtendCell(cid, orid, data[2:RSA.SIZE + 2])


class __CRETEXEDCell(Cell):
    def __init__(self, cid, command, dh_key: int, hashkey: bytes):
        super().__init__(cid, command)
        self.__dh_key = base64.encode(dh_key).encode()
        self.hashkey = hashkey

    def raw(self):
        data = super().raw()
        data += self.__dh_key + SEP + self.hashkey
        return data

    @property
    def dh_key(self):
        return int(base64.decode(self.__dh_key.decode()))

    @classmethod
    def split(cls, data: bytes):
        data = data.split(SEP)
        return int(base64.decode(data[0].decode())), data[1]


class CreatedCell(__CRETEXEDCell):
    def __init__(self, cid, dh_key: int, hashkey: bytes):
        super().__init__(cid, Commands.CREATED, dh_key, hashkey)

    @classmethod
    def create(cls, cid: int, data: bytes):
        dh, h = super().split(data)
        return CreatedCell(cid, dh, h)


class ExtendedCell(__CRETEXEDCell):
    def __init__(self, cid, dh_key: int, hashkey: bytes):
        super().__init__(cid, Commands.EXTENDED, dh_key, hashkey)

    @classmethod
    def create(cls, cid: int, data: bytes):
        dh, h = super().split(data)
        return ExtendedCell(cid, dh, h)


classes = {
    Commands.CREATE: CreateCell,
    Commands.CREATED: CreatedCell,
    Commands.EXTEND: ExtendCell,
    Commands.EXTENDED: ExtendedCell,
}
