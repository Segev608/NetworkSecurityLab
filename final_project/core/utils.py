import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as RSAKey
from baseconv import base64
from scapy.all import *
from .constants import *
from pyDH import DiffieHellman


def debug(*xs):
    for x in xs:
        print(type(x), end=' ')
        if hasattr(x, '__len__'):
            print(len(x), end=' ')
        print(x)


class RSA:
    SIZE = 256

    @classmethod
    def encrypt(cls, pubkey, data):
        if not isinstance(pubkey, RSAKey.RsaKey):
            pubkey = RSAKey.importKey(pubkey).publickey()

        if isinstance(data, str):
            data = data.encode()
        if isinstance(data, int):
            data = base64.encode(data).encode()

        data = PKCS1_OAEP.new(pubkey).encrypt(data)
        return data

    @classmethod
    def decrypt(cls, prvkey, data: bytes, expected: type):
        if not isinstance(prvkey, RSAKey.RsaKey):
            prvkey = RSAKey.importKey(prvkey)
        data = PKCS1_OAEP.new(prvkey).decrypt(data)

        if expected == str:
            return data.decode()
        if expected == int:
            return int(base64.decode(data.decode()))

        return data


# Model which holds the information about each onion router
# in this onion routing system implementation
class OnionNode:
    def __init__(self, identifier, ip, pubkey, **kwargs):
        self.identifier = identifier
        self.ip = ip
        self.port = 9000 + identifier
        self.pubkey = pubkey


# Responsible for handle the information which
# needs to be shared across the onion network
class DirectoryUnit:
    def __init__(self):
        with open("./DirectoryServer.txt", 'r') as file:
            nodes_data = file.read().split('\n\n')
            self.nodes = []
            for node in nodes_data[:-1]:
                data = json.loads(node)
                self.nodes.append(OnionNode(**data))

    # returns a node object based on his identifier
    def get_node(self, identifier: int):
        # for node in self.nodes:
        #     if node.identifier == id:
        #         return node
        return next((x for x in self.nodes if x.identifier == identifier), None)

    # returns a random path of OnionNode's identifiers
    def get_circuit(self):
        id_list = list(map(lambda node: node.identifier, self.nodes))
        return id_list

