import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA as RSAKey
from baseconv import base64
from scapy.all import *
from .constants import *
from pyDH import DiffieHellman


class Colors:
    colors = {
        'BLA': '\u001b[30m',
        'RED': '\u001b[31;1m',
        'GRE': '\u001b[01;32m',
        'YEL': '\u001b[33m',
        'BLU': '\u001b[34m',
        'WHI': '\u001b[0m',
        'CYA': '\u001b[01;36m'
    }
    C_BALL = u"\u25CF"

    @staticmethod
    def colorful_str(**kwargs):
        """
        kwargs:
            <color> str: color from ANSI colors\n
            <sentence> str: string to color
        :return: colored string
        """
        return f'{Colors.colors[kwargs["color"].upper()[:3]]}{kwargs["sentence"]}{Colors.colors["WHI"]}'


# wrapper to the RSA package in order to perform
# easy calculation with no need to worry about the variable types
class RSA:
    # RSA plaintext chunk size is limited
    SIZE = 256

    # in order to transfer the DH pre-shared key encrypted
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

    # every OnionRouter needs the ability to decrypt the DH shared-key
    # given by the client
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

