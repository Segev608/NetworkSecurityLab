import pickle
import ssl
from hashlib import sha256
from scapy.layers.x509 import X509_Cert
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from scapy.all import *
from pyDH import DiffieHellman  # router & client uses

# Initialize global variables for which
# both of the client & router uses

PORT = 9001
HASH_FUNC = sha256
SSL_VERSION = ssl.PROTOCOL_TLSv1
AES_MODE = AES.MODE_ECB

# In order to decrease the size of the prime number
# in the final shared diffie hellman key from 2048 to 1536
DH_SIZE = 5


#  Decorator which handle the log file for every
# function he called at
def session_log(client_session):
    # import logging
    from logging import basicConfig, INFO, info
    # the name file will be stored as client_connection.log
    basicConfig(filename='General.log', level=INFO)

    def wrapper(*args, **kwargs):
        result = client_session(*args, **kwargs)
        s = ''
        for arg in args:
            s += str(arg) + '\n'
        info(f'{client_session.__name__} ran with the variables: \n{s}\n{kwargs}\n and returned: {result}')
        return result

    return wrapper


# Model which holds the information about each onion router
# in this onion routing system implementation
class OnionNode:
    def __init__(self, pubkey, id):
        self.ip = get_if_addr('eth0')
        self.port = 9000 + id
        self.__pubkey = pubkey
        self.identifier = id  # TODO change between virtual machines

    @property
    def pubkey(self) -> RSA._RSAobj:
        return RSA.importKey(self.__pubkey).publickey()


# Responsible for handle the information which
# needs to be shared across the onion network
class DirectoryUnit:
    def __init__(self):
        with open("DirectoryServer.txt", 'rb') as directfile:
            nodes_data = directfile.read().split(b'\n\n\n')
            self.nodes = []
            for node in nodes_data[:-1]:
                data = pickle.loads(node)
                self.nodes.append(data)

    # returns a node object based on his identifier
    def get_node(self, id):
        if isinstance(id, OnionNode):
            raise Exception("HERE!!!!")
        print(f"Req: {id} | type: {type(id)}")
        for node in self.nodes:
            print(f"type: {type(node.identifier)}")
            print(node.identifier)
            print(node.ip)
            if node.identifier == id:
                return node

    # returns a random path of OnionNode's identifiers
    def get_circuit(self):
        id_list = list(map(lambda node: node.identifier, self.nodes))
        # random.shuffle(id_list)
        return id_list


# Const structure which holds all the different Cell's type
class Commands:
    # I) Client wants to start connection with the first OnionRouter in the onion circuit. He's sending
    #    Cell which contains a Cell identifier which the OnionRouters are identified by + Encrypted(DH key exchange)
    #    by the RSA public key of the OnionRouter he's about to send this Cell
    # II) by the Client order to extend connection, the first OnionRouter extends the client's CREATE cell
    # III) for any next extend further request, inside the onion network, (which was given by the Client)
    #      the OnionRouter are passing it on.
    CREATE = 'CREATE'
    # Once a CREATE cell is received by an extended OnionRouter, a Cell containing his unique OnionRouter's identifier
    # is send + his DH public key in the key exchange procedure + SHA256(shared key he has successfully created using
    # the Client DH public key part)
    CREATED = 'CREATED'
    # This command basically tells the receiver "Decrypt it with AES-ECB using our DH shared key and execute the command
    # which stored inside".
    RELAY = 'RELAY'
    # cell structure, the unique identifier of the next OnionRouter he's about to pass the CREATE cell to (He can obtain
    # more information about him, using the DirectoryUnit which holds all the info) + Encrypted(DH key exchange)
    # by the RSA public key of the *next* OnionRouter. Whenever a OnionRouter receives this command he knows that he's
    # should create a new CREATE cell and pass it with the info he just got to the next OnionRouter in the circuit.
    EXTEND = 'EXTEND'
    # this command notify the Client that this Cell payload contains the CREATED (more info above)Cell from an extended
    # OnionRouter but it came encrypted with the help of the OnionRouter in the middle.
    EXTENDED = 'EXTENDED'
    BEGIN = 'BEGIN'
    CONNECTED = 'CONNECTED'
    DATA = 'DATA'


# This object contains all the information which described above [line 88-113]
class Cell:
    PAD_SEPARATOR = b'\n\n\n'

    def __init__(self, cid, command, **kwargs):
        self.cid = cid
        self.command = command
        if command in (Commands.CREATED, Commands.EXTENDED):
            self.pubkey = int(kwargs['pubkey'])
            self.hashkey = kwargs['hashkey']
        elif command == Commands.EXTEND:
            self.OR = kwargs['OR']
            self.dhkey = kwargs['dhkey']
        else:
            self.payload = kwargs['payload']

    def __str__(self):
        if self.command in (Commands.CREATED, Commands.EXTENDED):
            return f'id: {self.cid} | command: {self.command} | pubkey: {self.pubkey} | hashkey: {self.hashkey}'
        elif self.command == Commands.EXTEND:
            return f'id: {self.cid} | command: {self.command} | OR: {self.OR} | dhkey: {self.dhkey}'
        else:
            return f'id: {self.cid} | command: {self.command} | payload: {self.payload}'

    def raw(self):
        data = pickle.dumps(self)
        data += Cell.PAD_SEPARATOR
        data += (16 - (len(data) % 16)) * b'0'
        return data

    @classmethod
    def create(cls, data: bytes):
        data = data.split(Cell.PAD_SEPARATOR)[0]
        return pickle.loads(data)


# A base class, wrapper of socket, handles the basic [send/receive] operation
class TorSocket:
    def __init__(self, **kwargs):
        if 'sock' in kwargs:
            self.__origsocket = kwargs['sock']
            self.sock = kwargs['sock']
        else:
            self.__origsocket = socket.socket()
            self.sock = None

    @session_log
    def send_cell(self, cell):
        if self.sock:
            packet_data = cell.raw()
            length = struct.pack('!I', len(packet_data))
            self.sock.send(length + packet_data)
        else:
            raise Exception("Unresolved socket")

    @session_log
    def recv_cell(self):
        if self.sock:
            length = b''
            while len(length) < 4:
                length += self.sock.recv(4 - len(length))
            length = struct.unpack('!I', length)[0]

            packet_data = self.sock.recv(length)
            data = Cell.create(packet_data)
            return data
        else:
            raise Exception("Unresolved socket")

    def sr1(self, cell):
        self.send_cell(cell)
        return self.recv_cell()

    def close(self):
        if self.sock:
            self.sock.close()
        else:
            self.__origsocket.close()

    def get_socket(self):
        return self.__origsocket


# A specific properties which executed by the client-side
class TorClient(TorSocket):
    def __init__(self, ip, port):
        TorSocket.__init__(self)
        self.get_socket().connect((ip, port))
        self.sock = ssl.wrap_socket(self.get_socket(), ssl_version=SSL_VERSION)
        self.peer_sslcertificate = X509_Cert(self.sock.getpeercert(binary_form=True))


# A specific properties which executed by the OnionRouter-side
class ORSocket(TorSocket):
    def __init__(self, ip, port):
        TorSocket.__init__(self)
        context = ssl.SSLContext(SSL_VERSION)
        context.load_cert_chain(certfile="cert.pem", keyfile="cert.pem")
        self.sock = context.wrap_socket(self.get_socket(), server_side=True)
        self.sock.bind((ip, port))
        self.sock.listen()

    def accept(self):
        con, _ = self.sock.accept()
        return TorSocket(sock=con)


def main():
    pass

if __name__ == '__main__':
    main()
