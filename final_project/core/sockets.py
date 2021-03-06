from scapy.all import *
from scapy.layers.x509 import X509_Cert
from core import cell
from .cell import Cell
from .constants import *


# A base class, wrapper of socket, handles the basic [send/receive] operation
class TorSocket:
    LEN = 12

    def __init__(self, **kwargs):
        if 'sock' in kwargs:
            self.__origsocket = kwargs['sock']
            self.sock = kwargs['sock']
        else:
            self.__origsocket = socket.socket()
            self.sock = None

    def send_cell(self, c: Cell):
        if self.sock:
            packet_data = c.raw()
            packet_data += cell.SEP
            packet_data += b'0'*(cell.CELL_LEN - (len(packet_data) % cell.CELL_LEN))
            size = str(len(packet_data))
            self.sock.send(size.zfill(TorSocket.LEN).encode())
            self.sock.send(packet_data)
        else:
            raise Exception("Unresolved socket")

    def recv_cell(self) -> Cell:
        if self.sock:
            length = b''
            while len(length) < TorSocket.LEN:
                length += self.sock.recv(TorSocket.LEN - len(length))

            length = int(length.decode())
            packet_data = b''
            while len(packet_data) < length:
                packet_data += self.sock.recv(length - len(packet_data))

            data = cell.from_bytes(packet_data)
            return data
        else:
            raise Exception("Unresolved socket")

    def sr1(self, c: Cell) -> Cell:
        self.send_cell(c)
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
