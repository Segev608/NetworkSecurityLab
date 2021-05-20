from socket import socket, AF_INET, SOCK_STREAM
from Crypto.Cipher import AES
from random import randint, getrandbits
from tqdm import tqdm
from sys import argv
import pickle

conf = ('127.0.0.1', 9000)
COMPLEXITY = 16


class Merkle_Puzzles:
    def __init__(self, factor: int = 3, key_size=128):
        """
        Initialize the Merkle's puzzles which can handles
        key exchange based on the complexity problem
        :param factor: Complexity factor
        :param key_size: length of the key (AES is 16 byte)
        """
        self.factor = factor
        self.P = dict()
        # secret keys
        self.keys = [int.to_bytes(randint(0, pow(2, AES.key_size[0] * 8)), length=AES.key_size[0] * 8,
                                  byteorder='big') for _ in range(pow(2, factor))]
        self.key_size = key_size

    def generate_puzzles(self):
        size = 2 ** self.factor
        with tqdm(total=size, position=0, leave=True) as pbar:
            for i in range(size):
                # full with random keys and their session keys
                p = int.to_bytes(randint(0, pow(2, self.factor)), length=self.factor, byteorder='big')
                iv = int.to_bytes(randint(0, pow(2, self.factor)), length=self.factor, byteorder='big')
                encryptor = AES.new(key=p, iv=iv, mode=AES.MODE_CBC)
                self.P[i] = [encryptor.encrypt(b'puzzle No.' + int.to_bytes(i, length=self.factor ,byteorder='big') +
                                               self.keys[i])]
                pbar.update(1)

    def get_keys(self, i: int = None):
        """
        :param i: specific key
        :return: list with the generated keys
        """
        if len(self.P) == 0:
            raise ResourceWarning("ERROR: key data-set did not initialized, use generate keys before")
        if i is not None:
            if 0 <= i <= pow(2, self.factor):
                return self.P[i]
            else:
                raise ValueError("Invalid index value")
        return self.P


def parse_argv(arg: int):
    if not 0 <= arg <= 128:
        raise ValueError("Unsuitable value for Merkle's Puzzle factor")
    return arg


def init_key_exchange(conn: socket, keys: bytes):
    conn.send(int.to_bytes(len(keys), length=32, byteorder='big'))  # msg size
    conn.send(keys)  # payload


if __name__ == '__main__':
    with socket(AF_INET, SOCK_STREAM) as session:
        session.bind(conf)
        session.listen()

        connection, address = session.accept()  # client wants to exchange keys
        with connection:
            print(f'New session established with {address}- sending puzzles...')
            mp = Merkle_Puzzles(parse_argv(int(COMPLEXITY)))
            mp.generate_puzzles()
            challenge: bytes = pickle.dumps(mp.get_keys())

            init_key_exchange(connection, challenge)
