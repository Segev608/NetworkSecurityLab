from socket import socket, AF_INET, SOCK_STREAM
import pickle
import random
from tqdm import tqdm

conf = ('127.0.0.1', 9000)
MAX_INPUT = 4096
LOOPS_AES_128 = 2193


def pick_random_key(keys: dict) -> (int, int):
    i = random.randint(0, len(keys))
    return i, int.from_bytes(keys[i], 'big')


def solve_single_puzzle(puzzle: bytes):
    # implement AES cracker. This program does not do that
    # because it's only focus on the learning part. but the idea is
    # to try every 2^128 options until this happens:
    #       Decrypt(cipher-text)[:10] == b'puzzle No.'
    pass


if __name__ == '__main__':
    with socket(AF_INET, SOCK_STREAM) as session:
        session.connect(conf)
        bsize = session.recv(32)
        data = b''

        with tqdm(total=LOOPS_AES_128, position=0, leave=True) as pbar:
            while True:
                u_challenge = session.recv(MAX_INPUT)
                if not u_challenge:
                    break
                data += u_challenge
                pbar.update(1)

        challenge = pickle.loads(data)
        solve_single_puzzle(challenge) # return to server
        session.close()
