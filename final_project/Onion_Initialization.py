from Crypto.PublicKey import RSA
import pem
import pickle
from core import OnionNode
from subprocess import Popen, PIPE, STDOUT


def create_cert():
    cmd = ["openssl", "req", "-new", "-x509", "-days", "365", "-nodes", "-out", "cert.pem", "-keyout", "cert.pem"]
    p = Popen(cmd, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    p.communicate(input=b'IL\nIsrael\nJerusalem\n.\n.\n.\n.\n')


def gen_rsa_key():
    # for every virtual machine which behave as router
    key = RSA.generate(2048)
    with open("key.pem", 'wb') as content_file:
        content_file.write(key.exportKey('PEM'))
        content_file.write(b'\n')
        pubkey = key.publickey()
        content_file.write(pubkey.exportKey('PEM'))


def append_to_dir():
    with open("DirectoryServer.txt", 'ab+') as pubfile:
        SEPERATOR = b'\n\n\n'
        _, pbkey = pem.parse_file('key.pem')
        node = OnionNode(str(pbkey), 1)
        print(f"node info: {node.pubkey}\n{node.ip}")
        pubfile.write(pickle.dumps(node) + SEPERATOR)


if __name__ == '__main__':
    pass
    # create_cert()
    # gen_rsa_key()
    append_to_dir()
