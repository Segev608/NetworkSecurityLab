from Crypto.PublicKey import RSA
import pem
from core.utils import OnionNode
from subprocess import Popen, PIPE, STDOUT
import json


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
    with open("DirectoryServer.txt", 'a+') as pubfile:
        _, pbkey = pem.parse_file('key.pem')
        node = OnionNode(1, '127.0.0.1', str(pbkey))
        print(f"node info: {node.pubkey}\n{node.ip}")
        pubfile.write(json.dumps(node.__dict__) + '\n\n')


if __name__ == '__main__':
    pass
    # create_cert()
    # gen_rsa_key()
    append_to_dir()
    # with open("DirectoryServer.txt", 'r') as pubfile:
    #     d = pubfile.read().split('\n\n')
    #     o = OnionNode(**json.loads(d[0]))
    #     print(o)
    #     print(o.ip)
    #     print(o.pubkey)
