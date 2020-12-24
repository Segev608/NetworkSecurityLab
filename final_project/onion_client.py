from core.utils import *
from core.sockets import TorClient
from core.cell import *

node_ip = '127.0.0.1'
server: TorClient = None

directory = DirectoryUnit()
nodes = directory.get_circuit()
# create DH instance
client_dh = DiffieHellman(DH_SIZE)
# list with all the keys which shared between client-routers
shared_keys = {}
# generate the *user* diffie hellman public key
dh_pubkey = client_dh.gen_public_key()


def init_connection(onion_node: OnionNode):
    encrypted_dh_key = RSA.encrypt(onion_node.pubkey, dh_pubkey)
    cell = CreateCell(cid=onion_node.identifier, enc_dh_key=encrypted_dh_key)
    print(f'Sending Create: {cell}')
    cell = server.sr1(cell)
    print(f'Got Created Response: {cell}')

    handle_cretexed(cell)


def handle_cretexed(cell: Union[CreatedCell, ExtendedCell]):
    global shared_keys
    shared_key = client_dh.gen_shared_key(cell.dh_key)[:32]
    print(f'Shared DH Key With {cell.cid}: {shared_key}')

    if HASH_FUNC(shared_key.encode()).digest() == cell.hashkey:
        shared_keys[cell.cid] = shared_key
        print(f'Success. Connection with {cell.cid} established.')
    else:
        raise Exception(f'Failed Connecting to {cell.cid}. DH shared key hash wrong.')


def create_relay(cell: Cell):
    payload = cell.relay()
    for node in reversed(shared_keys):
        cipher = AES.new(shared_keys[node].encode(), AES_MODE)
        payload = cipher.encrypt(payload)
        payload = PayloadCell(cid=node, command=Commands.RELAY, payload=payload).relay()
    return from_bytes(payload)


def handle_relay(cell: Cell):
    for node in shared_keys:
        cipher = AES.new(shared_keys[node].encode(), AES_MODE)
        payload = cipher.decrypt(cell.payload)
        cell = from_bytes(payload)
    return cell


def extend_connection(onion_node: OnionNode):
    encrypted_dh_key = RSA.encrypt(onion_node.pubkey, dh_pubkey)
    cell = ExtendCell(cid=onion_node.identifier, orid=onion_node.identifier, enc_dh_key=encrypted_dh_key)
    relay = create_relay(cell)
    relay_cell = server.sr1(relay)

    handle_cretexed(handle_relay(relay_cell))


def main():
    global server
    print(f'Node Order: {nodes}')
    f_node = directory.get_node(nodes[0])
    server = TorClient(f_node.ip, f_node.port)

    # startup the key-exchange with the first OR
    init_connection(f_node)
    for node in nodes[1:]:
        extend_connection(directory.get_node(node))

    server.close()


if __name__ == '__main__':
    main()
