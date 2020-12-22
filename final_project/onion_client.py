from core import *

# TODO: (1)
"""    
1) create types of messages:
1.1)  CREATE: Imp
1.2)  CREATED: 
1.3)  RELAY:
1.4)  EXTEND:
1.5)  EXTENDED:
1.6*) BEGIN/CONNECTED/DATA:
"""

# TODO: (2)
"""
1) Create Crypto package
1.1) DH
1.2) Hashes
1.3) Symmetric encryption
"""

node_ip = '127.0.0.1'
client: TorClient = None

directory = DirectoryUnit()
nodes = directory.get_circut()
# create DH instance
client_dh = DiffieHellman(DH_SIZE)
# list with all the keys which shared between client-routers
shared_keys = {}
# generate the *user* diffie hellman public key
dh_pubkey = client_dh.gen_public_key()


def init_connection(onion_node):
    # onion_node = directory.get_node(onion_node)
    node_rsa_key = onion_node.pubkey
    encrypted_dh_key = node_rsa_key.encrypt(dh_pubkey, 32)[0]
    cell = client.sr1(Cell(cid=onion_node.identifier, command=Commands.CREATE, payload=encrypted_dh_key))
    return cell


def extend_connection(onion_node: OnionNode):
    onion_node = directory.get_node(onion_node)
    node_rsa_key = onion_node.pubkey
    encrypted_dh_key = node_rsa_key.encrypt(dh_pubkey, 32)[0]
    cell = Cell(cid=1, command=Commands.EXTEND, OR=onion_node.identifier, dhkey=encrypted_dh_key)
    payload = cell.raw()

    relay = create_relay(payload)
    extended_cell = client.sr1(relay)
    return extended_cell


def create_relay(payload: bytes):
    for node in reversed(shared_keys):
        cipher = AES.new(shared_keys[node], AES_MODE)
        payload = cipher.encrypt(payload)
        relay_layer = Cell(cid=node, command=Commands.RELAY, payload=payload)
        payload = relay_layer.raw()
    return Cell.create(payload)


def handle_created(cell: Cell):
    global shared_keys
    shared_key = client_dh.gen_shared_key(cell.pubkey)

    print(shared_key)
    print(type(shared_key))
    print(HASH_FUNC(shared_key.encode()).digest())
    print(cell.hashkey)
    print(type(cell.hashkey))

    if HASH_FUNC(shared_key.encode()).digest() == cell.hashkey:
        shared_keys[cell.cid] = shared_key[:32]
        print('success!')
        print(shared_key)
    else:
        print('problem!')
        print(shared_key)


def handle_extended(cell: Cell):
    handle_created(cell)


def handle_relay(cell: Cell):
    for node in shared_keys:
        cipher = AES.new(shared_keys[node], AES_MODE)
        payload = cipher.decrypt(cell.payload)
        cell = Cell.create(payload)
    return cell


ACTIONS = {
    Commands.CREATED: handle_created,
    Commands.RELAY: handle_relay,
    Commands.EXTENDED: handle_extended,
    Commands.CONNECTED: None,
    Commands.DATA: None
}


def main():
    global client
    # initialize the client which listens to the first onion router
    f_node = directory.get_node(nodes[0])
    client = TorClient(f_node.ip, f_node.port)

    # startup the key-exchange with the first OR
    cell = init_connection(f_node)
    ACTIONS[cell.command](cell)

    # initialize connection
    for node in nodes[1:]:
        extended_cell = extend_connection(node)
        ACTIONS[cell.command](extended_cell)

    print(shared_keys)


if __name__ == '__main__':
    main()
