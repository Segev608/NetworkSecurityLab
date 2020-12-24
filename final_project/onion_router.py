import pem
from core.cell import *
from core.utils import *
from core.sockets import TorSocket, TorClient, ORSocket
import requests

# every OnionRouter knows his private+public RSA key
rsa_prvkey, rsa_pubkey = map(lambda key: str(key), pem.parse_file('key.pem'))

# Diffie-Hellman final result of the key-exchange
shared_key: bytes = None

################
identifier = 1
PORT = 9000 + identifier
################

# every OnionRouter knows about the node before him (closes to the client) and the node after him (he needs to pass
# on data toward him) in the path
next_node: TorClient = None
previous_node: TorSocket = None


# receive CREATE cell from the node before him and sending back CREATED cell
def handle_create(cell: CreateCell):
    global shared_key
    client_dh_pubkey = RSA.decrypt(rsa_prvkey, cell.enc_dh_key, int)
    server_dh = DiffieHellman(DH_SIZE)
    server_pubkey = server_dh.gen_public_key()
    shared_key = server_dh.gen_shared_key(client_dh_pubkey)[:32]
    cell = CreatedCell(cid=cell.cid, dh_key=server_pubkey, hashkey=HASH_FUNC(shared_key.encode()).digest())
    print(f'Sending Created Response: {cell}')
    print(f'Shared DH Key: {shared_key}')
    shared_key = shared_key.encode()
    previous_node.send_cell(cell)


def handle_relay(cell: PayloadCell):
    # in case the current router can see that the relay cell he has just got
    # belongs to him
    if cell.cid == identifier:
        data = AES.new(shared_key, AES_MODE).decrypt(cell.payload)
        cell = from_bytes(data)
        if cell.command == Commands.RELAY:
            res = next_node.sr1(cell)
            wrap_relay(res)
        else:
            ACTIONS[cell.command](cell)
    # the current router see that the relay cell he has just got does not
    # belongs to him and now he encrypting it and sending it *back*
    else:
        wrap_relay(cell)


# util function to handle RELAY cell and move on to the previous node
def wrap_relay(cell: Cell):
    cipher = AES.new(shared_key, AES_MODE).encrypt(cell.relay())
    relay_layer = PayloadCell(cid=identifier, command=Commands.RELAY, payload=cipher)
    previous_node.send_cell(relay_layer)


# after decrypting the RELAY cell and seeing EXTEND, respond by move that cell payload as new CREATE cell
def handle_extend(cell: ExtendCell):
    global next_node
    directory = DirectoryUnit()
    node = directory.get_node(cell.OR)
    next_node = TorClient(node.ip, node.port)
    # the next node returns as response his CREATED cell
    created = next_node.sr1(CreateCell(cid=node.identifier, enc_dh_key=cell.enc_dh_key))

    handle_created(created)


# in case he get CREATED from the next node, return it to the previous node, back to the client as EXTENDED
def handle_created(cell: CreatedCell):
    extended_cell = ExtendedCell(cid=cell.cid, dh_key=cell.dh_key, hashkey=cell.hashkey)
    wrap_relay(extended_cell)


def handle_begin(cell: PayloadCell):
    print('Got Begin Request!')
    cell = PayloadCell(cid=1, command=Commands.CONNECTED, payload=b'')
    wrap_relay(cell)


def handle_data(cell: PayloadCell):
    req = cell.payload.decode()
    r = requests.get(req, stream=True)
    res = PayloadCell(cid=1, command=Commands.DATA, payload=r.content)

    wrap_relay(res)


# every cell COMMAND has it own function to deal with
ACTIONS = {
    Commands.CREATE: handle_create,
    Commands.CREATED: handle_created,
    Commands.RELAY: handle_relay,
    Commands.EXTEND: handle_extend,
    Commands.BEGIN: handle_begin,
    Commands.DATA: handle_data
}


def main():
    global previous_node
    ip = '0.0.0.0'
    # listen for every cell packet which comes through this port
    server = ORSocket(ip, PORT)
    print(f'Listening to port {PORT}.')
    previous_node = server.accept()
    cell = previous_node.recv_cell()
    print(f'Received Create Request: {cell}')
    handle_create(cell)

    while True:
        request = previous_node.recv_cell()
        ACTIONS[request.command](request)

    previous_node.close()
    server.close()


if __name__ == '__main__':
    main()
