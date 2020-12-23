from core import *

# every OnionRouter knows his private+public RSA key
with open('key.pem', 'rb') as keyfile:
    rsa_key = RSA.importKey(keyfile.read())

# Diffie-Hellman final result of the key-exchange
shared_key = None

################
identifier = 1
PORT = 9000 + identifier
################

# every OnionRouter knows about the node before him (closes to the client) and the node after him (he needs to pass
# on data toward him) in the path
next_node: TorSocket = None
previous_node: TorSocket = None

# NOTE: every handle_COMMAND in this module, basically responsible to respond in the correct way
# to the COMMAND the OnionRouter just got


# receive CREATE cell from the node before him and sending back CREATED cell
def handle_create(connection: TorClient, cell: Cell, **kwargs):
    global shared_key
    client_dh_pubkey = rsa_key.decrypt(cell.payload)
    server_dh = DiffieHellman(DH_SIZE)
    server_pubkey = server_dh.gen_public_key()
    shared_key = server_dh.gen_shared_key(client_dh_pubkey)[:32]
    connection.send_cell(Cell(cid=cell.cid, command=Commands.CREATED, pubkey=server_pubkey,
                              hashkey=HASH_FUNC(shared_key.encode()).digest()))


# receive RELAY cell from the node before him and extending the inner cell to the next node
def handle_relay(connection: TorClient, cell: Cell, **kwargs):
    # in case the current router can see that the relay cell he has just got
    # belongs to him
    if cell.cid == identifier:
        dicryptor = AES.new(shared_key, AES_MODE)
        data = Cell.create(dicryptor.decrypt(cell.payload))
        return data
    # the current router see that the relay cell he has just got does not
    # belongs to him and now he encrypting it and sending it *back*
    elif kwargs['first']:
        encryptor = AES.new(shared_key, AES_MODE)
        previous_node.send_cell(create_relay(encryptor.encrypt(cell.payload)))
    else:
        return next_node.sr1(cell)


# util function to handle RELAY cell to move on to the previous node
def create_relay(payload: bytes):
    cipher = AES.new(shared_key, AES_MODE)
    payload = cipher.encrypt(payload)
    relay_layer = Cell(cid=identifier, command=Commands.RELAY, payload=payload)
    return relay_layer


# after decrypting the RELAY cell and seeing EXTEND, respond by move that cell payload as new CREATE cell
def handle_extend(connection: TorClient, cell: Cell, **kwargs):
    global next_node
    directory = DirectoryUnit()
    node = directory.get_node(cell.OR)
    next_node = TorClient(node.ip, 9002)
    # the next node returns as response his CREATED cell
    return next_node.sr1(Cell(cid=node.identifier, command=Commands.CREATE, payload=cell.dhkey))


# in case he get CREATED from the next node, return it to the previous node, back to the client as EXTENDED
def handle_created(connection: TorClient, cell: Cell, **kwargs):
    client_cell = Cell(cid=1, command=Commands.EXTENDED, pubkey=cell.pubkey, hashkey=cell.hashkey)
    data = client_cell.raw()
    connection.send_cell(create_relay(data))


# every cell COMMAND has it own function to deal with
ACTIONS = {
    Commands.CREATE: handle_create,
    Commands.CREATED: handle_created,
    Commands.RELAY: handle_relay,
    Commands.EXTEND: handle_extend,
    Commands.BEGIN: None,
    Commands.DATA: None
}


def main():
    ip = '0.0.0.0'
    # listen for every cell packet which comes through this port
    server = ORSocket(ip, PORT)
    previous_node = server.accept()

    while True:
        # this OnionRouter gets new cell from the ORSocket and respond with the corresponding procedure
        cell = previous_node.recv_cell()
        cell = ACTIONS[cell.command](previous_node, cell, first=True)
        while cell:
            cell = ACTIONS[cell.command](previous_node, cell, first=False)

    # shut down the socket
    previous_node.close()
    server.close()


if __name__ == '__main__':
    main()
