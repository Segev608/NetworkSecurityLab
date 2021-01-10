from typing import Union

from core.utils import *
from core.sockets import TorClient
from core.cell import *
from core.utils import Colors
import webbrowser

node_ip = '127.0.0.1'
server: TorClient = None

directory = DirectoryUnit()
nodes = directory.get_circuit()
f_node: OnionNode = None
# create DH instance
client_dh = DiffieHellman(DH_SIZE)
# list with all the keys which shared between client-routers
shared_keys = {}
# generate the *user* diffie hellman public key
dh_pubkey = client_dh.gen_public_key()


# In the OnionRouting theory, the client must initiate the first step
# and send his DH to the first node in the circuit
def init_connection(onion_node: OnionNode):
    encrypted_dh_key = RSA.encrypt(onion_node.pubkey, dh_pubkey)
    cell = CreateCell(cid=onion_node.identifier, enc_dh_key=encrypted_dh_key)
    print(f'Sending {Colors.colorful_str(color="cyan", sentence="CREATE")}: {cell}')
    cell = server.sr1(cell)
    print(f'Got {Colors.colorful_str(color="cyan", sentence="CREATED")} Response: {cell}')

    handle_cretexed(cell)


# whenever a OnionRouter returns an answer to the CREATE packet
def handle_cretexed(cell: Union[CreatedCell, ExtendedCell]):
    global shared_keys
    shared_key = client_dh.gen_shared_key(cell.dh_key)[:32]
    print(f'Shared DH Key With {cell.cid}: {Colors.colorful_str(color="blue", sentence=f"{shared_key}")}')

    if HASH_FUNC(shared_key.encode()).digest() == cell.hashkey:
        # update the keys database to include the new OnionRouter
        shared_keys[cell.cid] = shared_key
        print(f'Success. Connection with {cell.cid} {Colors.colorful_str(color="green", sentence="established")}.')
    else:
        raise Exception(f'{Colors.colorful_str(color="red", sentence="Failed")} connecting to {cell.cid}. DH shared key hash wrong.')


# handles the creation of the onion's encryption "layers"
def create_relay(cell: Cell):
    payload = cell.relay()
    # the most extended router will be located in the
    # most inner section of the encryption layer
    for node in reversed(shared_keys):
        cipher = AES.new(shared_keys[node].encode(), AES_MODE)
        payload = cipher.encrypt(payload)
        payload = PayloadCell(cid=node, command=Commands.RELAY, payload=payload).relay()
    return from_bytes(payload)


# the client "peels" the encryption layers which the
# OnionRouter has created
def handle_relay(cell: Cell):
    # last OnionRouter's key to encrypt will be the
    # first one to decrypt with
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


# in order to test the connectivity of our small network
def begin_session():
    cell = PayloadCell(1, Commands.BEGIN, b'')
    cell = create_relay(cell)
    server.sr1(cell)
    print(f'{Colors.colorful_str(color="green", sentence="Connected!")}!')


def request_data(request: str):
    cell = PayloadCell(cid=1, command=Commands.DATA, payload=request.encode())
    cell = create_relay(cell)
    response = server.sr1(cell)
    response = handle_relay(response)
    path = '/home/kali/Desktop/'
    with open(f'{path}img.png', 'wb+') as f:
        f.write(response.payload)
    # webbrowser.open(f'{path}img.png') - This line needs root permission on linux. works better on windows


def main():
    global server, f_node
    input('Get & Shuffle Nodes:')
    random.shuffle(nodes)
    print(f'Node Order: {nodes}')
    f_node = directory.get_node(nodes[0])
    server = TorClient(f_node.ip, f_node.port)
    input(f'\nPress enter to send {Colors.colorful_str(color="cyan", sentence="CREATE")} message')
    # startup the key-exchange with the first OR
    init_connection(f_node)
    for node in nodes[1:]:
        input(f'\nPress enter to {Colors.colorful_str(color="cyan", sentence="EXTEND")} your path')
        extend_connection(directory.get_node(node))

    url = 'https://blog.torproject.org/' \
          'sites/default/files/styles/full_width/public/image/tor-project-thank-you.jpg.png?itok=pALMzuNb'
    # print('Anonymous Browsing:')
    # input('Enter URL: ')
    input(f'\nPress enter to {Colors.colorful_str(color="cyan", sentence="BEGIN")} connection')
    begin_session()
    input(f'\nPress enter to request {Colors.colorful_str(color="cyan", sentence="DATA")} - final image!')
    request_data(url)

    server.close()


if __name__ == '__main__':
    main()
