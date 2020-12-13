import socket

# initialize const values on client side
PORT = 9000
HEADER = 64
DISCONNECT_MESSAGE = "!DISCONNECT!"
SERVER_ADDRESS = '192.168.112.1'

client_socket = socket.socket()
client_socket.connect((SERVER_ADDRESS, PORT))


# prepare the message before sending
# the header defines the size of the next message
def send(message: str):
    msg = message.encode()
    msg_length = len(message)
    send_length = str(msg_length).encode()
    send_length += b' ' * (HEADER - len(send_length))
    client_socket.send(send_length)  # notify the server about the length
    client_socket.send(msg)


send("message test 1")
input()
send("continue - test 2")
input()
send("continue - test 3")
input()

# close connection and free the thread!
send(DISCONNECT_MESSAGE)


