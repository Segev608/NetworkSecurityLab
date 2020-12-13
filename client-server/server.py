from socket import *
import threading


# other functionality which returns default web-page for every
# request [can be improved]
def init_server():
    server = socket(AF_INET, SOCK_STREAM) # initialize the socket
    try:
        server.bind(('localhost', 9000)) # listen to specific source
        server.listen(5) # request from OS to hold in queue max 5 requests while processing

        while True:
            # the rule is - the client speaks first. so as a server, we must wait for him
            client, address = server.accept() # in case someone connected to our socket, the server can accept him
            # we're getting here only if a request received
            received = client.recv(5000).decode()
            data = received.split('\n')
            if len(data) > 0:
                print(data)
            response = "HTTP/1.1 200 OK \r\n"
            response += "Content-Type: text/html; charset=utf-8\r\n"
            response += "\r\n"
            response += "<html><body>Hello from Segev</body></html>\r\n\r\n"
            client.sendall(response.encode())
            client.shutdown(SHUT_WR) # http is stateless so connection must closed after every session
    except KeyboardInterrupt:
        print("\nserver is shutting down...\n")
    except Exception as e:
        print("ERROR:\n "+str(e))
    server.close()


SERVER_IP = gethostbyname(gethostname())  # returns the host ip address
PORT = 9000
HEADER = 64
ADDRESS = (SERVER_IP, PORT)
DISCONNECT_MESSAGE = "!DISCONNECT!"

server = socket(AF_INET, SOCK_STREAM)
server.bind(ADDRESS)


# this function will run separately (different thread) for each
# client which send info
def handle_client(connection: socket, address):
    print(f"[NEW CONNECTION ESTABLISHED] {address} connected")
    connected = True

    # while client has not free the thread, handle the session
    while connected:
        msg_length = connection.recv(HEADER).decode()
        if msg_length:  # in case we got any messages
            msg_length = int(msg_length)
            msg = connection.recv(msg_length).decode()
            if msg == DISCONNECT_MESSAGE:  # if the client has sent the disconnect message - free the thread
                connected = False
            print(f"[RECEIVED DATA] {address} sent {msg}")
    # close the socket with this current client
    connection.close()


def activate_server():
    server.listen()  # listen to our socket
    while True:
        # get the connection socket and his ip address(of the client)
        conn, addr = server.accept()  # accept connection with client and move on
        # allocate new thread to deal with his session
        # this methodology is great because recv() function waits until
        # fully-message has received which cause all the system to wait.
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1} connections")


if __name__ == '__main__':
    print(f"[INFORMATION] listening on {SERVER_IP}")
    print("[STARTING] server is starting...")

    activate_server()
# init_server()



