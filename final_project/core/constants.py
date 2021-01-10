import ssl
from hashlib import sha256
from Crypto.Cipher import AES


CELL_LEN = 512
HASH_FUNC = sha256
HASH_SIZE = 32
SSL_VERSION = ssl.PROTOCOL_TLSv1_2
AES_MODE = AES.MODE_ECB
DH_SIZE = 1  # In order to decrease the size of the prime number


# Const structure which holds all the different Cell's type
class Commands:
    TYPE = bytes
    # I) Client wants to start connection with the first OnionRouter in the onion circuit. He's sending
    #    Cell which contains a Cell identifier which the OnionRouters are identified by + Encrypted(DH key exchange)
    #    by the RSA public key of the OnionRouter he's about to send this Cell
    # II) by the Client order to extend connection, the first OnionRouter extends the client's CREATE cell
    # III) for any next extend further request, inside the onion network, (which was given by the Client)
    #      the OnionRouter are passing it on.
    CREATE = b'1'
    # Once a CREATE cell is received by an extended OnionRouter, a Cell containing his unique OnionRouter's identifier
    # is send + his DH public key in the key exchange procedure + SHA256(shared key he has successfully created using
    # the Client DH public key part)
    CREATED = b'2'
    # This command basically tells the receiver "Decrypt it with AES-ECB using our DH shared key and execute the command
    # which stored inside".
    RELAY = b'3'
    # cell structure, the unique identifier of the next OnionRouter he's about to pass the CREATE cell to (He can obtain
    # more information about him, using the DirectoryUnit which holds all the info) + Encrypted(DH key exchange)
    # by the RSA public key of the *next* OnionRouter. Whenever a OnionRouter receives this command he knows that he's
    # should create a new CREATE cell and pass it with the info he just got to the next OnionRouter in the circuit.
    EXTEND = b'4'
    # this command notify the Client that this Cell payload contains the CREATED (more info above)Cell from an extended
    # OnionRouter but it came encrypted with the help of the OnionRouter in the middle.
    EXTENDED = b'5'
    # notify the OnionRouter that a connection is about to be established
    BEGIN = b'6'
    # the OnionRouter acknowledgements the connection which the last one has just finish to establish
    CONNECTED = b'7'
    # transferring information from client to end-point (Webpages, Confidential information...)
    DATA = b'8'

