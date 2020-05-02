import os
import sys
import getopt
import time
import getpass
from netsim.netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256


# create directories if not present
server_dir = os.getcwd() + '/server'
if not os.path.isdir(server_dir):
    os.mkdir(server_dir)

network_dir = os.getcwd() + '/network'
if not os.path.isdir(network_dir):
    os.mkdir(network_dir)

server_public_key = ''
server_private_key = ''
session_key = ''
nonce = 0

NET_PATH = './network/'
OWN_ADDR = 'S'


# ---------- LOGIN PROTOCOL ---------- #


def load_public_key():
    with open('test_keys/server_public.pem', 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except:
        print('Error: cannot import public key from file')
        sys.exit(1)


def load_private_key():
    RSA_password = getpass.getpass("Enter RSA password: ")
    with open('test_keys/server_private.pem', 'rb') as f:
        privkeystr = f.read()
    try:
        # password for the provided public/private key pair is 'password'
        return RSA.import_key(privkeystr, passphrase=RSA_password)
    except:
        print('Error: cannot import private key from file')
        sys.exit(1)


def increment_nonce():
    global nonce
    nonce = nonce[:8] + (int.from_bytes(nonce[8:], 'big') + 1).to_bytes(8, 'big')


def AES_decrypt(msg):
    auth_tag = msg[:16] 
    ciphertext = msg[16:]
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)

    try:
        # print('server side session_key: ')
        # print(session_key)
        # print('server side nonce: ') 
        # print(nonce)
        # print('server side auth_tag: ')
        # print(auth_tag)
        # print('server side ciphertext: ')
        # print(ciphertext)
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, auth_tag)
        # increment_nonce()
        return plaintext
    except:
        print('AES-GCM authentication failed. Ending session now...')
        exit(1)


def create_new_user(username, password_hash):
    user_folder = server_dir + '/' + username
    if os.path.exists(user_folder):
        print('This username is not available')
    else:
        os.mkdir(user_folder)
        with open(user_folder + '/password.hash', 'wb') as f:
            f.write(password_hash)


def send_response():
    print('Sending response back to client...')


def initialize_session(net_interface):
    print('Server is initializing session...')

    global server_private_key, server_private_key
    server_public_key = load_public_key()
    server_private_key = load_private_key()

    # RSA(session key + nonce) + AES(login:username:password)
    status, msg = net_interface.receive_msg(blocking=True)

    cipher_rsa = PKCS1_OAEP.new(server_private_key)
    size_of_key = server_public_key.size_in_bytes() # 256 bytes

    # get session_key and nonce
    global session_key, nonce
    enc_session_key_and_nonce = msg[:size_of_key]
    session_key_and_nonce = cipher_rsa.decrypt(enc_session_key_and_nonce)
    session_key = session_key_and_nonce[:16]
    nonce = session_key_and_nonce[16:]

    # process AES(login:username:password)
    credentials_plaintext = AES_decrypt(msg[size_of_key:])
    login_type, username, password = credentials_plaintext.split(':'.encode('utf-8'), 3)

    password_hash = SHA256.new(data=password).digest()
    if login_type.decode('utf-8') == 'new_user':
        create_new_user(username.decode('utf-8'), password_hash)
    elif login_type.decode('utf-8') == 'login':
        print('Verifying credentials...')

    send_response()


# ---------- MAIN ROUTINE ---------- #

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hs:n:', longopts=['help', 'server', 'network'])
except:
    print('Usage: ')
    print('python3 server.py -h')

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: ')
        print('python3 server.py -h <help> -s <path_to_server_dir> -n <path_to_network_dir>')
        sys.exit(1)
    elif opt == '-s' or opt == '--server':
        server = arg
    elif opt == '-n' or opt == '--network':
        network = arg

def main():
    print("Beginning server side routine...")

    net_interface = network_interface(NET_PATH, OWN_ADDR)
    initialize_session(net_interface)

main()