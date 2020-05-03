import os
import sys
import getopt
import time
from netsim.netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


# create directories if not present
client_dir = os.getcwd() + '/client'
if not os.path.isdir(client_dir):
    os.mkdir(client_dir)

server_dir = os.getcwd() + '/server'
if not os.path.isdir(server_dir):
    os.mkdir(server_dir)

network_dir = os.getcwd() + '/network'
if not os.path.isdir(network_dir):
    os.mkdir(network_dir)

username = ''
password = ''
nonce = 0
session_key = ''
server_public_key = ''

NET_PATH = './network/'
OWN_ADDR = 'C'
SERVER_ADDR = 'S'


# ---------- LOGIN PROTOCOL ---------- #


def generate_session_key():
    session_key = Random.get_random_bytes(16)
    return session_key


def load_public_key():
    with open('test_keys/server_public.pem', 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except:
        print('Error: cannot import public key from file')
        sys.exit(1)


def initialize_nonce():
    randomBytes = Random.get_random_bytes(8)
    counter = 0
    return randomBytes + counter.to_bytes(8, 'big')


def increment_nonce():
    global nonce
    nonce = nonce[:8] + (int.from_bytes(nonce[8:], 'big') + 1).to_bytes(8, 'big')


def AES_encrypt(plaintext, data=b''):
    global nonce
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
    if data != b'':
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext + b' ' + data)
    else:
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext)

    # print('client side session_key: ')
    # print(session_key)
    # print('client side nonce: ')
    # print(nonce)
    # print('client side auth_tag: ')
    # print(auth_tag)
    # print('client side ciphertext: ')
    # print(ciphertext)

    # increment_nonce()
    return auth_tag + ciphertext


def process_server_response(server_response):
    return


def initialize_login(net_interface, new_user):
    print('Sending login message...')

    global nonce, session_key, server_public_key
    nonce = initialize_nonce()
    session_key = generate_session_key()
    server_public_key = load_public_key()

    login_type = 'login:'
    if new_user:
        login_type = 'new_user:'

    # E_S_k(login type | username | password)
    plaintext = login_type.encode('utf-8') + username.encode('utf-8') + ':'.encode('utf-8') + password.encode('utf-8')
    aes_encrypted = AES_encrypt(plaintext) # auth_tag + ciphertext
    # increment_nonce()

    # E_k^+(S_k, nonce)
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    rsa_encrypted = cipher_rsa.encrypt(session_key + nonce)

    # RSA(session key + nonce) + AES(login:username:password)
    combined_msg = rsa_encrypted + aes_encrypted
    net_interface.send_msg(SERVER_ADDR, combined_msg)

    server_response = net_interface.receive_msg()
    print('client side server response: ')
    print(server_response)

    print('Session is successfully established.')


# ---------- MAIN ROUTINE ---------- #

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hnu:p:', longopts=['help', 'new_user', 'username=', 'password='])
except:
    print('Usage: ')
    print('python3 client.py -u <username> -p <password>')

new_user = False

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: ')
        print('python3 client.py -u <username> -p <password>')
        print('Add flag -n if you are a new user')
        sys.exit(1)
    elif opt in ('-n', '--new_user'):
        new_user = True
    elif opt in ('-u', '--username'):
        username = arg
    elif opt in ('-p', '--password'):
        password = arg

def main(new_user):
    print('Beginning client side routine...')

    net_interface = network_interface(NET_PATH, OWN_ADDR)
    initialize_login(net_interface, new_user)

main(new_user)