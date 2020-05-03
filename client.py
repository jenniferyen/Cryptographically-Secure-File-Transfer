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


def increment_nonce(nonce):
    return nonce[:8] + (int.from_bytes(nonce[8:], 'big') + 1).to_bytes(8, 'big')


def AES_encrypt(plaintext, nonce, data=b''):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')

    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    if data != b'':
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext + b' ' + data)
    else:
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext)

    return auth_tag + ciphertext


def AES_decrypt(msg, nonce):
    auth_tag = msg[:16] 
    ciphertext = msg[16:]
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)

    try:
        plaintext = cipher_aes.decrypt_and_verify(ciphertext, auth_tag)
        return plaintext
    except:
        print('AES-GCM authentication failed. Ending session now...')
        exit(1)


def initialize_login(net_interface, new_user):
    print('Sending login message...')

    global session_key, server_public_key
    nonce = initialize_nonce()
    session_key = generate_session_key()
    server_public_key = load_public_key()

    login_type = 'login:'
    if new_user:
        login_type = 'new_user:'

    # E_k^+(S_k, nonce)
    cipher_rsa = PKCS1_OAEP.new(server_public_key)
    rsa_encrypted = cipher_rsa.encrypt(session_key + nonce)

    # E_S_k(login type | username | password)
    plaintext = login_type.encode('utf-8') + username.encode('utf-8') + ':'.encode('utf-8') + password.encode('utf-8')
    aes_encrypted = AES_encrypt(plaintext, nonce) # auth_tag + ciphertext
    nonce = increment_nonce(nonce)

    # RSA(session key + nonce) + AES(login:username:password)
    combined_msg = rsa_encrypted + aes_encrypted
    net_interface.send_msg(SERVER_ADDR, combined_msg)

    status, server_response = net_interface.receive_msg(blocking=True)
    login_result = AES_decrypt(server_response, nonce)
    print(login_result)

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