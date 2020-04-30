import os
import sys
import getopt
import time
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

session_key = ''
public_key = ''

newUser = False
username = ''
password = ''

# ---------- LOGIN PROTOCOL ---------- #


def generate_session_key():
    session_key = Random.get_random_bytes(32)
    return session_key


def load_public_key():
    with open('test_keys/server_public.pem', 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except:
        print('Error: cannot import public key from file ')
        sys.exit(1)


def initialize_nonce():
    randomBytes = get_random_bytes(8)
    counter = 0
    return randomBytes + counter.to_bytes(8, 'big')


def encrypt_message(plaintext):
    return ''


def send_login_message():
    print('Sending login message...')

    login_type = 'login'
    if newUser:
        login_type = 'new_user'

    plaintext = login_type.encode(
        'utf-8') + username.encode('utf-8') + ':'.encode('utf-8') + password.encode('utf-8')
    nonce = initialize_nonce()

    encrypted_msg = encrypt_message(plaintext)

    print('Session is successfully established.')


# ---------- MAIN ---------- #

print('Beginning main routine...')

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hu:p:', longopts=['help', 'username=', 'password='])
except:
    print('Usage: ')
    print('client.py -u <username> -p <password>')

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: ')
        print('client.py -u <username> -p <password>')
        sys.exit(1)
    elif opt in ('-u', '--username'):
        username = arg
    elif opt in ('-p', '--password'):
        password = arg

# initialize keys
session_key = generate_session_key()
public_key = load_public_key()