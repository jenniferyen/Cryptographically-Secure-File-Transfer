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
username = ''

NET_PATH = './network/'
OWN_ADDR = 'S'
CLIENT_ADDR = 'C'


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


def increment_nonce(nonce):
    return nonce[:8] + (int.from_bytes(nonce[8:], 'big') + 1).to_bytes(8, 'big')


def AES_encrypt(plaintext, nonce, data=b''):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    if data != b'':
        ciphertext, auth_tag = cipher_aes.encrypt_and_digest(plaintext + b' - ' + data)
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


def create_new_user(username, password_hash):
    user_folder = server_dir + '/' + username
    if os.path.exists(user_folder):
        print('This username is not available')
    else:
        os.mkdir(user_folder)
        with open(user_folder + '/password.hash', 'wb') as f:
            f.write(password_hash)


def authenticate_user(username, password_hash):
    if username in os.listdir(server_dir):
        with open(server_dir + '/' + username + '/password.hash', 'rb') as f:
            if f.read() == password_hash:
                return True
    return False


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
    global session_key, username
    enc_session_key_and_nonce = msg[:size_of_key]
    session_key_and_nonce = cipher_rsa.decrypt(enc_session_key_and_nonce)
    session_key = session_key_and_nonce[:16]
    nonce = session_key_and_nonce[16:] 

    # process AES(login:username:password)
    credentials_plaintext = AES_decrypt(msg[size_of_key:], nonce)
    nonce = increment_nonce(nonce)
    login_type, username, password = credentials_plaintext.split(':'.encode('utf-8'), 3)

    # user authentication
    password_hash = SHA256.new(data=password).digest()
    if login_type.decode('utf-8') == 'new_user':
        create_new_user(username.decode('utf-8'), password_hash)
    elif login_type.decode('utf-8') == 'login':
        authenticated = authenticate_user(username.decode('utf-8'), password_hash)
        if not authenticated:
            print('User authentication failed. Ending session now...')
            exit(1)

    server_response = AES_encrypt(username, nonce, 'Login successful!')
    nonce = increment_nonce(nonce)
    net_interface.send_msg(CLIENT_ADDR, server_response) 

    print('Session is successfully established.')
    return authenticated, nonce


# ---------- COMMAND PROTOCOL ---------- #

def make_directory(directory_name, net_interface):
    curr_path = server_dir + '/' + username.decode('utf-8')
    try:
        # check path
        os.mkdir(curr_path + '/' + directory_name)
        # send response
    except:
        print('Error: MKD')
        # send response


def remove_directory(directory_name, net_interface):
    curr_path = server_dir + '/' + username.decode('utf-8')
    try:
        # check path
        os.rmdir(curr_path + '/' + directory_name)
        # send response
    except:
        print('Error: RMD')
        # send response


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
    LOGGED_IN, nonce = initialize_session(net_interface)

    while LOGGED_IN:
        status, msg = net_interface.receive_msg(blocking=True)
        if status:
            client_command = AES_decrypt(msg, nonce).split(' '.encode('utf-8'))
            command_code = client_command[0].decode('utf-8')
            
            if command_code == 'MKD':
                print('Making a directory in the server...')
                directory_name = client_command[1].decode('utf-8')
                make_directory(directory_name, net_interface)

            elif command_code == 'RMD':
                print('Removing a directory in the server...')
                directory_name = client_command[1].decode('utf-8')
                remove_directory(directory_name, net_interface)

            elif command_code == 'GWD':
                print('Getting working directory...')

            elif command_code == 'CWD':
                print('Changing working directory...')

            elif command_code == 'LST':
                print('Listing contents of directory...')

            elif command_code == 'UPL':
                print('Uploading file to server...')

            elif command_code == 'DNL':
                print('Downloading file from server...')

            elif command_code == 'RMF':
                print('Removing file from server...')

main()