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
WORKING_DIR = server_dir + '/'


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
    login_type, username, password = credentials_plaintext.split(':'.encode('utf-8'), 3)
    nonce = increment_nonce(nonce)

    # user authentication
    password_hash = SHA256.new(data=password).digest()
    if login_type.decode('utf-8') == 'new_user':
        create_new_user(username.decode('utf-8'), password_hash)
    elif login_type.decode('utf-8') == 'login':
        authenticated = authenticate_user(username.decode('utf-8'), password_hash)
        if not authenticated:
            print('User authentication failed. Ending session now...')
            exit(1)

    # send success response to client
    server_response = AES_encrypt(username, nonce, 'Login successful!')
    net_interface.send_msg(CLIENT_ADDR, server_response) 
    nonce = increment_nonce(nonce)

    # update working directory
    global WORKING_DIR
    WORKING_DIR = WORKING_DIR + username.decode('utf-8')

    print('Session is successfully established.')
    return authenticated, nonce


# ---------- COMMAND PROTOCOL ---------- #

def make_directory(directory_name, net_interface, nonce):
    try:
        # check path
        os.mkdir(WORKING_DIR + '/' + directory_name)
        mkd_response = AES_encrypt(directory_name + ' successfully created', nonce)
        net_interface.send_msg(CLIENT_ADDR, mkd_response)
        nonce = increment_nonce(nonce)
    except:
        print('Error: MKD')
        mkd_response = AES_encrypt('Error creating directory', nonce)
        net_interface.send_msg(CLIENT_ADDR, mkd_response)
        nonce = increment_nonce(nonce)
    return nonce


def remove_directory(directory_name, net_interface, nonce):
    try:
        # check path
        os.rmdir(WORKING_DIR + '/' + directory_name)
        rmd_response = AES_encrypt(directory_name + ' successfully removed', nonce)
        net_interface.send_msg(CLIENT_ADDR, rmd_response)
        nonce = increment_nonce(nonce)
    except:
        print('Error: RMD')
        rmd_response = AES_encrypt('Error removing directory', nonce)
        net_interface.send_msg(CLIENT_ADDR, rmd_response)
        nonce = increment_nonce(nonce)
    return nonce


def change_working_dir(path_to_dir, net_interface, nonce):
    global WORKING_DIR
    try:
        # check path
        dirs = path_to_dir.split('/')
        for dir in dirs:
            if dir == '..':
                # figure out break condition
                    # print('Error: CWD out of bounds')
                    # break
                # else:
                WORKING_DIR = '/'.join(WORKING_DIR.split('/')[:-1])
            elif os.path.exists(WORKING_DIR + '/' + dir):
                WORKING_DIR = WORKING_DIR + '/' + dir

        cwd_response = AES_encrypt('Changed to: ' + WORKING_DIR, nonce)
        net_interface.send_msg(CLIENT_ADDR, cwd_response)
        nonce = increment_nonce(nonce)
    except:
        print('Error: CWD')
        cwd_response = AES_encrypt('Error changing working directory', nonce)
        net_interface.send_msg(CLIENT_ADDR, cwd_response)
        nonce = increment_nonce(nonce)
    return nonce, WORKING_DIR


def remove_file(file_name, net_interface, nonce):
    try:
        # check path
        if file_name == 'password.hash':
            print('Cannot remove this file')
            rmf_response = AES_encrypt('Cannot remove this file', nonce)
            net_interface.send_msg(CLIENT_ADDR, rmf_response)
            nonce = increment_nonce(nonce)
        elif os.path.exists(WORKING_DIR + '/' + file_name):
            os.remove(WORKING_DIR + '/' + file_name)
            rmf_response = AES_encrypt(file_name + ' successfully removed', nonce)
            net_interface.send_msg(CLIENT_ADDR, rmf_response)
            nonce = increment_nonce(nonce)
    except:
        print('Error: RMF')
        rmf_response = AES_encrypt('Error removing file', nonce)
        net_interface.send_msg(CLIENT_ADDR, rmf_response)
        nonce = increment_nonce(nonce)
    return nonce


# def upload_file(file_name, data, net_interface, nonce):
#     try:
#         # 
#     except:
#         # 


# def download_file(file_name, net_interface, nonce):
#     try:
#         # 
#     except:
        


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
            nonce = increment_nonce(nonce)

            global WORKING_DIR 

            if command_code == 'MKD':
                print('Making a directory in the server...')
                directory_name = client_command[1].decode('utf-8')
                nonce = make_directory(directory_name, net_interface, nonce)

            elif command_code == 'RMD':
                print('Removing a directory in the server...')
                directory_name = client_command[1].decode('utf-8')
                nonce = remove_directory(directory_name, net_interface, nonce)

            elif command_code == 'GWD':
                print('Getting working directory...')
                gwd_response = AES_encrypt('Current working directory is: ' + WORKING_DIR, nonce)
                net_interface.send_msg(CLIENT_ADDR, gwd_response) 
                nonce = increment_nonce(nonce)

            # a little buggy
            elif command_code == 'CWD':
                print('Changing working directory...')
                path_to_dir = client_command[1].decode('utf-8')
                nonce, NEW_WORKING_DIR = change_working_dir(path_to_dir, net_interface, nonce)
                WORKING_DIR = NEW_WORKING_DIR

            elif command_code == 'LST':
                print('Listing contents of directory...')
                dir_items = ", ".join(os.listdir(WORKING_DIR))
                lst_response = AES_encrypt(dir_items, nonce)
                net_interface.send_msg(CLIENT_ADDR, lst_response)
                nonce = increment_nonce(nonce)

            elif command_code == 'UPL':
                print('Uploading file to server...')
                print(client_command)
                # file_name = client_command[1].decode('utf-8')
                # nonce = upload_file(file_name, data, net_interface, nonce)
                # nonce = increment_nonce(nonce)

            elif command_code == 'DNL':
                print('Downloading file from server...')

            elif command_code == 'RMF':
                print('Removing file from server...')
                file_name = client_command[1].decode('utf-8')
                nonce = remove_file(file_name, net_interface, nonce)

main()