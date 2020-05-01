import os
import sys
import getopt
import time
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

class Client:

    username = ''
    password = ''

    def __init__(self, client, server, network):
        if client == None:
            client_dir = os.getcwd() + '/client'
            if not os.path.isdir(client_dir):
                os.mkdir(client_dir)
        if server == None:
            server_dir = os.getcwd() + '/server'
            if not os.path.isdir(server_dir):
                os.mkdir(server_dir)
        # if network == None:
        #     # 

        self.nonce = 0
        self.session_key = ''
        self.server_public_key = ''


    # ---------- LOGIN PROTOCOL ---------- #


    def generate_session_key(self):
        session_key = Random.get_random_bytes(32)
        return session_key


    def load_public_key(self):
        with open('test_keys/server_public.pem', 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except:
            print('Error: cannot import public key from file ')
            sys.exit(1)


    def initialize_nonce(self):
        randomBytes = Random.get_random_bytes(8)
        counter = 0
        return randomBytes + counter.to_bytes(8, 'big')


    def increment_nonce(self):
        self.nonce = self.nonce[:8] + (int.from_bytes(self.nonce[8:], 'big') + 1).to_bytes(8, 'big')


    def encrypt_message(self, plaintext, data=b''):
        # if string, encode as bytes
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # initalize cipher for AES
        cipher_aes = AES.new(self.session_key, AES.MODE_GCM, nonce=self.nonce)

        # if there is data, encrypt it along with the original plaintext, ow just the plaintext
        if data != b'':
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext + ' '.encode('utf-8') + data)
        else:
            ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

        Client.increment_nonce(self)
        return ciphertext, tag


    def initialize_login(self):
        print('Sending login message...')

        self.nonce = Client.initialize_nonce(self)
        self.session_key = Client.generate_session_key(self)
        self.server_public_key = Client.load_public_key(self)

        login_type = 'login'
        if new_user:
            login_type = 'new_user'

        plaintext = login_type.encode('utf-8') + username.encode('utf-8') + ':'.encode('utf-8') + password.encode('utf-8')
        encrypted_msg = Client.encrypt_message(self, plaintext)

        cipher_rsa = PKCS1_OAEP.new(self.server_public_key)

        print('Session is successfully established.')
        return 


# ---------- MAIN ---------- #

def main(new_user, client, server, network):
    print('Beginning main routine...')
    curr_client = Client(client, server, network)
    curr_client.initialize_login()

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hu:p:', longopts=['help', 'username=', 'password='])
except:
    print('Usage: ')
    print('client.py -u <username> -p <password>')

new_user = False
client = None
server = None
network = None

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: ')
        print('client.py -u <username> -p <password>')
        sys.exit(1)
    elif opt in ('-u', '--username'):
        username = arg
    elif opt in ('-p', '--password'):
        password = arg

main(new_user, client, server, network)