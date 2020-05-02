import os
import sys
import getopt
import time
import getpass
from netinterface import network_interface
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


server_dir = os.getcwd() + '/server'
if not os.path.isdir(server_dir):
    os.mkdir(server_dir)

network_dir = os.getcwd() + '/network'
if not os.path.isdir(network_dir):
    os.mkdir(network_dir)


server_public_key = ''
server_private_key = ''


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
        return RSA.import_key(privkeystr, passphrase=RSA_password)
    except:
        print('Error: cannot import private key from file')
        sys.exit(1)


def initialize_session(net_interface):
    print('Server is initializing session...')

    global server_private_key, server_private_key
    server_public_key = load_public_key()
    server_private_key = load_private_key()

    status, msg = net_interface.receive_msg()


# ---------- MAIN ---------- #

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

    net_interface = network_interface(network_dir + '/', 'server')
    initialize_session(net_interface)

main()