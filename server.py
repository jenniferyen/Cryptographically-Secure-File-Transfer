import os
import sys
import getopt
import time
from netinterface import network_interface

server_dir = os.getcwd() + '/server'
if not os.path.isdir(server_dir):
    os.mkdir(server_dir)

# ---------- MAIN ---------- #

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hs:n:', longopts=['help', 'server', 'network'])
except:
    print('Usage: ')
    print('python3 server.py -h')

server = None
network = None

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

main(server, network)