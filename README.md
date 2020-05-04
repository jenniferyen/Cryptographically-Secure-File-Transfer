# Cryptographically-Secure-File-Transfer

## Running the program
This application simulates communication between a client and server over a network. It supports multiple users on one server. However, the way I implemented the netsim/ package only records logs from any one client/server session at a time. 

Please run the following commands in order and follow this process every time you initiate a new session:
1. python3 netsim/network.py -p './network/' -a 'CS' --clean
	- Refer to docs.md for the netsim/ documentation.
    - -p <path_to_network>
    - -a <addresses (I used C and S for client and server)>
2. python3 server.py
	- IMPORTANT: The RSA password for the provided public/private key pair is 'password'.
3. python3 client.py -n -u <username> -p <password>
	- -n indicates that you are a new user. Otherwise, leave it out.
    - -u <your_username>
    - -p <your_password>

## Commands

## Important notes
- The server will inform you if your command is invalid or improperly formatted.
- You cannot change into a directory that is out of your boundaries. For example, you cannot change into a directory to access other users' files in the server.

## Edge cases
- Currently, the application does not handle cases where the client enters a path as an argument for a command. For example, you must change into a specific directory to remove files from that directory. 
	- The only command that process a path is CWD. 
- You cannot remove your 'password.hash' file.
- I have only tested UPL and DNL with text files. The client side has difficult decrypting files of other types.

## Encryption specifications
- The session is initialized using hybrid encryption with RSA and AES-GCM (more on this in the login protocol session below).
- Messages between the client and server are encrypted using AES in GCM mode. 
- When uploading a file to the server, files are encrypted using AES in GCM mode and a file key generated with password based key derivation. This file key is never sent to the server. 
- When downloading a file from the server, the file is decrypted with the filekey so that the client can read the plaintext.

## Login protocol

## Command protocol