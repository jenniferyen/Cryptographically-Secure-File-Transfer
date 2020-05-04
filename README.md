# Cryptographically-Secure-File-Transfer

## Running the program
This application simulates communication between a client and server over a network. Please run the following commands in order:
1. python3 netsim/network.py -p './network/' -a 'CS' --clean
	- Refer to docs.md for the netsim/ documentation.
2. python3 server.py
	- The RSA password for the provided public/private key pair is 'password'.
3. python3 client.py -n -u <username> -p <password>
	- Only add -n flag if you are a new user. Otherwise, leave it out.

## Commands

## Important notes
- The server will inform you if your command is invalid or improperly formatted.
- You cannot change into a directory that is out of your boundaries. For example, you cannot change into a directory to access other users' files in the server.

## Edge cases
- Currently, the application does not handle cases where the client enters a path as an argument for a command. For example, you must change into a specific directory to remove files from that directory. 
	- The only command that process a path is CWD. 