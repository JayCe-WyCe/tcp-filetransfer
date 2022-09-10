# fileserver.py
#
# code for running the file transfer server. The server is started as
# a process by a main. We assumed the data will come in as a tuple,
# (choice, data) so for example, like (1, publickey)

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import os
from socket import *
import filemetadata as fmd
import debugger

def server(pipe_connection, shared_folder_path, serverport, gramsize, dbmode):
    # debugging
    db = debugger.debug(dbmode)

    # server sockets requires a port and IP
    hostname = gethostname()
    serverID = (hostname, serverport)

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.bind(serverID)
    server_socket.listen(1)

    # server is set up and is ready to receive data. Let main know.
    print(f"NOTICE: The server is running and ready for file transfer.")
    pipe_connection.send(True)

    # set up a keychain for users
    keychain = dict()

    while(True):
        choice = None
        data = None
        
        # the server will form a TCP connection with the client
        try:
            connection, client = server_socket.accept()
            packet_income = connection.recvfrom(gramsize)

            # incoming packet is a single tuple of string that must be decoded
            data_tup = eval(packet_income[0].decode())
            client_address = client[0]

            # data_tup takes the form (choice, data)
            choice = data_tup[0]
            data = data_tup[1]
            
        except Exception as err:
            db.log(f"DB: Server packet reception failed.\n{err}")
            

        if(choice=="t"):
            # if option is t, then the data is the public key.
            # client has chosen to initiate a secure channel

            pubkey = RSA.importKey(data)

            # generate a symmetric key and add it to the keychain
            symkey = Fernet.generate_key()
            fernet = Fernet(symkey)
            
            if(client_address in keychain):
                # the case where client re-establishes a connection
                keychain.pop(client_address)
                db.log(f"DB: {client_address} duplicated. Resetting.")
                
            keychain[client_address] = fernet
            db.log(f"DB: Successfully added encryption key.")

            # encrypt the symmetric key and send it back to client
            encsymkey = PKCS1_OAEP.new(pubkey).encrypt(symkey)
            connection.send(encsymkey)
            db.log(f"DB: Sent encrypted symmetric key back to client.")

        elif(choice=="v"):
            # client has requested a list of items from server directory
            if(client_address in keychain):
                shared_files = fmd.get_files(fmd.get_path([".", shared_folder_path]))
                filenames = ", ".join(str(f) for f in shared_files)
                enc_names = keychain[client_address].encrypt(filenames.encode())
                db.log(f"DB: Filenames on server acquired. Sending to client.")
                connection.send(enc_names)

        elif(choice=="r"):
            if(client_address in keychain):
                # the client has requested file download from the server
                targfile = keychain[client_address].decrypt(data).decode()
                db.log(f"DB: Received the file request from client.")

                # get the metadata from the file, and tell the client
                # how many partition it will take
                chunksize = gramsize>>1
                db.log(f"DB: Each chunk will have size {chunksize}.")

                targfilepath = fmd.get_path([".", shared_folder_path, targfile])

                targfilesize = fmd.get_filesize(targfilepath)
                chunkcount = fmd.get_chunkcount(targfilesize, chunksize)
                db.log(f"DB: Server determines to send {chunkcount} chunks.")

                # let the client know how many chunks it should be expecting for the file
                encchunkcount = keychain[client_address].encrypt(str(chunkcount).encode())
                connection.send(encchunkcount)
                db.log(f"DB: Chunk count has been sent to client.")

                # set up a loop to send the chunks of data over
                try:
                    with open(targfilepath, "rb") as datafile:
                        for i in range(0, chunkcount):
                            databuffer = datafile.read(chunksize)
                            encdatabuffer = keychain[client_address].encrypt(databuffer)
                            connection.send(encdatabuffer)
                            db.log(f"DB: Data chunk {i} encrypted and sent. Awaiting acknowledgement from client.")
                            ack = connection.recvfrom(gramsize)
                            ack = ack[0]
                            ackval = int(ack.decode())
                            db.log(f"DB: Acknowledgement received from client: {ackval}")
                            if(ackval!=1):
                                # if ackval is 0, then client failed; server stops sending
                                db.log(f"DB: Client admits failure... no more chunks will be sent.")
                                break
                except Exception as err:
                    print(f"NOTICE: Failed request from {client_address} to retrieve '{targfile}'")
                    db.log(f"DB: Server error while sending file chunks:\n{err}")

        connection.close()   

        
    
