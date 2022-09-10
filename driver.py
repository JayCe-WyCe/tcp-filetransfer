# driver.py
#
# contains the main script for

import multiprocessing
import rsa
import filemetadata as fmd
from pathlib import Path
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import fileserver
from socket import *
import debugger
import sys


if __name__ == '__main__':
    multiprocessing.freeze_support()

    # check for debug mode
    dbmode = False
    if(len(sys.argv)>1):
        if(sys.argv[1]=="-debug"):
            dbmode = True

    db = debugger.debug(dbmode)

    # main variables
    fernet = None
    gramsize = 4096
    serverport = 1337
    targIP = None
    shared_path = "sharedfolder"
    pr_conn, ch_conn = multiprocessing.Pipe()

    processes = []
    loop = True
    ready = False

    # pre-process: check that the shared folder is up
    sharedfolder = fmd.get_path([".", shared_path])
    if(not fmd.check_path(sharedfolder)):
        fmd.make_folder(sharedfolder)
        print(f"NOTICE: The folder '{sharedfolder}' has been generated.")

    # begin client loop
    while(loop):
        print(f"\nWhat would you like to do?")
        print(f"[s] Start a fileshare server")
        print(f"[t] Connect to a remote fileshare server")
        print(f"[v] View files on the remote fileshare server")
        print(f"[r] Request a remote file by name")
        print(f"[p] View my IP")
        print(f"[f] View files on local folder")
        print(f"[q] Quit")

        choice = input(">> ")

        if(choice=="s"):
            # flag to block main process until server is up
            if(not ready):
                process = multiprocessing.Process(target=fileserver.server,
                    args=[ch_conn, shared_path, serverport, gramsize, dbmode])
                print(f"NOTICE: Starting up the server...")
                process.start()
                processes.append(process)
                while(not ready):
                    ready = pr_conn.recv()
                db.log(f"DB: Server process stored in {processes}.")
            else:
                print(f"NOTICE: The server is already running.")
                db.log(f"DB: Server ready flag: {ready}")

        elif(choice=="t"):
            try:
                # begin by getting the target server
                targIP = input(f"IPv4->")
                if(len(targIP)>0):
                    print(f"NOTICE: Establishing a connection with {targIP}...")
                    # prepare the public key for communications
                    keypair = RSA.generate(2048)
                    pubkey = keypair.publickey().exportKey()

                    # build tuple to let server know what it is receiving
                    data_tup = str((choice, pubkey))
                    db.log(f"DB: Generated a keypair.")
                    
                    # request a connection with the server
                    serverID = (targIP, serverport)
                    client_socket = socket(AF_INET, SOCK_STREAM)
                    db.log(f"DB: Connecting the client socket with {serverID}.")
                    client_socket.connect(serverID)

                    # initiate contact with the public key
                    client_socket.send(data_tup.encode())
                    db.log(f"DB: Sending public key to the server.")
                    encsymkeypacket = client_socket.recv(gramsize)
                    db.log(f"DB: Received symmetric key from server.")

                    # receive the encrypted symmetric key now
                    encsymkey = encsymkeypacket
                    symkey = PKCS1_OAEP.new(keypair).decrypt(encsymkey)
                    db.log(f"DB: symmetric key has been decrypted.")

                    fernet = Fernet(symkey)
                    db.log(f"DB: symmetric key has been stored as a variable.")

                    # close the socket
                    client_socket.close()
                    print(f"NOTICE: Success.")
                else:
                    db.log(f"DB: No input for IPv4 given. Resetting keys.")
                    targIP = None
                    fernet = None

          
            except Exception as err:
                print(f"NOTICE: Failed to connect to {targIP}.")
                targIP = None
                fernet = None
                db.log(f"DB: Connection failed for reason:\n{err}.")
                db.log(f"DB: Server up status: {ready}.")
                db.log(f"DB: Resetting keys.")


        elif(choice=="v"):
            db.log(f"DB: Checking for key exchange: {fernet is not None}.")
            if(fernet is not None):
                # if key is established, communication is ok
                # operating under assumption client won't switch servers
                client_socket = socket(AF_INET, SOCK_STREAM)
                serverID = (targIP, serverport)
                client_socket.connect(serverID)

                data_tup = str((choice, None))
                db.log(f"DB: Sending {data_tup} to server.")
                client_socket.send(data_tup.encode())
                encserverfilenames = client_socket.recv(gramsize)
                db.log(f"DB: Received the encrypted server file names.")

                # close the socket
                client_socket.close()

                serverfilenames = fernet.decrypt(encserverfilenames).decode()
                print(f"{serverfilenames}")
            else:
                print(f"NOTICE: A connection was not established!")

                
        elif(choice=="r"):
            # request to download a file from the server
            if(fernet is not None):
                targfile = input(f"file name->")
                client_socket = socket(AF_INET, SOCK_STREAM)
                serverID = (targIP, serverport)
                client_socket.connect(serverID)
                
                enc_targfile = fernet.encrypt(targfile.encode())
                data_tup = str((choice, enc_targfile))

                # send the encrypted filename requested to the server
                db.log(f"DB: Sending packet to server for file request.")
                client_socket.send(data_tup.encode())

                # listen to the server to know how many chunks for the file
                encchunkcount = client_socket.recv(gramsize)
                chunkcount = int(fernet.decrypt(encchunkcount))
                db.log(f"DB: Client confirms server responds with {chunkcount} chunks.")

                # set up a loop to receive and reconstruct the chunks
                downloads = fmd.get_path([f"{Path.home()}", "Downloads", targfile])
                db.log(f"DB: Client sets downloads folder set to {downloads}.")

                if(chunkcount>0):
                    with open(downloads, "wb") as datafile:
                        db.log(f"DB: Successfully opened file to write.")
                        for i in range(0, chunkcount):
                            try:
                                encdatabuffer = client_socket.recv(gramsize)
                                databuffer = fernet.decrypt(encdatabuffer)
                                datafile.write(databuffer)
                                db.log(f"DB: Client sending acknowledgement...")
                                client_socket.send(str(1).encode())
                            except Exception as err:
                                client_socket.send(str(0).encode())
                                print(f"NOTICE: An error has occurred.")
                                db.log(f"DB: Chunk failed:\n{err}")
                                break
                    print(f"NOTICE: File downloaded to {downloads}.")

                # close the socket
                client_socket.close()
            else:
                print(f"NOTICE: A connection was not established!")
 
        elif(choice=="f"):
            local_files = fmd.get_files(sharedfolder)
            local_filenames = ", ".join(str(f) for f in local_files)
            print(f"{local_filenames}")
                
        elif(choice=="p"):
            localIP = gethostbyname(gethostname())
            print(f"NOTICE: local IP is {localIP}")

        elif(choice=="q"):
            for process in processes:
                process.terminate()
            loop = False


    for process in processes:
        process.join()
            
            

            
            
            
            
