#!/usr/bin/env python3
# client_as_server.py

import socket
#import tqdm
import os

HOST = socket.gethostbyname('ml_client')
PORT = 8081

BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

s = socket.socket()

s.bind((HOST, PORT))

s.listen(5)
print(f"[*] Listening as {HOST}:{PORT}")

client_socket, address = s.accept()
print(f"[+] {address} is connected.")

print(f"[+] Receiving Quote from server: {HOST}")
received = client_socket.recv(BUFFER_SIZE).decode()
filename, filesize = received.split(SEPARATOR)


#remove absolute path
filename = os.path.basename(filename)

#convert to integer
filesize = int(filesize)

#receive the file
#progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)

with open(filename, "wb") as f:
    while True:
        bytes_read = client_socket.recv(BUFFER_SIZE)
        if not bytes_read:
            break
        f.write(bytes_read)
        #progress.update(len(bytes_read))

print(f"[+] Quote received successfully.")

client_socket.close()

s.close()


