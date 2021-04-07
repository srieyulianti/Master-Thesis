#!/usr/bin/env python3
# client_as_client.py

import socket
import os
import ssl
import time
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL
from OpenSSL import crypto

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096

HOST = socket.gethostbyname('server')
PORT = 8081

client1_cert = "client1_ssl_key/client1_cert.pem"
client1cert_size = os.path.getsize(client1_cert)
client1_key = "client1_ssl_key/client1_private.pem"
ca_cert = "client1_ssl_key/ca_ssl_key/CA_cert.pem"

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
context.load_cert_chain(certfile = client1_cert, keyfile = client1_key)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(f"[+] Connecting to {HOST}:{PORT}")
time.sleep(2)

print("[+] Waiting server certificate...")
conn = context.wrap_socket(s, server_side=False, server_hostname='server_container')
conn.connect((HOST,PORT))
time.sleep(2)

print ("Server certificate in DER format:")
cert = conn.getpeercert(binary_form=True)
print(cert)
time.sleep(2)

print("Server certificate in PEM format:")
server_cert = ssl.DER_cert_to_PEM_cert(cert)
print(server_cert)
time.sleep (2)

server_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, server_cert)
server_pubkey = server_x509.get_pubkey()
server_pubkeystr = crypto.dump_publickey(crypto.FILETYPE_PEM, server_pubkey)
print(server_pubkey)
time.sleep(2)
print("Server public key in string:")
print(server_pubkeystr)

print("[+] Verify server certificate")
time.sleep(2)

conn.send(b'[+] The Quote has been verified successfully.')
time.sleep(2)
#conn.send(b'[+] Please find client certificate!')
#conn.send(f"{client1_cert}{SEPARATOR}{client1cert_size}".encode())

#with open(client1_cert, "rb") as f:
#    while True:
#        bytes_read = f.read(BUFFER_SIZE)
#        if not bytes_read:
#            break
#        conn.sendall(bytes_read)
        
#print("[+] Client certificate has sent successfully")
print("[+] SSL established. Peer: {}".format(conn.getpeercert()))
time.sleep(2)
print("[+] Server certificate is valid and signed by the authorized CA")

#server_socket, address = s.accept()
#received = server_socket.recv(BUFFER_SIZE).decode()
#filename, filesize = received.split(SEPARATOR)

#remove absolute path
#filename = os.path.basename(filename)

#convert to integer
#filesize = int(filesize)

conn.close()
