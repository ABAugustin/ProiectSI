import base64
import binascii
import math
import ssl
import socket
import os
import time
import sys

import RSA
from RSA import *
from AES import *
############################ SERVER #######################


# luate cu nmap
host = "0.0.0.0"
port = 8080

cypher_ex = [
        [0x2b, 0x28, 0xab, 0x09],
        [0x7e, 0xae, 0xf7, 0xcf],
        [0x15, 0xd2, 0x15, 0x4f],
        [0x16, 0xa6, 0x88, 0x3c]
    ]

def transform_chunk_into_matrix(chunk):
    dim = int(math.sqrt(len(chunk)))

    matr = [[0 for _ in range(dim)] for _ in range(dim)]

    for i in range(dim):
        for j in range(dim):
            index = i * dim + j
            matr[i][j] = chunk[index]

    return matr


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    server.bind((host, port))
    server.listen(5)

    return server

def matrix_transpouse(matrix):
    transposed_matrix = [[0 for _ in range(4)] for _ in range(4)]

    # Calcularea transpusei matricei
    for i in range(4):
        for j in range(4):
            transposed_matrix[j][i] = matrix[i][j]

    return transposed_matrix

def binding_client():
    client, address = server.accept()

    public_key = client.recv(1024)
    public_key = public_key.decode()
    list_of_args = public_key.split(":")

    N = int(list_of_args[0])
    e = int(list_of_args[1])

    # criptare cheie aes cu rsa(N,e) si trimitere spre client


    flat = ""
    for row in cypher_ex:

        for num in row:
            flat += chr(num)

    encrypted_cif = rsa_encrypt(N, e, flat)

    client.send((encrypted_cif).encode())
    return client

def recv_file_chunks(server):
    data_len = int(server.recv(1024).decode('utf-8'))
    final_text = []
    text = b''
    chunk = server.recv(80)
    with open("abel_transferat.jpg", "wb") as file:
    #with open("poza_transferat.jpg", "wb") as file:
        print(len(chunk))
        while chunk:
            print(len(chunk))
            old_chunk_decoded = chunk.decode('utf-8')
            chunk_decoded = ''.join(caracter for caracter in old_chunk_decoded if caracter != 'a')
            print(old_chunk_decoded)
            print(chunk_decoded)
            #print(type(chunk.decode('utf-8')))
            numbers_array = eval(chunk_decoded)

            chunk = transform_chunk_into_matrix(numbers_array)

            chunk = decryption_matrix(chunk, cypher_ex)

            chunk = matrix_transpouse(chunk)

            flat = []
            for row in chunk:
                for num in row:
                    flat.append(num)

            print("flat dupa trasnfer")
            print(flat)



            #print(final_text)
            if client.gettimeout() != 0:

                chunk = server.recv(80)
                sir_bytes = bytes(flat)
                print("sirul nou")
                print(sir_bytes)
                print(base64.b64decode(sir_bytes))
                flat.clear()
                text += base64.b64decode(sir_bytes)
        file.write((text[:data_len]))


if __name__ == '__main__':
    server = start_server()
    print("Serverul pornit")
    client = binding_client()
    recv_file_chunks(client)