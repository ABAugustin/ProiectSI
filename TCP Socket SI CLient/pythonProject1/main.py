import base64

import numpy as np
import ast
import math
import socket
from RSA import *
from aes import *
p = 29
q = 47
N = p * q

def transform_chunk_into_matrix(chunk):
    dim = int(math.sqrt(len(chunk)))

    matr = [[0 for _ in range(dim)] for _ in range(dim)]

    for i in range(dim):
        for j in range(dim):
            index = i * dim + j
            matr[i][j] = ord(str(chunk[index]))

    return matr


def client_start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    host = "localhost"
    port = 8080
    e = generate_e(p, q)
    server.connect((host, port))
    public_key = str(N) + ":" + str(e)
    server.send(public_key.encode())

    return server, e


def recv_cif(server, e):

    cif = server.recv(1024)
    decrypt_cif = rsa_decrypt(p, q, cif.decode(), e)
    matr = transform_chunk_into_matrix(decrypt_cif)

    return matr

def matrix_transpouse(matrix):
    transposed_matrix = [[0 for _ in range(4)] for _ in range(4)]

    # Calcularea transpusei matricei
    for i in range(4):
        for j in range(4):
            transposed_matrix[j][i] = matrix[i][j]

    return transposed_matrix

def to_matrix(chunk):
    dim = int(math.sqrt(int(len(chunk))))

    matr = [[0 for _ in range(dim)] for _ in range(dim)]
    for i in range(dim):
        for j in range(dim):
            index = i * dim + j
            matr[i][j] = chunk[index]

    return matr

def fragment_files_and_encrypt_and_send(path, server):
    fileR = open(path, "rb")

    #read bytes from file in a variable
    full_file = fileR.read()
    print(full_file)
    # parse it to base64
    base64_full_file = base64.b64encode(full_file)
    full_file = base64_full_file

    print(base64_full_file)
    # print(full_file)
    rest_rounds = len(full_file) % 16
    rounds = int(len(full_file) / 16)
    server.send(str(len(full_file)).encode('utf-8'))
    for i in range(rounds):

        # iau un chunk de 16 bytes
        chunk_16 = full_file[i*16:(i+1)*16]
        print(chunk_16)
        # transform datele in matrice

        matrix = [[chunk_16[i * 4 + j] for j in range(4)] for i in range(4)]
        print("matricea tinta")
        print(matrix)

        #criptez matricea cu rsa
        matrix = encryption_matrix(matrix_transpouse(matrix), cypher_received)
        print(matrix)
        # transform matricea in array

        flat = []
        for row in matrix:
            for num in row:
                flat.append(num)

        print(flat)
        a=str(flat).encode('utf-8')
        len_a= len(a)

        if 80-len_a != 0:
            b = a.decode('utf-8')
            for _ in range(80-len_a):
                b+="a"
            a=b.encode('utf-8')
        print(len(a))
        server.send(a)
        flat.clear()


    # the rest of the file


    data_left = full_file[rounds*16:]

    padding_bytes_needed = 16 - len(data_left)

    if padding_bytes_needed != 16:

        data_left += b'\x00' * padding_bytes_needed

        matrices = data_left


        matrix = encryption_matrix(matrix_transpouse(to_matrix(matrices)), cypher_received)

        flat = []
        for row in matrix:
            for num in row:
                flat.append(num)

        print("flat rest")
        print(flat)
        a = str(flat).encode('utf-8')
        len_a = len(a)

        if 80 - len_a != 0:
            b = a.decode('utf-8')
            for _ in range(80 - len_a):
                b += "a"
            a = b.encode('utf-8')
        print(len(a))
        server.send(a)
        flat.clear()




    server.shutdown(1)
    server.close()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    path = "abel.jpg"
    #path = "abc.txt"
    #path = "bluebrick.png"
    #path = "poza.jpg"
    serv, e = client_start()
    cypher_received = recv_cif(serv, e)
    fragment_files_and_encrypt_and_send(path,serv)



