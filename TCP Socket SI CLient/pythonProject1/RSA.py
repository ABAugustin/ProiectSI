
import random


def putere(number, power):
    binar = bin(power)
    val = number
    for i in range(3, len(binar)):
        val = val * val
        if binar[i] == '1':
            val = val * number
    return val


def cmmdc(a, b):
    if a == 0:
        return b
    return cmmdc(b % a, a)

def generate_e(p,q):
    N=p*q
    PHI = (p - 1) * (q - 1)
    e = random.randint(1, N)
    while cmmdc(e, PHI) != 1:
        e = random.randint(1, N)

    return e

def rsa_encrypt(p, q, plaintext):
    N=p*q
    e = generate_e(p, q)

    encrypted_text = [(putere(ord(char), e) % N) for char in plaintext]

    return encrypted_text, e

def generate_d(p,q,e):
    N = p * q
    PHI = (p - 1) * (q - 1)
    k = 0
    for k in range(1, PHI):
        if ((k * PHI) + 1) % e == 0:
            break
    d = (1 + PHI * k) // e

    return d

def rsa_decrypt(p, q, cyphertext, e):
    N = p * q
    d=generate_d(p,q,e)
    decrypted_text=""
    #decrypted_text = ''.join([chr((putere(char, d) % N)) for char in cyphertext])

    for chars in cyphertext:
        decrypted_text += chr(putere(ord(chars), d) % N)

    return decrypted_text

if __name__ == '__main__':
    print('p = ')
    p = int(input())
    print('q = ')
    q = int(input())
    print("plaintext = ")
    plaintext = input()
    cyphertext, e = rsa_encrypt(p, q, plaintext)
    print(f"\n\nCiphertext = {cyphertext}")
    decrypt = rsa_decrypt(p, q, cyphertext, e)
    print(f"\nDecrypted text = {decrypt}")