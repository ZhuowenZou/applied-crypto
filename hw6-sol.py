#from Crypto.Cipher import AES
#from Crypto import Random
from sage.all import *
import copy
import sys

import struct
import re
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import *


def prod_tree(moduli):
    global squares
    global counter

    prod = Integer(1)
    l = len(moduli)
    if l == 1:
        squares.append(moduli[0] ** 2)
        return moduli[0]
    else:
        prod *= prod_tree(moduli[:l // 2])
        prod *= prod_tree(moduli[l // 2:])
        prod = Integer(prod)
        if len(moduli) != 100000:
            squares.append(prod * prod)
        return Integer(prod)


def remainder_walk(rem, moduli):
    global squares
    global factored
    global counter
    l = len(moduli)
    # print("Going: rem = %d, moduli ="%(rem), moduli)
    # print(squares)

    if l == 1:
        result = rem.divide_knowing_divisible_by(moduli[0])
        the_gcd = gcd(result, moduli[0])
        if the_gcd != 1:
            factored.append((moduli[0], the_gcd))
            # print("Moduli factored! ", moduli[0], gcd)
    else:
        # _, rem_r = rem.quo_rem(squares[-1])
        rem_r = Mod(rem, squares[-1])
        del squares[-1]
        remainder_walk(Integer(rem_r), moduli[l // 2:])

        # _, rem_l = rem.quo_rem(squares[-1])
        rem_l = Mod(rem, squares[-1])
        del squares[-1]
        remainder_walk(Integer(rem_l), moduli[:l // 2])


file = open("moduli.sorted", "r")
moduli = []
squares = []
factored = []
counter = 0

for i in range(100000):
    modulus = file.readline()
    moduli.append(Integer(int(modulus, 16)))

file.close()

product = prod_tree(moduli)
remainder_walk(product, moduli)

# Store it just in case
file = open("moduli.factor","w")
for (x,y) in factored:
    file.write(str(x) + "\n")
    file.write(str(y) + "\n")
file.close()

#extended gcd 
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        q, y, x = egcd(b % a, a)
        return (q, x - (b // a) * y, y)
def inverse(a, p):
    _, inv, _= egcd(a, p)
    inv = (inv+p)%p
    return inv

# Chinese remainder theorem
def crt(constrains):
    result = 0
    big_p = 1
    for (x, p) in constrains:
        big_p *= p
    for (x, p) in constrains:
        curr_p = big_p//p
        #print(egcd(curr_p, p))
        inv = inverse(curr_p % p, p)
        #print(inv * (curr_p % p) % p )
        assert inv * (curr_p % p) % p == 1
        result = (result + (curr_p * inv * x)) % big_p
    return result, big_p

file = open("moduli.factor","r")
moduli = []
factors = []
while True:
    modulus = file.readline()
    if modulus == "":
        break
    moduli.append(int(modulus))
    fac1 = int(file.readline())
    fac2 = int(modulus)//fac1
    factors.append((fac1, fac2))
file.close()

e = 65537
sks = []
for i in range(len(moduli)):
    fac1 = factors[i][0]-1
    d1 = inverse(e, fac1)
    assert e * d1 % fac1 == 1
    fac2 = factors[i][1]-1
    d2 = inverse(e, fac2)
    assert e * d2 % fac2 == 1
    fac, _, _ = egcd(fac1, fac2)
    sk, _ = crt([(d1, fac1//fac), (d2, fac2//fac)])
    while sk * e % (fac1 * fac2) != 1:
        sk += (fac1 * fac2 //fac // fac)
    assert sk*e % (fac1 * fac2) == 1
    sks.append(sk)

encrypt_header = '-----BEGIN PRETTY BAD ENCRYPTED MESSAGE-----\n'
encrypt_footer = '-----END PRETTY BAD ENCRYPTED MESSAGE-----\n'
ciphertext = open('hw6.pdf.enc.asc').read()
ciphertext = b64decode(ciphertext[len(encrypt_header):-len(encrypt_footer)])

pref = 0
p_len = int.from_bytes(ciphertext[pref:pref+4],"little")
#print(p_len)
p = int.from_bytes(ciphertext[pref+4:pref+4+p_len],"big")
pref = 4 + p_len

for i in len(sks):
    decry = pow(p, sks[i], moduli[i])
    s = "%x"%(decry)
    if len(s) == 253:  # A hack for find the right aeskey
        s = s[s.find("00") + 2:]
        aeskey = int(s).to_bytes(32, byteorder='big')
        break

def strip_padding(msg):
    padlen = msg[-1]
    if padlen > 16:
        return None
    if msg[-padlen:] != bytes([padlen]*padlen):
        return None
    return msg[:-padlen]

ciphertext2 = ciphertext[pref:]
cipher = AES.new(aeskey, AES.MODE_CBC, ciphertext2[:16])
text = strip_padding(cipher.decrypt(ciphertext2[16:]))

f = open('hw6.pdf','wb')
f.write(text)
f.close()