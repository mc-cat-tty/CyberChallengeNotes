#!/usr/bin/python3
# Meet In The Middle Attack

import string
import base64
from itertools import product
from string import ascii_lowercase

def encrypt(clear, key):
  enc = []
  for i in range(len(clear)):
    key_c = key[i % len(key)]
    enc_c = chr((ord(clear[i]) + ord(key_c)) % 128)
    enc.append(enc_c)
  return str(base64.urlsafe_b64encode("".join(enc).encode('ascii')), 'ascii')

def decrypt(enc, key):
    dec = []
    enc = str(base64.urlsafe_b64decode(enc.encode('ascii')), 'ascii')
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((128 + ord(enc[i]) - ord(key_c)) % 128)
        dec.append(dec_c)
    return "".join(dec)
 


m = "See you later in the city center"
c = "QSldSTQ7HkpIJj9cQBY3VUhbQ01HXD9VRBVYSkE6UWRQS0NHRVE3VUQrTDE="

all_keys = [*product(*(ascii_lowercase,)*4)]
d_to_k = {encrypt(m, ''.join(k)): k for k in all_keys}

for k in all_keys:
  d = decrypt(c, ''.join(k))
  if d in d_to_k:
    print(d_to_k[d], k)
    KEY = ''.join((*d_to_k[d], *k))

k1 = KEY[0:4]
k2 = KEY[4:8]
print("flag: CCIT{%s}" % KEY)

m = "See you later in the city center"
d = encrypt(m, k1)
c = encrypt(d, k2)

print("Message:", m)
print("Ciphertext:", c)
