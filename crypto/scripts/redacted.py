#!/bin/python3

from Crypto.Cipher import AES
import binascii, sys

BLOCK_SIZE = 16

def xor(x: bytes, y: bytes):
  return bytes([_x ^ _y for _x, _y in zip(x, y)])

sure_key = "yn9RB3Lr43xJK2".encode()
iv  = "████████████████".encode()
plain = "AES with CBC is very unbreakable".encode()
cipher = bytes.fromhex("c500000000000000000000000000d49e78c670cb67a9e5773d696dc96b78c4e0")

cipher_1 = cipher[:BLOCK_SIZE]
cipher_2 = cipher[BLOCK_SIZE:BLOCK_SIZE*2]

plain_1 = plain[:BLOCK_SIZE]
plain_2 = plain[BLOCK_SIZE:BLOCK_SIZE*2]

keys = [bytes((b1, b2)) for b1 in range(2**8) for b2 in range(2**8)]

for k_guess in keys:
  aes = AES.new(sure_key+k_guess, AES.MODE_CBC, cipher_1)
  plain_2_guess = aes.decrypt(cipher_2)
  if plain_2_guess[0] == plain_2[0] and plain_2_guess[-2] == plain_2[-2]:  # Given that they are the only known chars
    key = sure_key+k_guess  # Key found
    break

aes = AES.new(key, AES.MODE_ECB)
partial_pad_2 = aes.decrypt(cipher_2)
cipher_1 = xor(partial_pad_2, plain_2)

partial_pad_1 = aes.decrypt(cipher_1)
print(xor(plain_1, partial_pad_1))
