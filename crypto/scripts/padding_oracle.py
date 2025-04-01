#!/bin/python3

from pwn import *
import re

HOST = "padding.challs.cyberchallenge.it"
PORT = 9033
BLOCK_SIZE = 16
FLAG_LEN = 48  # Guessed, not sure, anyway between 32 and 48

PARTIAL_KEY = b''

def bytes_xor(x: bytes, y: bytes):
  return bytes([_x^_y for _x, _y in zip(x, y)])

def bruteforce_byte(conn: remote, current_cipher_block: bytes, pos: int, lb: int) -> int:
  global PARTIAL_KEY

  pad_len = BLOCK_SIZE-pos
  guesses = []

  assert len(PARTIAL_KEY)==pad_len-1, "Wrong partial key len"

  for b in range(2**8):  # All possible byte values
    guessed_block = bytes([0]*(BLOCK_SIZE-pad_len) + [b]) + bytes_xor(PARTIAL_KEY, [pad_len]*len(PARTIAL_KEY))
    guess = bytes([0]*lb) + guessed_block + current_cipher_block
    guesses.append(guess.hex())
  
  # Parallel gusses rock
  conn.sendlines(guesses)
  results = conn.recvlines(numlines=len(guesses))

  for res in results:
    if b'Wow you are so strong at decrypting!' in res:
      b = results.index(res)
      b ^= pad_len
      PARTIAL_KEY = b.to_bytes() + PARTIAL_KEY
      print(".", end='', flush=True)
      return
  
  raise RuntimeError("No valid char found")


def main():
  global PARTIAL_KEY

  c = remote(HOST, PORT)
  token_str = c.recvuntil("What do you want to decrypt").split(b"\n")[1].decode()
  token = bytes.fromhex(token_str)
  cipher = token[16:]
  for chunk_i in range((FLAG_LEN+BLOCK_SIZE-1)//BLOCK_SIZE):
    lb = chunk_i*BLOCK_SIZE
    ub = lb + BLOCK_SIZE

    for i in reversed(range(BLOCK_SIZE)):
      bruteforce_byte(c, cipher[lb:ub], i, lb)
    
    print(bytes_xor(PARTIAL_KEY, token[lb:ub]).decode(), flush=True)
    PARTIAL_KEY = b''

if __name__ == "__main__":
  main()