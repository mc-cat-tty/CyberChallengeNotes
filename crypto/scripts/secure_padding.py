#!/bin/python3

from socket import *
import re
from string import printable

HOST = "padding.challs.cyberchallenge.it"
PORT = 9030
SEP = b'\n'
BLOCK_SIZE = 16
KEY_LEN = BLOCK_SIZE*2

PASS_PATTERN = re.compile(':\s(\w+)\s')
KEY_ALPHABET = printable

def recv_at_least_one_line(sock: socket):
  data = b''
  while SEP not in data:
    new_data = sock.recv(128)
    data += new_data
  return data

def get_enc_pass(plain_pass, sock: socket, data=b''):
  sock.sendall(plain_pass.encode()+b'\n')

  while new_data:=recv_at_least_one_line(sock):
    # print(*new_data.split(SEP), sep=SEP.decode())
    data += new_data
    
    pass_search = PASS_PATTERN.search(data.decode())
    if pass_search:
      enc_pass = bytes.fromhex(pass_search.group(1))
      data = data[pass_search.span(1)[1]:]
      return enc_pass

def chunk_pass(p: bytes):
  return [p[i:i+BLOCK_SIZE] for i in range(0, len(p), BLOCK_SIZE)]

def main():
  s = socket(AF_INET, SOCK_STREAM)
  s.connect((HOST, PORT))

  padding_len = KEY_LEN
  mirrored_block = 'a'*BLOCK_SIZE
  flag = ''

  while padding_len > 0:
    padding_len -= 1
    mirrored_block = mirrored_block[1:]
    # print(padding_len, mirrored_block)

    for c in KEY_ALPHABET:
      p = mirrored_block+c + 'a'*padding_len
      ep = get_enc_pass(p, s)
      cp = chunk_pass(ep)
      if cp[0] == cp[2]:
        flag += c
        mirrored_block += c
        break
  
    print(flag)

  s.close()

if __name__ == "__main__":
  main()
