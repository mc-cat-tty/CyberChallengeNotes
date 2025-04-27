from pwn import *
import re

HOST = "piecewise.challs.cyberchallenge.it"
PORT = 9110

FLAG_RGX = re.compile(r"CCIT{.*}")
CONVERSION_RGX = re.compile(r"Please send me the number (\d+) as a (\d+)-bit (\w+)-endian integer \((4|8) bytes only, no other stuff\)")

def main():
  flag = ''
  c = connect(HOST, PORT)

  while not FLAG_RGX.match(flag):
    line = c.recvline().decode().strip()

    if res := CONVERSION_RGX.match(line):
      num, bits, endianness, bytes = res.groups()
      num_b = int(num).to_bytes(int(bytes), byteorder=endianness)
      c.send(num_b)
    else:
      c.sendline("")
    
    c.recvuntil("flag: ")
    flag = c.recvline().decode().strip()
    print(".", end="", flush=True)
  
  print("\n"+flag)

if __name__ == "__main__":
  main()