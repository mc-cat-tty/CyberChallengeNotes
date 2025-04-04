from pwn import *

HOST: str = "danceable.challs.cyberchallenge.it"
PORT: int = 9036

def xor(x: bytes, y: bytes) -> bytes:
  return bytes(_x ^ _y for _x, _y in zip(x, y))

def main():
  plaintxt = bytes(b'a'*16)
  plaintxt_b = plaintxt.hex()
  print(plaintxt, len(plaintxt))
  c = connect(HOST, PORT)
  c.sendlineafter("> ", b"1")
  c.sendlineafter("What do you want to encrypt (in hex)?", plaintxt_b)
  e = bytes.fromhex(c.recvline().decode())
  k = xor(e[:16], plaintxt)
  res = b''
  for i in range(16, len(e), 16):
    res += xor(k, e[i:i+16])
  print(res)


if __name__ == "__main__":
  main()