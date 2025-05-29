from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

HOST: str = "10.42.0.2"
PORT: int = 38083

INITIAL_NONCE = b'000000000000000000000000000001'
REPEATS_AFTER = 0x100
FLAG_BLOCKS_NUM = 4
COUNTER = 0


def main():
  app = remote(HOST, PORT)
  app.sendlineafter(b'> ', '3')
  app.sendlineafter(b'> ', INITIAL_NONCE)

  keystreams = []

  for i in range(REPEATS_AFTER):
    app.sendlineafter(b'> ', '1')
    
    if i < FLAG_BLOCKS_NUM:  # First three blocks used to predict next ones (flag ones)
      line = app.recvline()
      line = line.strip().decode().split(' ')
      plaintxt, ciphertxt = bytes.fromhex(line[0]), bytes.fromhex(line[1])
      print(plaintxt, ciphertxt)
      keystreams.append(strxor(plaintxt, ciphertxt))
  

  app.sendlineafter(b'> ', '3')
  app.sendlineafter(b'> ', INITIAL_NONCE[:-2])

  app.sendlineafter(b'> ', '2')
  flag_enc = bytes.fromhex(app.recvline().decode().strip())

  print(f"Collected {len(keystreams)} blocks")
  keystream = b''.join(keystreams)

  flag = strxor(
    keystream[:len(flag_enc)],
    flag_enc
  )   
  print(flag)


if __name__ == "__main__":
  main()