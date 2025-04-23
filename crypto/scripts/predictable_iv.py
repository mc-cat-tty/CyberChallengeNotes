from pwn import *
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad

HOST: str = "predictable.challs.cyberchallenge.it"
PORT: int = 9034

# 6765745f666c6167


def get_user_token(c: connect, name: str) -> str:
  c.sendlineafter("> ", b"1")
  c.sendlineafter("username: ", name.encode())
  c.recvuntil("token: ")
  return c.recvline().strip().decode()

def get_command_token(c: connect, cmd: str, user_token: str):
  c.sendlineafter("> ", b"2")
  c.sendlineafter("token ", user_token.encode())
  c.sendlineafter("execute? ", cmd.encode())
  c.recvuntil("token: ")
  return c.recvline().strip().decode()

def send_cmd(c: connect, cmd: str):
  c.sendlineafter("> ", b"3")
  c.sendlineafter("do? ", cmd.encode())
  return c.recvline().strip()

def main():
  conn = connect(HOST, PORT)
  cmd = "get_flag".encode().hex()

  name = "bdmin"
  user_token = get_user_token(conn, name)
  user_token = bytes.fromhex(user_token)
  iv, ct = user_token[:16], user_token[16:]
  pt = pad(f"login_token:{name}".encode(), 16)
  partial_key = strxor(iv, pt[:16])
  target_pt = pad("login_token:admin".encode(), 16)
  mangled_iv = strxor(partial_key, target_pt[:16])

  mangled_user_token = mangled_iv+ct

  cmd_token = get_command_token(conn, cmd, mangled_user_token.hex())

  flag = send_cmd(conn, cmd_token)
  print(flag)
  


if __name__ == "__main__":
  main()