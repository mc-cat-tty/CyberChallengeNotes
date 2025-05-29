from pwn import *
from string import ascii_letters, digits, punctuation

HOST = "10.42.0.2"
PORT = 38082

ALPHABET = digits + ascii_letters + punctuation

def main():
  app = remote(HOST, PORT)
  flag = ''
  prev_rev = 0

  try:
    while True:
      print('.', end='', flush=True)

      for c in ALPHABET:
        partial_flag = flag + c
        app.sendlineafter(b"flag: ", partial_flag.encode())
        rev_score = int(app.recvline().decode().split("=")[1].strip())

        if rev_score > prev_rev:
          prev_rev = rev_score
          flag = partial_flag
          break
        
  except EOFError:
    print(flag)
    i = int(flag, 2)
    flag_str = i.to_bytes(i.bit_length()//8+1).decode()
    print(flag_str)

if __name__ == "__main__": main()