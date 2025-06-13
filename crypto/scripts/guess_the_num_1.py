from pwn import *

HOST: str = "gtn1.challs.cyberchallenge.it"
PORT: int = 9060

def main():
  r = remote(HOST, PORT)
  m = int(r.recvline_startswith("m = ").decode()[4:])
  c = int(r.recvline_startswith("c = ").decode()[4:])
  n = int(r.recvline_startswith("n = ").decode()[4:])
  s = int(r.recvline_startswith("s = ").decode()[4:])
  print(m, c, n, s)
  
  values = [(m*s + c) % n]
  for _ in range(49):
    new_val = (m*values[-1] + c) % n
    values.append(new_val)
  
  values = list(
    map(
      lambda v: str(v).encode(),
      values
    )
  )
  
  r.sendlines(values)
  print(r.recvline())
  r.close()


if __name__ == "__main__": main()