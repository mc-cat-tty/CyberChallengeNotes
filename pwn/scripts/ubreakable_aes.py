from sys import argv

def rol(char: int, times: int):
  for _ in range(times):
    char = (char >> 7) | ((char << 1) & 0xff)
  return char

def main():
  if len(argv) < 2: print("First argument is cyphertext")

  with open(argv[1], 'rb') as f:
    flag = bytearray(f.read())
  
  for i in range(len(flag)):
    flag[i] = rol(flag[i], i+1)
  
  print(flag.decode())

if __name__ == "__main__":
  main()