from Crypto.Hash import SHA3_384
from string import ascii_letters, punctuation, digits

def main():
  inv = {
    SHA3_384.new(c.encode()).digest()[:2].hex(): c
    for c in ascii_letters+punctuation+digits
  }
  flag = ""
  print(inv)

  with open('out.txt', 'rb') as rf:
    enc_flag = rf.read().strip()
    for i in range(0, len(enc_flag), 4):
      try: flag += inv[enc_flag[i:i+4].decode()]
      except: flag += '?'
    
  
  print(flag)


if __name__ == "__main__":
  main()