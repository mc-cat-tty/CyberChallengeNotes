BIN: str = "./cha-cha"
OFFSET: int = 40
TARGET_ADDR_LOWER_BYTES: int = 0x083a

ENCRYPTED_FLAG = b"C\xa1R\x8a\xb7\x1b\xa1h_\xb1\x1a\x86\xf5\x93\xcc\xc2l\xaf\xdc\xad\x03{\xd1\xd0_\x1cX'\x13\x13\xd8h7\xbe\x00"

def rol(byte, shift):
  shift &= 0x7
  return ((byte << shift) | (byte >> (8 - shift))) & 0xFF

def decrypt_string(encrypted: bytes) -> bytes:
  decrypted = bytearray()
  for offset, byte in enumerate(encrypted):
    if byte == 0:
      break
    decrypted.append(rol(byte, offset & 0x7))
  return bytes(decrypted)

def main():
  flag = decrypt_string(ENCRYPTED_FLAG)
  print(flag)

if __name__ == "__main__":
  main()