from pwn import *
from sage.all import *
from hashlib import sha1
from Crypto.Util.number import bytes_to_long, inverse

HOST: str = "lineardsa.challs.cyberchallenge.it"
PORT: int = 9067

k  = 54
q = 0x926c99d24bd4d5b47adb75bd9933de8be5932f4b
p = 0x80000000000001cda6f403d8a752a4e7976173ebfcd2acf69a29f4bada1ca3178b56131c2c1f00cf7875a2e7c497b10fea66b26436e40b7b73952081319e26603810a558f871d6d256fddbec5933b77fa7d1d0d75267dcae1f24ea7cc57b3a30f8ea09310772440f016c13e08b56b1196a687d6a5e5de864068f3fd936a361c5


def sign(m):
  global p, q, k, x, g
  H = bytes_to_long(sha1(m).digest())
  r = pow(g, k, p) % q
  s = (inverse(k, q)*(H + x*r)) % q
  assert(s != 0)
  return hex(r)[2:].rjust(40,'0') + hex(s)[2:].rjust(40,'0')


def main():
  global g, y, x
  c = connect(HOST, PORT)
  c.sendlineafter(b">", b"3")
  g, y = c.recvuntil(b")").split(b',')
  g, y = g.strip(b"() "), y.strip(b"() ")
  g, y = int(g), int(y)

  msg = b"ciao"

  c.sendlineafter(b"> ", b"1")
  c.sendlineafter(b": ", msg)
  sign1 = c.recvline_regex(r"[\d\w]{80}").strip()
  r1, s1 = int(sign1[:40], 16), int(sign1[40:], 16)

  c.sendlineafter(b"> ", b"1")
  c.sendlineafter(b": ", msg)
  sign2 = c.recvline_regex(r"[\d\w]{80}").strip()
  r2, s2 = int(sign2[:40], 16), int(sign2[40:], 16)
  
  # s1 * k - r1 * x == h(m) 
  # s2 * k - x * r2 == h(m) - s2 * 1337

  hm = bytes_to_long(sha1(msg).digest())

  R = Integers(q)
  A = Matrix(R, [[s1, -r1], [s2, -r2]])
  b = vector(R, [hm, hm-s2*1337])
  k, x = A.solve_right(b)

  flag_msg = b"gimme the flag"

  c.sendlineafter(b"> ", b"2")
  c.sendlineafter(b": ", flag_msg)
  c.sendlineafter(b": ", sign(flag_msg))

  print(c.recvline())

if __name__ == "__main__":
  main()