from pwn import *

MAZE = [
  "pacmanpacman",
  "cho4$aaagioc",
  "caaarmmmmmmc",
  "cz1pia66600c",
  "cx4p2c00666c",
  "cg8a2pacmanc",
  "ci_cz737373c",
  "co1pacpaconc",
  "c4____pac0ac",
  "czxgioN1234c",
  "c0ZXGIOacpac"
  "pacmanpacman",
]

ROWS = len(MAZE)
COLS = len(MAZE[0])

BLACKLIST = set("pacman")
START = (1, 1)

VISITED = []
SOLUTIONS = []

BIN = "./pacman_p"

def already_visited(pos: tuple) -> bool:
  return pos in VISITED

def in_boundaries(pos: tuple) -> bool:
  return (0 < pos[0] < ROWS) and (0 < pos[1] <  COLS)

def blacklisted(pos: tuple) -> bool:
  return MAZE[pos[0]][pos[1]] in BLACKLIST

def find_direction(pos: tuple, seq: str) -> str:
  """Updates curernt position (pos is both an input and output argument)
  and returns the letter (hjkl controls) corresponding to the right direction
  """
  positions = {
    'k': (pos[0]-1, pos[1]),
    'h': (pos[0], pos[1]-1),
    'j': (pos[0]+1, pos[1]),
    'l': (pos[0], pos[1]+1),
  }

  for direction, new_pos in positions.items():
    if in_boundaries(new_pos) and not already_visited(new_pos) and not blacklisted(new_pos):
      VISITED.append(new_pos)
      find_direction(new_pos, seq+direction)
  
  SOLUTIONS.append(seq)
  return 

def main():
  find_direction(START, "")

  for sol in SOLUTIONS:
    app = process([BIN, sol])
    out = app.clean()
    print(sol, out)
    if b'CCIT' in out:
      print(out)
      return

if __name__ == "__main__": main()