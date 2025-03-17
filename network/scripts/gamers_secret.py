"""
Usage: python3 gamers_secret.py out.txt
"""

from matplotlib import pyplot as m
from matplotlib import collections as mc
import json, re
from sys import argv

FILENAME = argv[1]

class MalformedLine(Exception):
  def __init__(self):
    super().__init__(f"Malformed line, try it and remove it")

def websocket_payload_filter_factory(cmd: str):
  return lambda websocket_payloads: filter(lambda payload: cmd in payload, websocket_payloads)

def extract_segments_from_draw_cmds(draw_cmds):
  return [
    (segment[3:5], segment[5:7]) for draw_cmd in draw_cmds for segment in draw_cmd[1] 
  ]


def parse_payload(websocket_payloads):
  return map(
    lambda payload: json.loads(re.search(r"\[.*\]", payload).group()),
    websocket_payloads
  )


draw_cmds_filter = websocket_payload_filter_factory("drawCommands")

with open(FILENAME, "r") as file:
  try:
    lines = extract_segments_from_draw_cmds(
      parse_payload(
        draw_cmds_filter(
        file.readlines()
        )
      )
    )
  except json.decoder.JSONDecodeError as e:
    raise MalformedLine()

lc = mc.LineCollection(lines)
m.gca().add_collection(lc)
m.gca().autoscale()
m.gca().yaxis.set_inverted(True)
m.show()