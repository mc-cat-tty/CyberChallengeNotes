"""
This script will extract and reconstruct four video streams.
Among the four streams, the one which contains the flag is out_1391104.mp4.

However, right after the extraction the file is not ready to be opened and interpreted by an mp4 decoder;
by inspecting the file with an hex editor is clear that the video has't been played entirely and sequentially.

Instead, the user jumped on the timebar of the video player. This leaves huge zero-blocks in the final stream.

To fix it run: ffmpeg -i out_1391104.mp4 -vcodec copy -acodec copy output_video_file.mp4

Enjoy :)
"""

import re
from dpkt import *
from sys import argv
from contextlib import suppress
from collections import defaultdict

def main():
  if len(argv) < 2:
    print("Pass pcap file capture as first arument")
    return 1
  
  video_names = set()
  tcp_streams = defaultdict(bytes)
  http_responses = list()

  with open(argv[1], 'rb') as f:
    for ts, pkt in pcap.Reader(f):
      eth_pdu = ethernet.Ethernet(pkt)
      
      if not isinstance(eth_pdu.data, ip.IP): continue
      ip_pdu = eth_pdu.data
      
      if not isinstance(ip_pdu.data, tcp.TCP): continue
      tcp_pdu = ip_pdu.data

      key = (ip_pdu.src, ip_pdu.dst, tcp_pdu.sport, tcp_pdu.dport)
      tcp_streams[key] += tcp_pdu.data
      
      with suppress(NeedData | UnpackError):
        http_pdu_res = http.Response(tcp_streams[key])
        http_responses.append((http_pdu_res, tcp_pdu))
        tcp_streams[key] = bytes()

      with suppress(NeedData | UnpackError):
        http_pdu_req = http.Request(tcp_pdu.data)
        if 'video' in http_pdu_req.uri:
          video_names.add(http_pdu_req.uri)
      
  print(f"{video_names=}")

  outs = defaultdict(bytearray)

  for http_r, tcp_r in http_responses:
    if http_r.status == '206':
      range = http_r.headers['content-range']
      matched_range = re.match(r'bytes (\d+)-(\d+)/(\d+)', range)
      start_b, end_b, length = matched_range.groups()
      start_b, end_b, length = int(start_b), int(end_b), int(length)
      outs[length] = bytearray(length)
  
  for http_r, tcp_r in http_responses:
    if http_r.status == '206':
      range = http_r.headers['content-range']
      matched_range = re.match(r'bytes (\d+)-(\d+)/(\d+)', range)
      start_b, end_b, length = matched_range.groups()
      start_b, end_b, length = int(start_b), int(end_b), int(length)
      print(range, end_b-start_b, len(http_r.body))
      outs[length][start_b:end_b] = http_r.body
      print("Len - seq", length, tcp_r.seq)
    
  for size, content in outs.items():
    print(len(content), size)
    with open(f"out_{size}.mp4", "wb") as o: o.write(content)



if __name__ == "__main__": main()
