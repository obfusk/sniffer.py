#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : sniffer.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-09-13
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.1
# License     : GPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
r"""
Python (2+3) network sniffer

Examples
========


HTTP GET
--------

>>> import sniffer as S, subprocess, time

>>> c1 = [sys.executable, "sniffer.py"]           # sniffer
>>> c2 = "curl -s obfusk.ch".split()              # curl
>>> p1 = subprocess.Popen(c1, stdout = subprocess.PIPE)
>>> time.sleep(1)
>>> p2 = subprocess.Popen(c2, stdout = subprocess.PIPE)
>>> time.sleep(1)
>>> p1.terminate()
>>> o  = S.b2s(p1.stdout.read()).split('\n\n')    # sniffer output
>>> g  = [ x for x in o if "GET" in x and "obfusk" in x ][0] # the GET
>>> print(g)                                      # doctest: +ELLIPSIS
1... | eth... | eth >> IP >> TCP:
  parsed:
    eth_source_mac      : ...
    eth_dest_mac        : ...
    eth_q_tag           : None
    eth_type            : 2048 (0x800)
    ip_source           : ...
    ip_dest             : ...
    ip_PROTO            : 6 (0x6)
    ip_TTL              : 64 (0x40)
    tcp_source_port     : ...
    tcp_dest_port       : 80 (0x50)
    tcp_seq_n           : ...
    tcp_ack_n           : ...
    tcp_flags           : ack=1 ... syn=0 ...
    tcp_win_sz          : ...
  raw:
    ......47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 ...GET / HTTP/1.1
    0d 0a 48 6f 73 74 3a 20 6f 62 66 75 73 6b 2e 63  ..Host: obfusk.c
    68 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 63  h..User-Agent: c
    75 72 6c 2f .................................... url/...


... TODO ...
"""
                                                                # }}}1

from __future__ import print_function

import argparse, binascii, functools, itertools, os, select, struct
import sys, time
import socket as S

if sys.version_info.major == 2:                                 # {{{1
  def b2s(x):
    """convert bytes to str"""
    return x
  def s2b(x):
    """convert str to bytes"""
    return x
  from itertools import izip_longest
else:
  def b2s(x):
    """convert bytes to str"""
    if isinstance(x, str): return x
    return x.decode("utf8")
  def s2b(x):
    """convert str to bytes"""
    if isinstance(x, bytes): return x
    return x.encode("utf8")
  from functools import reduce
  from itertools import zip_longest
  xrange = range; izip_longest = zip_longest
                                                                # }}}1

__version__         = "0.0.1"

DEFAULT_GROUP_SIZE  = 16

def main(*args):                                                # {{{1
  p = argument_parser(); n = p.parse_args(args)
  if n.test:
    import doctest
    doctest.testmod(verbose = n.verbose)
    return 0
  try:
    sniffer(n.filter, n.bytes)
  except KeyboardInterrupt:
    return 1
  return 0
                                                                # }}}1

def argument_parser():                                          # {{{1
  p = argparse.ArgumentParser(description = "network sniffer")
  p.add_argument("--filter", "-f",
                 help = "expression to filter packets; "
                        "NB: passed to eval() !!!")
  p.add_argument("--bytes", "-b", type = int,
                 help = "bytes per row for hex dump "
                        "(default: %(default)s)")
  p.add_argument("--version", action = "version",
                 version = "%(prog)s {}".format(__version__))
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and not the sniffer)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults(bytes = DEFAULT_GROUP_SIZE)
  return p
                                                                # }}}1

def sniffer(filter_expr = None, group_size = None):             # {{{1
  """sniff & print"""

  sock = S.socket(S.AF_PACKET, S.SOCK_RAW, S.ntohs(0x0003))     # TODO
  try:
    while True:
      rs, _, _ = select.select([sock], [], [])
      if sock in rs:
        data, src = sock.recvfrom(65565)
        parsed_data = unpack_packet(data)
        if not filter_expr or eval_filter_expr(filter_expr,
                                               parsed_data.copy()):
          print_packet(time.time(), data, src, parsed_data,
                       group_size)
  finally:
    sock.close()
                                                                # }}}1

# TODO
def eval_filter_expr(expr, data):
  """eval()s expr with data as locals and minimal globals"""
  b = {}
  for k in "bin chr hex len oct ord".split(): b[k] = __builtins__[k]
  return eval(expr, dict(__builtins__ = b), data)

def unpack_packet(data, proto = "eth"):                         # {{{1
  """unpack & parse packet"""

  p = PARSERS[proto]
  if "identifier" in p and not p["identifier"](data): return None
  p_data = p["parser"](data)
  for cp in p.get("children", []):
    cp_data = unpack_packet(p_data, cp)
    if cp_data is not None: return cp_data
  return p_data
                                                                # }}}1

def print_packet(t, data, src, parsed_data,                     # {{{1
                 group_size = None):
  """(pretty)print packet"""

  if not group_size: group_size = DEFAULT_GROUP_SIZE
  iface, _type, _, _, _mac  = src
  protos                    = " >> ".join(parsed_data["protos"])
  print("{} | {} | {}:".format(t, iface, protos))
  print("  parsed:")
  for k, v in sorted(parsed_data.items(), key = packet_info_sorter):
    if k != "protos" and not any(map(lambda x: k.endswith(x),
                                     HIDDEN_PACKET_INFO)):
      if isinstance(v, dict):
        v = " ".join("{}={}".format(*x) for x in sorted(v.items()))
      elif isinstance(v, int):
        v = "{0} (0x{0:X})".format(v)
      print("    {:20}: {}".format(k,v))
  print("  raw:")
  for x in grouper(data, group_size):
    y = list(ords(itertools.takewhile(lambda c: c is not None, x)))
    print("    ", end = "")
    for c in y: print(b2s("%02x" % c), end = " ")
    print((group_size - len(y)) * "   " + " " + uncontrolled(y))
  print()
                                                                # }}}1

def packet_info_sorter(x):
  """sort packet info by protocol and importance"""
  f     = lambda l, k, d: l.index(k) if k in l else d
  k, _  = x; pre = k[:k.index("_")] if "_" in k else ""
  return (f(SORT_PROTOCOLS, pre , float("inf")),
          f(SORT_FIRST    , k   , float("inf")), k)

def parser(parent_proto, proto, *sort_first):                   # {{{1
  """decorator that adds an unpack_* parser to PARSERS"""

  ppl, pl = [ x.lower() for x in [parent_proto, proto] ]
  def parser_(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
      x = f(*a, **kw)
      if x is not None:
        protos = x.setdefault("protos", [])
        if proto not in protos: protos.append(proto)
      return x
    PARSERS.setdefault(proto, {})["parser"] = wrapper
    PARSERS.setdefault(parent_proto, {}) \
      .setdefault("children", set()).add(proto)
    SORT_FIRST.extend([ pl + "_" + x  for y in sort_first
                                      for x in y.split() ])
    if ppl not in SORT_PROTOCOLS: SORT_PROTOCOLS.insert(0, ppl)
    if pl  not in SORT_PROTOCOLS: SORT_PROTOCOLS.append(pl)
    return wrapper
  return parser_
                                                                # }}}1

def identifier(parent_proto, proto):
  """decorator that adds an is_* identifier to PARSERS"""
  def identifier_(f):
    PARSERS.setdefault(proto, {})["identifier"] = f
    return f
  return identifier_

HIDDEN_PACKET_INFO    = "_data _offset _opts _pkt".split()
PARSERS               = {}
SORT_FIRST            = []
SORT_PROTOCOLS        = []

# === ICMP ======================================================== #
# type (8)       | code (8)       | checksum (16)                   #
# ================================================================= #

# === ICMP_ECHO & ICMP_ECHOREPLY ================================== #
# identifier (16)                 | sequence number (16)            #
#                           ... data ...                            #
# ================================================================= #

# === ICMP_DEST_UNREACH =========================================== #
# unused (16)                     | next-hop MTU (16)               #
#       IP header + first 8 bytes of original datagram's data       #
# ================================================================= #

# === ICMP_TIME_EXCEEDED ========================================== #
#                             unused (32)                           #
#       IP header + first 8 bytes of original datagram's data       #
# ================================================================= #

def is_icmp_echo(icmp_data):
  """is ICMP_ECHO?"""
  return  dict(icmp_TYPE = icmp_data["icmp_TYPE"],
               icmp_CODE = icmp_data["icmp_CODE"]) \
            == ICMP_ECHO

def is_icmp_echoreply(icmp_data):
  """is ICMP_ECHOREPLY?"""
  return  dict(icmp_TYPE = icmp_data["icmp_TYPE"],
               icmp_CODE = icmp_data["icmp_CODE"]) \
            == ICMP_ECHOREPLY

def is_icmp_exc_ttl(icmp_data):
  """is ICMP_EXC_TTL?"""
  return  is_icmp_time_exceeded(icmp_data) and \
            icmp_data["icmp_CODE"] == ICMP_EXC_TTL

def is_icmp_time_exceeded(icmp_data):
  """is ICMP_TIME_EXCEEDED?"""
  return icmp_data["icmp_TYPE"] == ICMP_TIME_EXCEEDED

def is_icmp_port_unreach(icmp_data):
  """is ICMP_PORT_UNREACH?"""
  return  is_icmp_dest_unreach(icmp_data) and \
            icmp_data["icmp_CODE"] == ICMP_PORT_UNREACH

def is_icmp_dest_unreach(icmp_data):
  """is ICMP_DEST_UNREACH?"""
  return icmp_data["icmp_TYPE"] == ICMP_DEST_UNREACH

@parser("IP", "ICMP", "TYPE CODE")
def unpack_icmp(pkt):                                           # {{{1
  """unpack ICMP packet from IP packet"""

  d = unpack_ip(pkt); pkt = d["ip_pkt"]
  if not is_icmp(d): return None
  o = d["ip_data_offset"]; icmp_hdr, icmp_data = pkt[o:o+8], pkt[o+8:]
  TYPE, code, _, ID, seq = struct.unpack("!BBHHH", icmp_hdr)
  d.update(icmp_TYPE  = TYPE, icmp_CODE = code, icmp_ID = ID,
           icmp_seq   = seq , icmp_data = icmp_data)
  return d
                                                                # }}}1

def is_icmp(ip_data):
  """is ICMP packet?"""
  return ip_data is not None and ip_data["ip_PROTO"] == S.IPPROTO_ICMP

# === UDP ========================================================= #
# source port (16)                | destination port (16)           #
# length (16)                     | checksum (16)                   #
#                           ... data ...                            #
# ================================================================= #

@parser("IP", "UDP", "source_port dest_port")
def unpack_udp(pkt):                                            # {{{1
  """unpack UDP packet from IP packet"""

  d = unpack_ip(pkt); pkt = d["ip_pkt"]
  if not is_udp(d): return None
  o = d["ip_data_offset"]; udp_hdr, udp_data = pkt[o:o+8], pkt[o+8:]
  s_port, d_port, _, _ = struct.unpack("!HHHH", udp_hdr)
  d.update(udp_source_port  = s_port, udp_dest_port = d_port,
           udp_data         = udp_data)
  return d
                                                                # }}}1

def is_udp(ip_data):
  """is UDP packet?"""
  return ip_data is not None and ip_data["ip_PROTO"] == S.IPPROTO_UDP

# === TCP ========================================================= #
# source port (16)                | destination port (16)           #
#                        sequence number (16)                       #
#                  acknowledgment number (16) (if ACK)              #
# data offset + flags (16)        | window Size (16)                #
# checksum (16)                   | urgent pointer (16) (if URG)    #
#                          ... options ...                          #
#                           ... data ...                            #
# ================================================================= #

# === TCP data offset + flags ===================================== #
# |      0|      1|      2|      3|      4|      5|      6|      7| #
# |        data offset (4)        | reserved (3) = 000    | NS    | #
# |      8|      9|     10|     11|     12|     13|     14|     15| #
# | CWR   | ECE   | URG   | ACK   | PSH   | RST   | SYN   | FIN   | #
# ================================================================= #

@parser("IP", "TCP", "source_port dest_port seq_n ack_n")
def unpack_tcp(pkt):                                            # {{{1
                                                                # {{{2
  r"""
  unpack TCP packet from IP packet

  >>> import binascii as B, sniffer as S
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> p = S.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089, 0x1f9fb402, d, 29200, psh = 1, ack = 1)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = S.unpack_tcp(i + p)
  >>> " ".join(str(x["tcp_"+k]) for k in "source_port dest_port seq_n ack_n offset win_sz".split())
  '54474 80 24584329 530560002 5 29200'
  >>> S.b2s(x["tcp_opts"])
  ''
  >>> S.b2s(x["tcp_data"])
  'GET / HTTP/1.0\r\n'
  >>> " ".join("{}={}".format(k,v) for k, v in sorted(x["tcp_flags"].items()))
  'ack=1 cwr=0 ece=0 fin=0 ns=0 psh=1 rst=0 syn=0 urg=0'
  """                                                           # }}}2

  d = unpack_ip(pkt); pkt = d["ip_pkt"]
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+20]
  s_port, d_port, seq_n, ack_n, offset_and_flags, win_sz, _, _ = \
    struct.unpack("!HHIIHHHH", tcp_hdr)
  offset = offset_and_flags >> 12; flags = {}
  if not 5 <= offset <= 15: return None
  for i, flag in enumerate(reversed(TCP_FLAGS)):
    flags[flag.lower()] = (offset_and_flags >> i) & 0b1
  tcp_opts, tcp_data = pkt[o+20:o+offset*4], pkt[o+offset*4:]
  d.update(tcp_source_port  = s_port  , tcp_dest_port = d_port,
           tcp_seq_n        = seq_n   , tcp_ack_n     = ack_n,
           tcp_offset       = offset  , tcp_flags     = flags,
           tcp_win_sz       = win_sz  , tcp_opts      = tcp_opts,
           tcp_data         = tcp_data)
  return d
                                                                # }}}1

def unpack_tcp_first8(pkt):                                     # {{{1

  """
  unpack first 8 bytes of TCP packet from IP packet (from ICMP packet)

  >>> import binascii as B, sniffer as S
  >>> p = S.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = S.unpack_tcp_first8(i + p)
  >>> " ".join(str(x["tcp_"+k]) for k in "source_port dest_port seq_n".split())
  '54474 80 24584329'
  """

  d = unpack_ip(pkt); pkt = d["ip_pkt"]
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+8]
  s_port, d_port, seq_n = struct.unpack("!HHI", tcp_hdr)
  d.update(tcp_source_port = s_port, tcp_dest_port = d_port,
           tcp_seq_n = seq_n)
  return d
                                                                # }}}1

def is_tcp_synack(tcp_data):
  """is TCP SYN+ACK?"""
  return tcp_data["tcp_flags"]["syn"] == 1 and \
         tcp_data["tcp_flags"]["ack"] == 1

def is_tcp_rst(tcp_data):
  """is TCP RST?"""
  return tcp_data["tcp_flags"]["rst"] == 1

def is_tcp(ip_data):
  """is TCP packet?"""
  return ip_data is not None and ip_data["ip_PROTO"] == S.IPPROTO_TCP

def tcp_packet(source, dest, seq_n, ack_n = 0, data = b"",      # {{{1
               win_sz = 0, **flags):
  r"""
  create TCP packet

  >>> import binascii as B, sniffer as S
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> p = S.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089, 0x1f9fb402, d, 29200, psh = 1, ack = 1)
  >>> S.b2s(B.hexlify(p))
  'd4ca0050017720891f9fb402501872105f700000474554202f20485454502f312e300d0a'
  """

  s, s_p = source; d, d_p = dest
  args = lambda c = 0: [s_p, d_p, seq_n, ack_n, c, win_sz]
  csum = tcp_checksum(source, dest, tcp_header(*args(), **flags), data)
  return tcp_header(*args(csum), **flags) + data
                                                                # }}}1

# TODO
def tcp_header(s_port, d_port, seq_n, ack_n, csum,              # {{{1
               win_sz = 0, **flags):
  """create TCP header"""

  offset = 5; urg_ptr = 0;    # ignore TCP options and URG -- TODO
  offset_and_flags = offset << 12
  for i, flag in enumerate(reversed(TCP_FLAGS)):
    b = 1 if flags.get(flag.lower(), 0) else 0
    offset_and_flags |= b << i
  return struct.pack("!HHIIHHHH", s_port, d_port, seq_n, ack_n,
                     offset_and_flags, win_sz, csum, urg_ptr)
                                                                # }}}1

def tcp_checksum(source, dest, header, data):                   # {{{1
  r"""
  TCP checksum as per RFC 793

  >>> import sniffer as S
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> h = S.tcp_header(54474, 80, 0x01772089, 0x1f9fb402, 0, 29200, psh = 1, ack = 1)
  >>> hex(S.tcp_checksum(("10.0.2.15", 54474), ("93.184.216.34", 80), h, d))
  '0x5f70'
  """

  s, s_p = source; d, d_p = dest; l = len(header); p = S.IPPROTO_TCP
  return internet_checksum(pseudo_ipv4_header(s, d, l + len(data), p)
                           + header + data)
                                                                # }}}1

TCP_FLAGS = "NS CWR ECE URG ACK PSH RST SYN FIN".split()

# === UDP/TCP Pseudo IPv4 Header ================================== #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# zeroes (8)     | protocol (8)   | UDP length (16)                 #
# ================================================================= #

def pseudo_ipv4_header(s_ip, d_ip, length, proto):              # {{{1
  """
  UDP/TCP pseudo IPv4 header

  >>> import binascii as B, socket, sniffer as S
  >>> u = socket.IPPROTO_UDP
  >>> h = S.pseudo_ipv4_header("10.0.2.15", "10.0.2.2", 32 + 8, u)
  >>> S.b2s(B.hexlify(h))
  '0a00020f0a00020200110028'
  """

  return  S.inet_aton(s_ip) + S.inet_aton(d_ip) + \
            struct.pack("!BBH", 0, proto, length)
                                                                # }}}1

# === IPv4 ======================================================== #
# version | IHL  | DSCP + ECN (8) | length (16)                     #
# identification (16)             | flags + offset (16)             #
# TTL (8)        | protocol (8)   | checksum (16)                   #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# ================================================================= #

# TODO
@parser("eth", "IP", "source dest")
def unpack_ip(pkt):                                             # {{{1
  """unpack IP packet"""

  d = {}
  if isinstance(pkt, dict):
    if "IP" in pkt["protos"]: return pkt
    else: d, pkt = pkt, pkt["eth_data"]
  ihl, ttl, proto = b2i(pkt[0]) & 0xf, b2i(pkt[8]), b2i(pkt[9])
  if ihl != 5: return None    # ignore IPv4 w/ options -- TODO
  s_ip  , d_ip    = pkt[12:16], pkt[16:20]
  s_ip_a, d_ip_a  = map(S.inet_ntoa, [s_ip, d_ip])
  d.update (ip_TTL          = ttl   , ip_PROTO  = proto,
            ip_source       = s_ip_a, ip_dest   = d_ip_a,
            ip_data_offset  = 4*ihl , ip_pkt    = pkt)
  return d
                                                                # }}}1

@identifier("eth", "IP")
def is_ip(eth_data):
  """is IP packet?"""
  return eth_data is not None and eth_data["eth_type"] == ETH_IP

def internet_checksum(data):                                    # {{{1
  """
  calculate internet checksum as per RFC 1071

  >>> import binascii as B, sniffer as S
  >>> x = B.unhexlify(b"0001f203f4f5f6f7")
  >>> c = S.internet_checksum(x)
  >>> S.b2s(B.hexlify(S.i2b(c)))
  '220d'
  """

  csum = 0; count = len(data); i = 0;
  while count > 1:
    csum += b2i(data[i:i+2])
    csum &= 0xffffffff
    count -= 2; i += 2
  if count > 0:
    csum += b2i(data[i])
    csum &= 0xffffffff
  while csum >> 16:
    csum = (csum & 0xffff) + (csum >> 16)
  return ~csum & 0xffff
                                                                # }}}1

# === Layer 2 Ethernet Frame ====================================== #
#                       MAC destination (6o)                        #
#                          MAC source (6o)                          #
# 802.1Q tag (optional) (4o)            | Ethertype (2o)            #
#                         Payload (46(42)-1500o)                    #
#                               ...                                 #
# ================================================================= #

@parser("__root__", "eth", "source_mac dest_mac")
def unpack_eth(data):                                           # {{{1
  """unpack Ethernet packet"""

  dest_mac      = struct.unpack("!BBBBBB", data[0:6])
  source_mac    = struct.unpack("!BBBBBB", data[6:12])
  eth_type,     = struct.unpack("!H",      data[12:14])
  if eth_type == ETH_QTAG:
    q_tag,      = struct.unpack("!I",      data[12:16])
    eth_type,   = struct.unpack("!H",      data[16:18])
    payload     = data[18:]
  else:
    q_tag       = None
    payload     = data[14:]
  f = lambda x, y: x << 8 | y
  d_mac, s_mac  = [ b2s(binascii.hexlify(i2b(reduce(f, x, 0))))
                    for x in [dest_mac, source_mac] ]
  return dict(eth_dest_mac  = d_mac   , eth_source_mac  = s_mac,
              eth_type      = eth_type, eth_q_tag       = q_tag,
              eth_data      = payload)
                                                                # }}}1

ETH_QTAG              = 0x8100
ETH_IP                = 0x0800

ICMP_ECHOREPLY        = dict(icmp_TYPE = 0, icmp_CODE = 0)
ICMP_ECHO             = dict(icmp_TYPE = 8, icmp_CODE = 0)

ICMP_TIME_EXCEEDED    = 11

ICMP_EXC_TTL          = 0
ICMP_EXC_FRAGTIME     = 1

ICMP_TIME_EXCEEDED_CODES = {
  ICMP_EXC_TTL        : "Time to live exceeded",
  ICMP_EXC_FRAGTIME   : "Frag reassembly time exceeded",
}

ICMP_DEST_UNREACH     = 3

ICMP_NET_UNREACH      = 0                                       # {{{1
ICMP_HOST_UNREACH     = 1
ICMP_PROT_UNREACH     = 2
ICMP_PORT_UNREACH     = 3
ICMP_FRAG_NEEDED      = 4
ICMP_SR_FAILED        = 5
ICMP_NET_UNKNOWN      = 6
ICMP_HOST_UNKNOWN     = 7
ICMP_HOST_ISOLATED    = 8
ICMP_NET_ANO          = 9
ICMP_HOST_ANO         = 10
ICMP_NET_UNR_TOS      = 11
ICMP_HOST_UNR_TOS     = 12
ICMP_PKT_FILTERED     = 13
ICMP_PREC_VIOLATION   = 14
ICMP_PREC_CUTOFF      = 15                                      # }}}1

ICMP_DEST_UNREACHABLE_CODES = {                                 # {{{1
  ICMP_NET_UNREACH    : "Destination Net Unreachable",
  ICMP_HOST_UNREACH   : "Destination Host Unreachable",
  ICMP_PROT_UNREACH   : "Destination Protocol Unreachable",
  ICMP_PORT_UNREACH   : "Destination Port Unreachable",
  ICMP_FRAG_NEEDED    : "Frag needed and DF set",   # mtu?
  ICMP_SR_FAILED      : "Source Route Failed",
  ICMP_NET_UNKNOWN    : "Destination Net Unknown",
  ICMP_HOST_UNKNOWN   : "Destination Host Unknown",
  ICMP_HOST_ISOLATED  : "Source Host Isolated",
  ICMP_NET_ANO        : "Destination Net Prohibited",
  ICMP_HOST_ANO       : "Destination Host Prohibited",
  ICMP_NET_UNR_TOS    : "Destination Net Unreachable for Type of Service",
  ICMP_HOST_UNR_TOS   : "Destination Host Unreachable for Type of Service",
  ICMP_PKT_FILTERED   : "Packet filtered",
  ICMP_PREC_VIOLATION : "Precedence Violation",
  ICMP_PREC_CUTOFF    : "Precedence Cutoff",
}                                                               # }}}1

# TODO: more!
ICMP_ERROR_SYMBOLS = {
  ICMP_NET_UNREACH    : "N",
  ICMP_HOST_UNREACH   : "H",
  ICMP_PROT_UNREACH   : "P",
}

def ords(s):
  """string (or sequence of chars/ints) as list of ints"""
  return map(lambda c: c if isinstance(c, int) else ord(c), s)

def uncontrolled(s):                                            # {{{1
  r"""
  string w/ control chars as dots

  >>> import sniffer as S
  >>> S.uncontrolled(b"\x00 \n\tfoo\rbar\b")
  '. ..foo.bar.'
  """

  return "".join(chr(c) if 31 < c < 127 else '.' for c in ords(s))
                                                                # }}}1

# from https://docs.python.org/2/library/itertools.html
def grouper(it, n, fill = None):
  """iterate in groups of n"""
  return izip_longest(fillvalue = fill, *([iter(it)]*n))

def b2i(x):
  """convert bytes to integer"""
  if isinstance(x, int): return x
  return int(binascii.hexlify(x), 16)

def i2b(x, n = 1):
  """convert integer to bytes of length (at least) n"""
  if isinstance(x, bytes): return x
  return binascii.unhexlify(s2b("%0*x" % (n*2,x)))

if __name__ == "__main__":
  sys.exit(main(*sys.argv[1:]))

# vim: set tw=70 sw=2 sts=2 et fdm=marker :
