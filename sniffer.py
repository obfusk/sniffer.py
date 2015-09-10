#!/usr/bin/python

# --                                                            ; {{{1
#
# File        : sniffer.py
# Maintainer  : Felix C. Stegerman <flx@obfusk.net>
# Date        : 2015-09-10
#
# Copyright   : Copyright (C) 2015  Felix C. Stegerman
# Version     : v0.0.1
# License     : LGPLv3+
#
# --                                                            ; }}}1

                                                                # {{{1
"""
Python (2+3) network sniffer

Examples
--------

>>> import sniffer as S

... TODO ...
"""
                                                                # }}}1

from __future__ import print_function

import argparse, binascii, os, select, struct, sys, time
import socket as S

if sys.version_info.major == 2:                                 # {{{1
  def b2s(x):
    """convert bytes to str"""
    return x
  def s2b(x):
    """convert str to bytes"""
    return x
else:
  def b2s(x):
    """convert bytes to str"""
    if isinstance(x, str): return x
    return x.decode("utf8")
  def s2b(x):
    """convert str to bytes"""
    if isinstance(x, bytes): return x
    return x.encode("utf8")
  xrange = range
  from functools import reduce
                                                                # }}}1

__version__       = "0.0.1"


def main(*args):                                                # {{{1
  p = argument_parser(); n = p.parse_args(args)
  if n.test:
    import doctest
    doctest.testmod(verbose = n.verbose)
    return 0
  try:
    sniffer()
  except KeyboardInterrupt:
    return 1
  return 0
                                                                # }}}1

def argument_parser():                                          # {{{1
  p = argparse.ArgumentParser(description = "network sniffer")
  p.add_argument("--version", action = "version",
                 version = "%(prog)s {}".format(__version__))
  p.add_argument("--test", action = "store_true",
                 help = "run tests (and not the sniffer)")
  p.add_argument("--verbose", "-v", action = "store_true",
                 help = "run tests verbosely")
  p.set_defaults(test = False, verbose = False)
  return p
                                                                # }}}1

# TODO
def sniffer():                                                  # {{{1
  """sniff & print"""

  sock = S.socket(S.AF_PACKET, S.SOCK_RAW, S.ntohs(0x0003))     # TODO
  try:
    while True:
      rs, _, _ = select.select([sock], [], [])
      if sock in rs:
        data, src = sock.recvfrom(65565)
        eth       = unpack_eth(data)
        tm        = time.time()
        if is_ip(eth):
          for f, t in [(unpack_icmp,  "ICMP"),
                       (unpack_udp,   "UDP"),
                       (unpack_tcp,   "TCP")]:
            pkt = f(eth["eth_data"])
            if pkt is not None: break
          if pkt is None:
            tp  = "IP >> UNKNOWN"; pkt = eth
          else:
            tp  = "IP >> " + t
        else:
          tp    = "RAW"; pkt = eth
        print("{} | eth >> {} | from {} :".format(tm, tp, src))
        print("  parsed:", pkt)
        print("  raw:", data)
        print("  hex:", b2s(binascii.hexlify(data)))
        print()
  finally:
    sock.close()
                                                                # }}}1

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
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHO

def is_icmp_echoreply(icmp_data):
  """is ICMP_ECHOREPLY?"""
  return  dict(TYPE = icmp_data["TYPE"], CODE = icmp_data["CODE"]) \
            == ICMP_ECHOREPLY

def is_icmp_exc_ttl(icmp_data):
  """is ICMP_EXC_TTL?"""
  return  is_icmp_time_exceeded(icmp_data) and \
            icmp_data["CODE"] == ICMP_EXC_TTL

def is_icmp_time_exceeded(icmp_data):
  """is ICMP_TIME_EXCEEDED?"""
  return icmp_data["TYPE"] == ICMP_TIME_EXCEEDED

def is_icmp_port_unreach(icmp_data):
  """is ICMP_PORT_UNREACH?"""
  return  is_icmp_dest_unreach(icmp_data) and \
            icmp_data["CODE"] == ICMP_PORT_UNREACH

def is_icmp_dest_unreach(icmp_data):
  """is ICMP_DEST_UNREACH?"""
  return icmp_data["TYPE"] == ICMP_DEST_UNREACH

def unpack_icmp(pkt):                                           # {{{1
  """unpack ICMP packet from IP packet"""

  d = unpack_ip(pkt)
  if not is_icmp(d): return None
  o = d["ip_data_offset"]; icmp_hdr, icmp_data = pkt[o:o+8], pkt[o+8:]
  TYPE, code, _, ID, seq = struct.unpack("!BBHHH", icmp_hdr)
  d.update(TYPE = TYPE, CODE = code, ID = ID, seq = seq,
           icmp_data = icmp_data)
  return d
                                                                # }}}1

def is_icmp(ip_data):
  """is ICMP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_ICMP

# === UDP ========================================================= #
# source port (16)                | destination port (16)           #
# length (16)                     | checksum (16)                   #
#                           ... data ...                            #
# ================================================================= #

def unpack_udp(pkt):                                            # {{{1
  """unpack UDP packet from IP packet"""

  d = unpack_ip(pkt)
  if not is_udp(d): return None
  o = d["ip_data_offset"]; udp_hdr, udp_data = pkt[o:o+8], pkt[o+8:]
  s_port, d_port, _, _ = struct.unpack("!HHHH", udp_hdr)
  d.update(source_port = s_port, dest_port = d_port,
           udp_data = udp_data)
  return d
                                                                # }}}1

def is_udp(ip_data):
  """is UDP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_UDP

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

def unpack_tcp(pkt):                                            # {{{1
                                                                # {{{2
  r"""
  unpack TCP packet from IP packet

  >>> import binascii as B, trcrt as T
  >>> d = b"GET / HTTP/1.0\r\n"
  >>> p = T.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089, 0x1f9fb402, d, 29200, psh = 1, ack = 1)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = T.unpack_tcp(i + p)
  >>> " ".join(str(x[k]) for k in "source_port dest_port seq_n ack_n offset win_sz".split())
  '54474 80 24584329 530560002 5 29200'
  >>> T.b2s(x["tcp_opts"])
  ''
  >>> T.b2s(x["tcp_data"])
  'GET / HTTP/1.0\r\n'
  >>> " ".join("{}={}".format(k,v) for k, v in sorted(x["flags"].items()))
  'ack=1 cwr=0 ece=0 fin=0 ns=0 psh=1 rst=0 syn=0 urg=0'
  """                                                           # }}}2

  d = unpack_ip(pkt)
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+20]
  s_port, d_port, seq_n, ack_n, offset_and_flags, win_sz, _, _ = \
    struct.unpack("!HHIIHHHH", tcp_hdr)
  offset = offset_and_flags >> 12; flags = {}
  if not 5 <= offset <= 15: return None
  for i, flag in enumerate(reversed(TCP_FLAGS)):
    flags[flag.lower()] = (offset_and_flags >> i) & 0b1
  tcp_opts, tcp_data = pkt[o+20:o+offset*4], pkt[o+offset*4:]
  d.update(source_port  = s_port  , dest_port = d_port,
           seq_n        = seq_n   , ack_n     = ack_n,
           offset       = offset  , flags     = flags,
           win_sz       = win_sz  , tcp_opts  = tcp_opts,
           tcp_data     = tcp_data)
  return d
                                                                # }}}1

def unpack_tcp_first8(pkt):                                     # {{{1

  """
  unpack first 8 bytes of TCP packet from IP packet (from ICMP packet)

  >>> import binascii as B, trcrt as T
  >>> p = T.tcp_packet(("10.0.2.15", 54474), ("93.184.216.34", 80), 0x01772089)
  >>> i = B.unhexlify(b"45" + 8 * b"00" + b"06" + 10 * b"00") # fake IP header
  >>> x = T.unpack_tcp_first8(i + p)
  >>> " ".join(str(x[k]) for k in "source_port dest_port seq_n".split())
  '54474 80 24584329'
  """

  d = unpack_ip(pkt)
  if not is_tcp(d): return None
  o = d["ip_data_offset"]; tcp_hdr = pkt[o:o+8]
  s_port, d_port, seq_n = struct.unpack("!HHI", tcp_hdr)
  d.update(source_port = s_port, dest_port = d_port, seq_n = seq_n)
  return d
                                                                # }}}1

def is_tcp_synack(tcp_data):
  """is TCP SYN+ACK?"""
  return tcp_data["flags"]["syn"] == 1 and \
         tcp_data["flags"]["ack"] == 1

def is_tcp_rst(tcp_data):
  """is TCP RST?"""
  return tcp_data["flags"]["rst"] == 1

def is_tcp(ip_data):
  """is TCP packet?"""
  return ip_data is not None and ip_data["PROTO"] == S.IPPROTO_TCP

TCP_FLAGS = "NS CWR ECE URG ACK PSH RST SYN FIN".split()

# === IPv4 ======================================================== #
# version | IHL  | DSCP + ECN (8) | length (16)                     #
# identification (16)             | flags + offset (16)             #
# TTL (8)        | protocol (8)   | checksum (16)                   #
#                        source IP address (32)                     #
#                     destination IP address (32)                   #
# ================================================================= #

# TODO
def unpack_ip(pkt):
  """unpack IP packet"""
  ihl, ttl, proto = b2i(pkt[0]) & 0xf, b2i(pkt[8]), b2i(pkt[9])
  if ihl != 5: return None    # ignore IPv4 w/ options -- TODO
  return dict(TTL = ttl, PROTO = proto, ip_data_offset = 4*ihl)

def is_ip(eth_data):
  """is IP packet?"""
  return eth_data is not None and eth_data["eth_type"] == ETH_IP

# === Layer 2 Ethernet Frame ====================================== #
#                       MAC destination (6o)                        #
#                          MAC source (6o)                          #
# 802.1Q tag (optional) (4o)            | Ethertype (2o)            #
#                         Payload (46(42)-1500o)                    #
#                               ...                                 #
# ================================================================= #

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
  d_mac, s_mac  = [ binascii.hexlify(i2b(reduce(f, x, 0)))
                    for x in [dest_mac, source_mac] ]
  return dict(dest_mac = d_mac, source_mac = s_mac,
              eth_type = eth_type, eth_q_tag = q_tag,
              eth_data = payload)
                                                                # }}}1

ETH_QTAG              = 0x8100
ETH_IP                = 0x0800

ICMP_ECHOREPLY        = dict(TYPE = 0, CODE = 0)
ICMP_ECHO             = dict(TYPE = 8, CODE = 0)

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
