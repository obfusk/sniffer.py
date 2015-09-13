[]: {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2015-09-12

    Copyright   : Copyright (C) 2015  Felix C. Stegerman
    Version     : v0.0.1

[]: }}}1

<!-- badge? -->

## Description

sniffer.py - python (2+3) network sniffer

See `sniffer.py` for the code (with examples).

## Examples

[]: {{{1

```
$ sudo ./sniffer.py
...
1441933466 | eth >> IP >> TCP | from ('eth0', ...) :
  parsed:
    eth_dest_mac        : XXXXXXXXXXXX
    eth_q_tag           : None
    eth_source_mac      : XXXXXXXXXXXX
    eth_type            : 2048 (0x800)
    ip_PROTO            : 6 (0x6)
    ip_TTL              : 64 (0x40)
    ip_dest             : 213.108.108.143
    ip_source           : X.X.X.X
    tcp_ack_n           : 12345 (0x3039)
    tcp_dest_port       : 80 (50)
    tcp_flags           : ack=1 ... syn=0 ...
    tcp_seq_n           : 67890 (0x10932)
    tcp_source_port     : 1234 (0x4d2)
    tcp_win_sz          : 229 (0xe5)
  raw:
    XX XX XX XX XX XX XX XX XX XX XX XX 08 00 45 00  XXXXXXXXXXXX..E.
    00 7d 02 07 40 00 40 06 1a cf XX XX XX XX XX XX  .}..@.@...XXXXXX
    XX XX eb 4c 00 50 be 73 a2 ee 99 18 6c ed 80 18  XX.L.P.s....l...
    00 e5 1e 15 00 00 01 01 08 0a 00 64 a0 ee 28 39  ...........d..(9
    c6 f6 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31  ..GET / HTTP/1.1
    0d 0a 48 6f 73 74 3a 20 6f 62 66 75 73 6b 2e 63  ..Host: obfusk.c
    68 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 63  h..User-Agent: c
    75 72 6c 2f 37 2e 34 34 2e 30 0d 0a 41 63 63 65  url/7.44.0..Acce
    70 74 3a 20 2a 2f 2a 0d 0a 0d 0a                 pt: */*....
...
```

[]: }}}1

## TODO

* (use) more parsers!
* options (like filtering)?!
* prettier printing?!
* ...

## License

GPLv3+ [1].

## References

[1] GNU General Public License, version 3
--- https://www.gnu.org/licenses/gpl-3.0.html

[]: ! ( vim: set tw=70 sw=2 sts=2 et fdm=marker : )
