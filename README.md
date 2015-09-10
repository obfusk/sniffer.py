[]: {{{1

    File        : README.md
    Maintainer  : Felix C. Stegerman <flx@obfusk.net>
    Date        : 2015-09-10

    Copyright   : Copyright (C) 2015  Felix C. Stegerman
    Version     : v0.0.1

[]: }}}1

<!-- badge? -->

## Description

sniffer.py - python (2+3) network sniffer

See `sniffer.py` for the code (with examples).

## Examples

```
$ sudo ./sniffer.py
...

1441925470 | eth >> IP >> TCP | from ('eth0', ...) :
  parsed: {'PROTO': 6, 'dest_port': 80, 'tcp_data': b'GET / HTTP/1.1...', ...}
  raw: ...
  hex: ...

...
```

## TODO

* prettier printing!
* (use) more parsers!
* options (like filtering)?!
* ...

## License

LGPLv3+ [1].

## References

[1] GNU Lesser General Public License, version 3
--- https://www.gnu.org/licenses/lgpl-3.0.html

[]: ! ( vim: set tw=70 sw=2 sts=2 et fdm=marker : )
