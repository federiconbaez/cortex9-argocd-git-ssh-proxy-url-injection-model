#!/usr/bin/env python3
"""Extra inputs for scripts/crosscheck_go.sh, one per line, TSV escapes."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cx9_util import escape  # noqa: E402

out = []
for c in range(0x20, 0x7F):
    ch = chr(c)
    if ch == "%":
        continue
    out += [
        "socks5://a" + ch + "b:1080",
        "socks5://[" + ch + "]:1080",
        "socks5://h:1" + ch,
        "http://a" + ch + ":b:1080",
        "socks5://u" + ch + "@h:1080",
        ch + "x://h:1",
        "socks5://[::1" + ch + "]:1",
    ]
out += ["*", "socks5:", "socks5:///x", "///h:1", "//h:1", "socks5://h:1#\x01",
        "socks5://h:1?q", "socks5://[::1]", "socks5://[1.2.3.4]:1",
        "socks5://[::ffff:1.2.3.4]:1", "socks5://[1::2::3]:1", "socks5://[12345::1]:1",
        "socks5://[::1]x", "socks5://h:", "SOCKS5://H:1", "socks5://[1:2:3:4:5:6:7:8]:1",
        "socks5://[1:2:3:4:5:6:7::]:1", "socks5://[::1.2.3.4]:1", "socks5://[1:2:3:4:5:6:1.2.3.4]:1",
        "socks5://[1:2:3:4:5:1.2.3.4]:1", "socks5://[::01.2.3.4]:1", "socks5://[::256.1.1.1]:1",
        "socks5://[:1]:1", "socks5://[1:]:1", "socks5://[::]:1", "socks5://h:99999999999999999999"]
for s in out:
    print(escape(s))
