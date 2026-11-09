#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv.

Written from the Argo CD diffs 9b27aeb1a4fb (introduced the sink, v2.11.0)
and 1149cdc6e932 (the fix in tag v3.3.15), util/git/creds.go, and the go1.27
net/url sources, not from the C model:

- pre  (9b27aeb:309-325): url.Parse, then
       ProxyCommand='connect-proxy -S <Hostname()>:<Port()> -5 %h %p'
- post (1149cdc:341-350, 95-133, 426-479): validateProxyURL in NewSSHCreds
       drops an invalid proxy; a valid one becomes ProxyCommand=<script> %h %p
       and the script runs exec connect-proxy -5 -S <host>:<port> "$@".

The two "levels" are read by a small POSIX-sh reader (no shell is run).
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cx9_util import escape, read_cases, unescape  # noqa: E402

PREFIX = "ssh -i /dev/shm/KEYFILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SCRIPT = "/dev/shm/argocd-proxy-cmd-000000"
HOST_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!$&'()*+,;=:[]<>\"-_.~")
USER_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._:~!$&'()*+,;=%@")


class URLError(Exception):
    pass


def port_ok(cp):
    return cp == "" or (cp[0] == ":" and all(c.isdigit() for c in cp[1:]))


def ipv4(s):
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not re.fullmatch(r"[0-9]{1,3}", p) or (len(p) > 1 and p[0] == "0") or int(p) > 255:
            return False
    return True


def ipv6(s):
    """netip.ParseAddr for a string with ':' and no zone, IPv6 result."""
    if s.count("::") > 1 or ":::" in s:
        return False
    tail4 = None
    if "." in s:
        head, _, last = s.rpartition(":")
        if not ipv4(last):
            return False
        tail4 = last
        s = head + ":" if head.endswith(":") else head
        if s == "":
            return False
    if "::" in s:
        left, right = s.split("::")
        lg = left.split(":") if left else []
        rg = right.split(":") if right else []
        groups = len(lg) + len(rg) + (2 if tail4 else 0)
        if groups >= 8:
            return False
        fields = lg + rg
    else:
        fields = s.split(":")
        if tail4 is not None:
            if s.endswith(":"):
                fields = fields[:-1]
        if len(fields) + (2 if tail4 else 0) != 8:
            return False
    return all(re.fullmatch(r"[0-9a-fA-F]{1,4}", f) for f in fields)


def parse_host(scheme, h):
    if h.rfind("[") > 0:
        raise URLError("ERR_BRACKET_IP")
    if h.startswith("["):
        close = h.rfind("]")
        if close < 0:
            raise URLError("ERR_BRACKET")
        if not port_ok(h[close + 1:]):
            raise URLError("ERR_PORT")
        inner = h[1:close]
        if any(c not in HOST_OK for c in inner):
            raise URLError("ERR_HOST_CHAR")
        if ":" not in inner or not ipv6(inner):
            raise URLError("ERR_BRACKET_IP")
    elif ":" in h:
        first, last = h.index(":"), h.rindex(":")
        k = first if (first != last and scheme in ("http", "https")) else last
        if not port_ok(h[k:]):
            raise URLError("ERR_PORT")
    if any(c not in HOST_OK for c in h):
        raise URLError("ERR_HOST_CHAR")
    return h


def go_url_parse(raw):
    """Returns (scheme, host) or raises URLError."""
    u = raw.split("#", 1)[0]
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in u):
        raise URLError("ERR_CTL")
    m = re.match(r"([A-Za-z][A-Za-z0-9+\-.]*):", u)
    if u.startswith(":"):
        raise URLError("ERR_NO_SCHEME")
    if m:
        scheme, rest = m.group(1).lower(), u[m.end():]
    else:
        scheme, rest = "", u
    if rest.endswith("?") and rest.count("?") == 1:
        rest = rest[:-1]
    else:
        rest = rest.split("?", 1)[0]
    if not rest.startswith("/"):
        if scheme:
            return scheme, ""
        if ":" in rest.split("/", 1)[0]:
            raise URLError("ERR_COLON_SEG")
    if rest.startswith("//") and (scheme or not rest.startswith("///")):
        authority = rest[2:].split("/", 1)[0]
        userinfo, sep, hostpart = authority.rpartition("@")
        host = parse_host(scheme, hostpart if sep else authority)
        if sep and any(c not in USER_OK for c in userinfo):
            raise URLError("ERR_USERINFO")
        return scheme, host
    return scheme, ""


def hostname_port(host):
    hn, port = host, ""
    i = host.rfind(":")
    if i >= 0 and port_ok(host[i:]):
        hn, port = host[:i], host[i + 1:]
    if hn.startswith("[") and hn.endswith("]"):
        hn = hn[1:-1]
    return hn, port


def validate(raw):
    try:
        scheme, host = go_url_parse(raw)
    except URLError:
        return "ERR_PARSE"
    if scheme not in ("socks5", "socks5h"):
        return "ERR_SCHEME"
    hn, port = hostname_port(host)
    if hn == "":
        return "ERR_EMPTY_HOST"
    if ":" in hn:
        if not ipv6(hn):
            return "ERR_IPV6"
    elif not re.fullmatch(r"[a-zA-Z0-9.\-]+", hn):
        return "ERR_HOST_CHARS"
    if port == "":
        return "ERR_NO_PORT"
    if not 1 <= int(port) <= 65535:
        return "ERR_PORT_RANGE"
    return "OK"


def sh_read(s):
    """Static reading of a sh command string: (subst, param, ops, syntax, words of the first command)."""
    st = {"subst": 0, "param": 0, "ops": 0, "syntax": 0}
    words, cur = [], None
    first = True
    i, n = 0, len(s)

    def emit(ch, nested):
        nonlocal cur
        if nested or not first:
            return
        if cur is None:
            cur = []
            words.append(cur)
        cur.append(ch)

    def dollar(j, nested):
        """s[j-1] == '$'. Returns new index or None if '$' is literal."""
        if j < n and s[j] == "(":
            st["subst"] += 1
            emit("$", nested)
            return skip_group(j + 1)
        if j < n and s[j] == "{":
            st["param"] += 1
            emit("$", nested)
            k = s.find("}", j)
            if k < 0:
                st["syntax"] = 1
                return n
            return k + 1
        if j < n and (s[j].isalpha() or s[j] == "_"):
            st["param"] += 1
            emit("$", nested)
            k = j
            while k < n and (s[k].isalnum() or s[k] == "_"):
                k += 1
            return k
        if j < n and s[j] in "@*#?$!-0123456789":
            st["param"] += 1
            emit("$", nested)
            return j + 1
        return None

    def backtick(j, nested):
        st["subst"] += 1
        emit("$", nested)
        while j < n and s[j] != "`":
            j += 2 if s[j] == "\\" else 1
        if j >= n:
            st["syntax"] = 1
            return n
        return j + 1

    def skip_group(j):
        """Inside $( ... ): read until the matching ')' (quotes respected)."""
        depth = 1
        while j < n:
            c = s[j]
            if c == "'":
                k = s.find("'", j + 1)
                if k < 0:
                    st["syntax"] = 1
                    return n
                j = k + 1
            elif c == '"':
                j = dq(j + 1, True)
            elif c == "\\":
                j += 2
            elif c == "`":
                j = backtick(j + 1, True)
            elif c == "$":
                r = dollar(j + 1, True)
                j = r if r is not None else j + 1
            elif c == "(":
                depth += 1
                j += 1
            elif c == ")":
                depth -= 1
                j += 1
                if depth == 0:
                    return j
            else:
                j += 1
        st["syntax"] = 1
        return n

    def dq(j, nested):
        while j < n:
            c = s[j]
            if c == '"':
                return j + 1
            if c == "\\" and j + 1 < n and s[j + 1] in '$`"\\\n':
                if s[j + 1] != "\n":
                    emit(s[j + 1], nested)
                j += 2
            elif c == "$":
                r = dollar(j + 1, nested)
                if r is None:
                    emit("$", nested)
                    j += 1
                else:
                    j = r
            elif c == "`":
                j = backtick(j + 1, nested)
            else:
                emit(c, nested)
                j += 1
        st["syntax"] = 1
        return n

    while i < n:
        c = s[i]
        if c in " \t":
            cur = None
            i += 1
        elif c == "\\":
            if i + 1 < n and s[i + 1] != "\n":
                emit(s[i + 1], False)
            i += 2
        elif c == "'":
            k = s.find("'", i + 1)
            if k < 0:
                st["syntax"] = 1
                break
            if first and cur is None:
                cur = []
                words.append(cur)
            for ch in s[i + 1:k]:
                emit(ch, False)
            i = k + 1
        elif c == '"':
            if first and cur is None:
                cur = []
                words.append(cur)
            i = dq(i + 1, False)
        elif c == "`":
            i = backtick(i + 1, False)
        elif c == "$":
            r = dollar(i + 1, False)
            if r is None:
                emit("$", False)
                i += 1
            else:
                i = r
        elif c == "#" and cur is None:
            k = s.find("\n", i)
            i = n if k < 0 else k
        elif c in ";&|<>()\n":
            cur = None
            if not (c == "\n" and i == n - 1):
                st["ops"] += 1
                first = False
            i += 1
        else:
            emit(c, False)
            i += 1
    return st, ["".join(w) for w in words]


def environ(version, proxy):
    """Returns a dict with the fields of expected.tsv."""
    out = dict(url="-", valid="-", host="", port="", pc=0, l1=(0, 0, 0), l2=(0, 0, 0))
    if "%" in proxy or any(ord(c) >= 0x80 for c in proxy) or len(proxy) >= 1024:
        return dict(out, url="BAD_INPUT", label="BAD_INPUT")
    if version == "post" and proxy:
        out["valid"] = validate(proxy)
        if out["valid"] != "OK":
            return dict(out, label="REJECTED")
    if not proxy:
        return dict(out, label="NO_PROXY")
    try:
        scheme, host = go_url_parse(proxy)
    except URLError as e:
        return dict(out, url=str(e), label="ENV_ERROR")
    hn, port = hostname_port(host)
    out.update(url="OK", host=hn, port=port)
    if version == "pre":
        opt = f"ProxyCommand='connect-proxy -S {hn}:{port} -5 %h %p'"
    else:
        opt = f"ProxyCommand={SCRIPT} %h %p"
    st1, words = sh_read(f"{PREFIX} -o {opt}")
    value = next((w[len("ProxyCommand="):] for w in words if w.startswith("ProxyCommand=")), None)
    out["pc"] = int(value is not None)
    if version == "post":
        value = f'exec connect-proxy -5 -S {hn}:{port} "$@"'
    st2, _ = sh_read(value or "")
    out["l1"] = (st1["subst"], st1["ops"], st1["syntax"])
    out["l2"] = (st2["subst"], st2["ops"], st2["syntax"])
    if st1["subst"] or st1["ops"] or st1["syntax"] or st1["param"] or value is None:
        out["label"] = "L1_INJECTION"
    elif st2["subst"] or st2["ops"] or st2["syntax"] or (version == "pre" and st2["param"]):
        out["label"] = "L2_ONLY"
    else:
        out["label"] = "CLEAN"
    return out


def main():
    root = Path(__file__).resolve().parent.parent
    print("id\tversion\turl_parse\tvalidation\thostname\tport\tproxycmd\tl1\tl2\tlabel")
    for row in read_cases(root / "fixtures" / "cases.tsv"):
        cid, proxy = row[0], unescape(row[2])
        for version in ("pre", "post"):
            r = environ(version, proxy)
            l1 = ",".join(map(str, r["l1"]))
            l2 = ",".join(map(str, r["l2"]))
            print(f"{cid}\t{version}\t{r['url']}\t{r['valid']}\t{escape(r['host']) or '-'}\t"
                  f"{escape(r['port']) or '-'}\t{r['pc']}\t{l1}\t{l2}\t{r['label']}")


if __name__ == "__main__":
    main()
