# cortex9-argocd-git-ssh-proxy-url-injection-model

Offline model of **CVE-2026-55797** (GHSA-j6cw-g6p4-7hch): Argo CD's
repo-server copied the proxy host and port of an SSH repository into
`ProxyCommand='connect-proxy -S <host>:<port> -5 %h %p'` inside
`GIT_SSH_COMMAND`, a string interpreted by a shell. A host with shell
metacharacters changed that command. The sink was introduced by
9b27aeb1a4fb (SOCKS5 proxy support for SSH, first in v2.11.0); this model
uses it as `pre`. The fix in the patched tags is the squashed commit
"coordinated security fixes": 1149cdc6e932 in v3.3.15 (also 4bc8085b0a6d in
v3.4.10, 7f0a05834b05 in v3.5.4, d5dd7019ee65 in v3.6.0-rc2), used as
`post`. It adds `validateProxyURLWithSchemes` (socks5/socks5h, host `^[a-zA-Z0-9.\-]+$` or
an IPv6 address, port 1-65535) and moves host and port into a temporary
script. Educational, deterministic, C11 checked with ASan/UBSan. **No shell,
ssh, git, connect-proxy or Argo CD code runs, and nothing touches the
network.** The command is a string that a static POSIX-sh reader inspects.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled (tied to the diffs, `util/git/creds.go`)

`9b27aeb:N` is line N of creds.go after 9b27aeb1a4fb; `1149cdc:N` is line N
after 1149cdc6e932 (v3.3.15).

| Line | Code | Model |
|---|---|---|
| 9b27aeb:311 / 1149cdc:432 | `url.Parse(c.proxy)` | `src/go_url.c`: Parse, Hostname, Port (go1.27 rules) |
| 9b27aeb:315-317 | `ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'` | `pre` command string |
| 1149cdc:84-86, 95-133 | `validateProxyURL` -> `validateProxyURLWithSchemes` | `am_validate_proxy_url` |
| 1149cdc:57 | `^[a-zA-Z0-9.\-]+$` | host check |
| 1149cdc:341-350 | `NewSSHCreds`: invalid proxy -> logged, `proxy = ""` | `REJECTED` |
| 1149cdc:440-444 | script `exec connect-proxy -5 -S %s:%s "$@"` | level-2 input after the fix |
| 1149cdc:469 | `"ProxyCommand="+proxyScriptPath+" %h %p"` | `post` command string |
| 9b27aeb:325 / 1149cdc:479 | `GIT_SSH_COMMAND=` + `strings.Join(args, " ")` | joined with spaces |

**Level 1** is the shell that reads `GIT_SSH_COMMAND` (the fix's comment at
1149cdc:438-439 calls it "shell-interpreted"). **Level 2** is the shell that
runs the `ProxyCommand` value; that ssh runs it through a shell comes from
ssh_config(5), not from the verified sources.

## Differential evidence (`results/`)

| Proxy | pre | post |
|---|---|---|
| `socks5://evil'$(id>argocd-ssh-proxy-poc-id)'host:1080` (PoC in the fix's `util/git/ssh_test.go`) | `L1_INJECTION`: the `'` closes the quote, `$(...)` reaches git's shell | `REJECTED` (`ERR_HOST_CHARS`) |
| `socks5://a';id;'b:1080` | `L1_INJECTION` (2 operators) | `REJECTED` |
| `socks5://host;id:1080`, `host&id`, `host$(x)`, `host>x`, `h(x)`, `h"x` | `L2_ONLY`: quoted for git's shell, live in the ProxyCommand shell | `REJECTED` |
| `http://h'$(id)'x:1080` | `L1_INJECTION` (any scheme reached this path) | `REJECTED` (`ERR_SCHEME`) |
| `host|id`, `` host`x` ``, `ho st`, newline | `ENV_ERROR`: Go's url.Parse already refuses them | `REJECTED` |
| `127.0.0.1:1080`, `[::1]:1080`, `proxy.example.com:65535`, user:password@ | `CLEAN` | `CLEAN` |

`results/sweep.csv` puts each printable byte into `socks5://a<c>b:1080`:
before the fix 1 byte (`'`) reaches level 1 and 8 bytes reach level 2; after
it, none does. On 30,000 generated proxies (`tests/test_model.c`) the
post-fix model never yields `L1_INJECTION` or `L2_ONLY`, and every accepted
host matches the regexp or is IPv6.

**Unverified observation of the model:** after the fix, `" %h %p"` is not
quoted (1149cdc:469, same line on master), so git's shell would split `%h` and `%p` off the
`ProxyCommand` value (words 9 and 10 in `argossh case post ...`). This was
not run against ssh or a real Argo CD; it may be handled elsewhere (for
example in a later commit or in how the arguments reach ssh).

The master commit 1e3ddd0b7250 (cited in the candidate list) carries the
same `util/git/creds_test.go` and `ssh_test.go` changes and the same SSH
path in `creds.go`, but it is **not** in any patched tag (GitHub compare:
`v3.3.15...1e3ddd0` diverged); SOURCES.md lists both. It is
recorded as an observation, not a finding. See [LIMITATIONS.md](LIMITATIONS.md).

## Run

```sh
sh scripts/build.sh test              # -Wall -Wextra -Werror, ASan + UBSan
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/argossh case pre "socks5://host;id:1080"   # prints both levels; runs nothing
sh scripts/crosscheck_go.sh           # optional, local: needs Go, not in CI
```

`fixtures/cases.tsv` holds positive, negative, edge and out-of-domain
proxies with labels derived by hand. `fixtures/expected.tsv` comes from
`scripts/derive_expected.py`, a separate Python implementation. The C url
model was compared with the real go1.27.3 `net/url` on 724 inputs with
`scripts/crosscheck_go.sh` (identical on 2026-11-09).

A model is not a finding: see [LIMITATIONS.md](LIMITATIONS.md) and
[SOURCES.md](SOURCES.md). License: Apache-2.0.
