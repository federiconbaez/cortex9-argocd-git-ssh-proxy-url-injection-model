# Limitations

- **A model, not a finding.** Nothing here was reproduced against Argo CD,
  git, ssh or connect-proxy. It restates the advisory and the fix commit.
- **Static shell reader.** `src/shlex.c` counts command substitutions,
  parameter expansions and unquoted `; & | < > ( )` / newlines, and dequotes
  the first command's words. It does not model globbing (`*`, `?`, `[`),
  tilde, brace or arithmetic expansion, here-documents, aliases, reserved
  words or `$'...'`. A proxy that is `CLEAN` here can still be changed by
  those (for example `*` at level 2).
- **Level 2.** That ssh runs `ProxyCommand` through a shell comes from
  ssh_config(5), not from the sources in SOURCES.md. `%h` and `%p` are kept
  literally. When level 1 is already injected, the level-2 columns are not
  meaningful.
- **The rest of `GIT_SSH_COMMAND`.** Only the `ProxyCommand` argument
  follows the diff. The prefix (`ssh -i <key> -o StrictHostKeyChecking=no -o
  UserKnownHostsFile=/dev/null`) is a placeholder based on the options the
  tests assert; key and script paths are fixed placeholders.
- **Go version.** `src/go_url.c` follows go1.27.3 (strict colons for
  http/https, `[` only at the start, bracketed hosts must be IPv6). Older Go
  versions accept more hosts; which Go version a given Argo CD release was
  built with is **not verified**. Percent-encoding and non-ASCII bytes are
  outside the model (`BAD_INPUT`).
- **Post-fix observation.** In the model, `" %h %p"` after the script path
  (1149cdc:469) is split by git's shell into separate words. This is an
  **unverified observation**, not a finding: it was not run against ssh,
  and the shipped releases may differ from this single commit.
- **Not modelled:** the HTTP/HTTPS creds paths that also gained
  `ValidateHTTPProxyURL` (1149cdc:91-93, 520; the Azure hunk of master is not in v3.3.15), SOCKS5 user/password
  environment variables, temp-file cleanup, the v2 line without a patch.
- **Which commit.** `post` follows 1149cdc6e932 (v3.3.15). Its SSH path
  (+/- lines of `util/git/creds.go` for validation, `NewSSHCreds`, the
  script and `ProxyCommand`) matches 1e3ddd0b7250 on master; the v3.5.4 and
  v3.6.0-rc2 commits match master on all of `creds.go`; v3.3.15 and v3.4.10
  lack only the Azure `WithProxy` hunk. The squashed commits also carry
  unrelated security fixes (jsonnet, hooks, extensions, kustomize, OCI,
  sessions) that are **not** modelled. `pre` is 9b27aeb1a4fb as introduced;
  later changes to that code before the fix are not modelled.
- **Sweeps** (`results/sweep.csv`, 30,000 generated proxies in the tests)
  are grids, not proofs.
- Nothing is attributed beyond the commit and advisories in SOURCES.md.
