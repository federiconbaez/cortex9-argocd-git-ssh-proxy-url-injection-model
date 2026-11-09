# Sources

Local copies under `security-research-45/sources/cve2026/` (not in this
repo), fetched read-only (GET) with the GitHub API; the SHA-256 of each copy
is listed in that directory's `SHA256SUMS` (re-checked on 2026-11-09).

## Commits

| Role | Commit | Tag evidence (`tags_CVE-2026-55797.txt`) | Used for | SHA-256 of diff copy |
|---|---|---|---|---|
| **pre**: introduced the sink ("Added socks5 proxy support for ssh based git URL, upgraded go-git to 5.10.1 (#15864)", 2024-01-09) | [9b27aeb1a4fb15d11a0f01cad65dea1fdfc60205](https://github.com/argoproj/argo-cd/commit/9b27aeb1a4fb15d11a0f01cad65dea1fdfc60205) | in v2.11.0, not in v2.10.20 | `creds.go` 9b27aeb:309-326 (url.Parse, ProxyCommand, GIT_SSH_COMMAND) | a815b8a2ae762f1f66f2f78f96ce7b4555b9a2bf224128f4448e915aa631f0c5 |
| **post**: fix in v3.3.15 ("fix(security): coordinated security fixes (release-3.3) (#30040)", 2026-10-06, 31 files) | [1149cdc6e932208c4402183cc3d7b7485239940c](https://github.com/argoproj/argo-cd/commit/1149cdc6e932208c4402183cc3d7b7485239940c) | in v3.3.15 (compare: behind 1, ahead 0), not in v3.3.14 | `creds.go` 1149cdc:57, 84-133, 341-350, 426-479; `ssh_test.go` PoC | 40cc972d7703741ca41224a97dd8f88591d68d057809b2fcdd436c1eed3e1a44 |
| fix in v3.4.10 (#30039) | [4bc8085b0a6d2296b849539d3d09fc7be7a4a511](https://github.com/argoproj/argo-cd/commit/4bc8085b0a6d2296b849539d3d09fc7be7a4a511) | in v3.4.10 | cross-check | acc22901502d3f02d69372455f0677f280af6147542c9b9f9203c42633db8a93 |
| fix in v3.5.4 (#30038) | [7f0a05834b05103d69d7c150e1ee36541b314696](https://github.com/argoproj/argo-cd/commit/7f0a05834b05103d69d7c150e1ee36541b314696) | in v3.5.4 | cross-check | fc9cfb997ef891439d4c881a034ce8b4b7eeed77bf775fcff3b64732ea0dc47b |
| fix in v3.6.0-rc2 (#30037) | [d5dd7019ee65be8895133fe4df554e28074242c4](https://github.com/argoproj/argo-cd/commit/d5dd7019ee65be8895133fe4df554e28074242c4) | in v3.6.0-rc2 | cross-check | 4ff28e6904063c13ffc4d41ad804230da6a9e8bb7a5c164f0e95024b262b7daa |
| master commit ("fix: prevent command injection via SSH proxy handling in GIT_SSH_COMMAND", 2026-10-06; message cites GHSA-j6cw-g6p4-7hch and cherry-picks 521ec2ce9c36 / ec94afab64b7, which the API does not resolve) | [1e3ddd0b7250aa23f489956b5fab8c13d0493a9f](https://github.com/argoproj/argo-cd/commit/1e3ddd0b7250aa23f489956b5fab8c13d0493a9f) | **not** in v3.3.15 or v3.4.10 (diverged) | comparison only | a358e95d59c1b6a36ad15fe5d490ced8b278519d813a22e9887a341522c5dbc2 |

The `+/-` lines of `util/git/creds_test.go` and `util/git/ssh_test.go` are
identical in all five fix commits. In `creds.go`, 7f0a0583 and d5dd7019 match
1e3ddd0 exactly; 1149cdc and 4bc8085 lack the Azure `WithProxy` hunk and
one comment line.

## Advisories

| Source | URL | Used for | SHA-256 of copy |
|---|---|---|---|
| GHSA-j6cw-g6p4-7hch (GitHub advisory JSON) | https://github.com/argoproj/argo-cd/security/advisories/GHSA-j6cw-g6p4-7hch | affected: v2 `>= 2.11.0, <= 2.14.21` (no patch); v3 `>= 3.0.0, < 3.3.15`, `>= 3.4.0, < 3.4.10`, `>= 3.5.0, < 3.5.4`, `= 3.6.0-rc1`; fixed 3.3.15, 3.4.10, 3.5.4, 3.6.0-rc2; CWE-78; http/https/socks5 proxies on SSH repos all reach the path; 9b27aeb1a4 named as the introducing commit | f9718c82159fdfc7424b832a6168b5f0328e5d9cdff2eb7cec954031d43d7cd1 |
| NVD CVE-2026-55797 (Undergoing Analysis, published 2026-10-09) | https://nvd.nist.gov/vuln/detail/CVE-2026-55797 | description, CWE-78; it lists 9b27aeb1a4fb among references, but that commit introduced the bug | a2fc0eb959713bedff9d495a0f078dfb0d839189c7f85e81e870a1e4e289b02f |
| Go standard library, go1.27.3 `src/net/url/url.go` (local toolchain) | https://go.dev/ | url.Parse rules in `src/go_url.c`; compared on 724 inputs with `scripts/crosscheck_go.sh` | not copied |

No source contained instructions addressed to a tool or agent. The fix
commits' messages include co-author trailers; they were read as data only.
