# cortex9-argocd-git-ssh-proxy-url-injection-model

Modelo offline de **CVE-2026-55797** (GHSA-j6cw-g6p4-7hch): el repo-server
de Argo CD copiaba el host y el puerto del proxy de un repositorio SSH en
`ProxyCommand='connect-proxy -S <host>:<puerto> -5 %h %p'` dentro de
`GIT_SSH_COMMAND`, una cadena que interpreta un shell. Un host con
metacaracteres de shell cambiaba ese comando. El sink lo introdujo
9b27aeb1a4fb (soporte de proxy SOCKS5 para SSH, desde v2.11.0), que el
modelo usa como `pre`. El fix de los tags parcheados es el commit
"coordinated security fixes": 1149cdc6e932 en v3.3.15 (y 4bc8085b0a6d en
v3.4.10, 7f0a05834b05 en v3.5.4, d5dd7019ee65 en v3.6.0-rc2), usado como
`post`. Agrega `validateProxyURLWithSchemes` (socks5/socks5h, host
`^[a-zA-Z0-9.\-]+$` o IPv6, puerto 1-65535) y pasa host y puerto a un script
temporal. Educativo, determinista, en C11 comprobado con ASan/UBSan. **No se
ejecuta shell, ssh, git, connect-proxy ni código de Argo CD, y no hay
red.** El comando es una cadena que lee un lector estático de sh.

## Qué se modela

- `pre` (9b27aeb:315-317): el ProxyCommand con comillas simples.
- `post` (1149cdc:95-133, 341-350, 440-444, 469): la validación descarta
  el proxy en `NewSSHCreds`; uno válido pasa por el script.
- Nivel 1: el shell que lee `GIT_SSH_COMMAND` (el comentario del fix en
  1149cdc:438-439 lo llama "shell-interpreted"). Nivel 2: el shell que corre
  el valor de `ProxyCommand` (según ssh_config(5), no según las fuentes
  verificadas).

## Evidencia diferencial

- El PoC del `ssh_test.go` del fix (`evil'$(id>...)'host`) cierra la comilla
  y llega al nivel 1 antes del fix; después, `REJECTED`.
- `host;id`, `host&id`, `host$(x)`, `host>x`: quedan entre comillas para
  git pero vivos en el nivel 2; después, `REJECTED`.
- `host|id`, backticks, espacios y saltos de línea ya los rechazaba
  `url.Parse` de Go (`ENV_ERROR`).
- IPv4, `[::1]`, nombres DNS y user:password@ dan `CLEAN` antes y después.

**Observación no verificada del modelo:** después del fix, `" %h %p"` no va
entre comillas (1149cdc:469), así que el shell de git separaría `%h` y `%p`
del valor de `ProxyCommand`. No se probó contra ssh ni contra un Argo CD
real; es una observación, no un hallazgo.

El commit de master 1e3ddd0b7250 trae el mismo camino SSH, pero **no**
está en ningún tag parcheado; SOURCES.md documenta los dos.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
sh scripts/crosscheck_go.sh   # opcional, local, requiere Go
```

Un modelo no es un hallazgo: ver [LIMITATIONS.md](LIMITATIONS.md) y
[SOURCES.md](SOURCES.md). Ejercicios en [PRACTICE.md](PRACTICE.md).
Licencia: Apache-2.0.
