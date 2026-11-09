# Guía práctica (8 niveles)

Ejercicios **offline y locales** sobre cómo un campo de configuración llega
a un shell. No se ejecuta shell, ssh, git ni Argo CD: `argossh` solo
imprime el comando y lo que vería un shell. Cada respuesta está comprobada
en `tests/test_model.c` (`practice_level_N`), compilado con ASan/UBSan. Si
querés ver el comportamiento real, hacelo solo en un lab propio (un cluster
kind/k3d tuyo, sin datos ni credenciales reales), nunca contra instancias
de terceros.

Comandos: `sh scripts/build.sh test`; después de `sh scripts/build.sh
results /tmp/r`: `./build/argossh case pre|post '<proxy>'`.

**Básico**

1. **El camino normal.** `socks5://127.0.0.1:1080` antes del fix.
   (`practice_level_1`: `CLEAN`)
2. **Dos shells.** `socks5://host;id:1080`. ¿Por qué el nivel 1 no ve el
   `;` y el nivel 2 sí? (`practice_level_2`: `L2_ONLY`, ops nivel 1 = 0,
   nivel 2 = 1)
3. **Cerrar la comilla.** El PoC del `ssh_test.go` del fix.
   (`practice_level_3`: `L1_INJECTION`, una sustitución en el nivel 1)

**Intermedio**

4. **Lo que Go ya rechaza.** `socks5://host|id:1080`. (`practice_level_4`:
   `ENV_ERROR`, `ERR_HOST_CHAR` en url.Parse)
5. **El fix.** El PoC en `post`. (`practice_level_5`: `REJECTED`,
   `ERR_HOST_CHARS`)
6. **IPv6.** `socks5://[::1]:1080` en `post`. ¿Por qué la regexp no alcanza
   y hace falta `net.ParseIP`? (`practice_level_6`: `CLEAN`)

**Avanzado**

7. **Esquemas.** `http://proxy.example.com:3128` en un repo SSH después del
   fix. (`practice_level_7`: `REJECTED`, `ERR_SCHEME`)
8. **Mirar el fix con lupa.** En `post`, ¿qué palabras ve el shell de git
   después de `ProxyCommand=...`? (`practice_level_8`: `%h` y `%p` quedan
   separadas; observación **no verificada** del modelo, ver LIMITATIONS)

Más allá: agregá un proxy a `fixtures/cases.tsv` con su etiqueta a mano,
regenerá `fixtures/expected.tsv` y, si tenés Go, corré
`sh scripts/crosscheck_go.sh`. Buscá en tu propio código lugares donde un
valor de configuración se interpola en un comando de shell.
