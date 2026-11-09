/* Model of how Argo CD's util/git/creds.go turns an SSH repository's proxy
 * URL into GIT_SSH_COMMAND: "pre" as introduced by 9b27aeb1a4fb (v2.11.0),
 * "post" as fixed by 1149cdc6e932 (in v3.3.15) (CVE-2026-55797). Line
 * references: 9b27aeb:N and 1149cdc:N are lines of the new file in each
 * diff. Nothing is executed: the command is a string that the
 * static lexer in shlex.c reads twice (level 1: the shell git uses for
 * GIT_SSH_COMMAND; level 2: the shell that runs the ProxyCommand value). */
#ifndef ARGO_MODEL_H
#define ARGO_MODEL_H
#include "go_url.h"
#include "shlex.h"

#define AM_CMD_MAX 4096

typedef enum { AM_PRE = 0, AM_POST = 1 } am_version;

typedef enum {
  AV_OK = 0,
  AV_ERR_PARSE,      /* url.Parse error */
  AV_ERR_SCHEME,     /* not socks5/socks5h */
  AV_ERR_EMPTY_HOST,
  AV_ERR_IPV6,       /* host has ':' and net.ParseIP fails */
  AV_ERR_HOST_CHARS, /* not ^[a-zA-Z0-9.\-]+$ */
  AV_ERR_NO_PORT,
  AV_ERR_PORT_RANGE
} am_valid;

typedef enum {
  AL_BAD_INPUT = 0,
  AL_NO_PROXY,     /* no ProxyCommand in the command */
  AL_ENV_ERROR,    /* pre: Environ() returns the url.Parse error */
  AL_REJECTED,     /* post: NewSSHCreds drops the proxy (proxy = "") */
  AL_CLEAN,        /* ProxyCommand present, no substitution or operator at either level */
  AL_L2_ONLY,      /* clean for git's shell, but the ProxyCommand value is not */
  AL_L1_INJECTION  /* the proxy text changes git's own shell command */
} am_label;

typedef struct {
  am_label label;
  am_valid valid;  /* post: validateProxyURL result; pre: AV_OK */
  gu_url url;
  sl_report l1, l2;
  int has_proxycmd;
  int validated;    /* post with a non-empty proxy */
  int parsed;       /* url.Parse ran in Environ() */
  char git_ssh_command[AM_CMD_MAX];
  char proxy_value[AM_CMD_MAX]; /* level-2 input (pre: dequoted value; post: script exec line) */
} am_result;

am_valid am_validate_proxy_url(const char *raw); /* 1149cdc:95-133 */
void am_environ(am_version v, const char *proxy, am_result *r);

const char *am_valid_name(am_valid v);
const char *am_label_name(am_label l);
const char *am_version_name(am_version v);

#define AM_SSH_PREFIX "ssh -i /dev/shm/KEYFILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
#define AM_SCRIPT_PATH "/dev/shm/argocd-proxy-cmd-000000"
#endif
