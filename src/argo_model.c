#include "argo_model.h"
#include <stdio.h>
#include <string.h>

const char *am_version_name(am_version v) { return v == AM_PRE ? "pre" : "post"; }
const char *am_valid_name(am_valid v) {
  static const char *const n[] = {"OK", "ERR_PARSE", "ERR_SCHEME", "ERR_EMPTY_HOST",
                                  "ERR_IPV6", "ERR_HOST_CHARS", "ERR_NO_PORT", "ERR_PORT_RANGE"};
  return (unsigned)v < sizeof n / sizeof n[0] ? n[v] : "?";
}
const char *am_label_name(am_label l) {
  static const char *const n[] = {"BAD_INPUT", "NO_PROXY", "ENV_ERROR", "REJECTED",
                                  "CLEAN", "L2_ONLY", "L1_INJECTION"};
  return (unsigned)l < sizeof n / sizeof n[0] ? n[l] : "?";
}

static int host_regexp(const char *h) { /* ^[a-zA-Z0-9.\-]+$ (1149cdc:57) */
  if (!*h) return 0;
  for (; *h; ++h) {
    char c = *h;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          c == '.' || c == '-'))
      return 0;
  }
  return 1;
}

am_valid am_validate_proxy_url(const char *raw) {
  gu_url u;
  const char *p;
  long port = 0;
  gu_parse(raw, &u);                                         /* 1149cdc:96 */
  if (u.err != GU_OK) return AV_ERR_PARSE;
  if (strcmp(u.scheme, "socks5") != 0 && strcmp(u.scheme, "socks5h") != 0)
    return AV_ERR_SCHEME;                                    /* 1149cdc:101-104 */
  if (u.hostname[0] == '\0') return AV_ERR_EMPTY_HOST;       /* 1149cdc:106-109 */
  if (strchr(u.hostname, ':')) {                             /* 1149cdc:110-115 */
    if (!gu_parse_ipv6(u.hostname)) return AV_ERR_IPV6;
  } else if (!host_regexp(u.hostname)) {                     /* 1149cdc:116-121 */
    return AV_ERR_HOST_CHARS;
  }
  if (u.port[0] == '\0') return AV_ERR_NO_PORT;              /* 1149cdc:123-126 */
  for (p = u.port; *p; ++p) {                                /* 1149cdc:127-130: strconv.Atoi */
    port = port * 10 + (*p - '0');
    if (port > 65535) return AV_ERR_PORT_RANGE;
  }
  if (port < 1) return AV_ERR_PORT_RANGE;
  return AV_OK;
}

static int domain_ok(const char *proxy) {
  const unsigned char *p = (const unsigned char *)proxy;
  if (strlen(proxy) >= GU_MAX) return 0;
  for (; *p; ++p)
    if (*p >= 0x80 || *p == '%') return 0;
  return 1;
}

static void find_proxy_value(am_result *r) {
  int i;
  for (i = 0; i < r->l1.nwords; ++i) {
    if (strncmp(r->l1.words[i], "ProxyCommand=", 13) == 0) {
      r->has_proxycmd = 1;
      snprintf(r->proxy_value, sizeof r->proxy_value, "%s", r->l1.words[i] + 13);
      return;
    }
  }
}

void am_environ(am_version v, const char *proxy, am_result *r) {
  char opt[2 * GU_MAX + 64];
  memset(r, 0, sizeof *r);
  if (!domain_ok(proxy)) {
    r->label = AL_BAD_INPUT;
    r->url.err = GU_BAD_INPUT;
    return;
  }
  if (v == AM_POST && proxy[0] != '\0') {
    /* NewSSHCreds, 1149cdc:341-350: an invalid proxy is logged and dropped. */
    r->valid = am_validate_proxy_url(proxy);
    r->validated = 1;
    if (r->valid != AV_OK) proxy = "";
  }
  if (proxy[0] == '\0') {
    snprintf(r->git_ssh_command, sizeof r->git_ssh_command, "%s", AM_SSH_PREFIX);
    sl_analyze(r->git_ssh_command, &r->l1);
    r->label = (v == AM_POST && r->valid != AV_OK) ? AL_REJECTED : AL_NO_PROXY;
    return;
  }
  gu_parse(proxy, &r->url); /* 9b27aeb:311 / 1149cdc:432 */
  r->parsed = 1;
  if (r->url.err != GU_OK) { r->label = AL_ENV_ERROR; return; }
  if (v == AM_PRE) {
    /* 9b27aeb:315-317: ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p' */
    snprintf(opt, sizeof opt, "ProxyCommand='connect-proxy -S %s:%s -5 %%h %%p'",
             r->url.hostname, r->url.port);
  } else {
    /* 1149cdc:469: "ProxyCommand="+proxyScriptPath+" %h %p" */
    snprintf(opt, sizeof opt, "ProxyCommand=%s %%h %%p", AM_SCRIPT_PATH);
  }
  /* 9b27aeb:325 / 1149cdc:479: GIT_SSH_COMMAND= + strings.Join(args, " ") */
  snprintf(r->git_ssh_command, sizeof r->git_ssh_command, "%s -o %s", AM_SSH_PREFIX, opt);
  sl_analyze(r->git_ssh_command, &r->l1);
  find_proxy_value(r);
  if (v == AM_POST) {
    /* 1149cdc:440-444: the script body; level 2 is its exec line. */
    snprintf(r->proxy_value, sizeof r->proxy_value, "exec connect-proxy -5 -S %s:%s \"$@\"",
             r->url.hostname, r->url.port);
  }
  sl_analyze(r->proxy_value, &r->l2);
  if (r->l1.subst || r->l1.ops || r->l1.syntax || r->l1.param || !r->has_proxycmd)
    r->label = AL_L1_INJECTION;
  else if (r->l2.subst || r->l2.ops || r->l2.syntax || (v == AM_PRE && r->l2.param))
    r->label = AL_L2_ONLY;
  else
    r->label = AL_CLEAN;
}
