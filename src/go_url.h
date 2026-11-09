/* Model of the parts of Go's net/url.Parse, URL.Hostname and URL.Port that
 * decide what Argo CD's creds.go sees for a proxy URL, plus net.ParseIP for
 * the IPv6 branch of validateProxyURLWithSchemes, following the go1.27
 * sources (net/url/url.go). Domain: ASCII without
 * '%' (percent-encoding is not modelled) and without bytes >= 0x80. */
#ifndef GO_URL_H
#define GO_URL_H
#include <stddef.h>

#define GU_MAX 1024

typedef enum {
  GU_OK = 0,
  GU_BAD_INPUT,        /* outside the modelled domain */
  GU_ERR_CTL,          /* "net/url: invalid control character in URL" */
  GU_ERR_NO_SCHEME,    /* "missing protocol scheme" */
  GU_ERR_COLON_SEG,    /* "first path segment in URL cannot contain colon" */
  GU_ERR_USERINFO,     /* "net/url: invalid userinfo" */
  GU_ERR_BRACKET,      /* "missing ']' in host" */
  GU_ERR_BRACKET_IP,   /* "invalid IP-literal": misplaced [ or bracketed non-IPv6 */
  GU_ERR_PORT,         /* "invalid port ... after host" */
  GU_ERR_HOST_CHAR     /* "invalid character ... in host name" */
} gu_err;

typedef struct {
  gu_err err;
  int opaque;            /* scheme present, no "//": Host stays empty */
  char scheme[GU_MAX];   /* lower-cased, as Go stores it */
  char host[GU_MAX];     /* URL.Host */
  char hostname[GU_MAX]; /* URL.Hostname() */
  char port[GU_MAX];     /* URL.Port() */
  int has_user;
} gu_url;

void gu_parse(const char *raw, gu_url *u);
int gu_parse_ipv6(const char *s); /* net.ParseIP(s) != nil, for s containing ':' */
const char *gu_err_name(gu_err e);
#endif
