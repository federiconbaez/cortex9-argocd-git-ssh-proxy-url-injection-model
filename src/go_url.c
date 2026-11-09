#include "go_url.h"
#include <string.h>

const char *gu_err_name(gu_err e) {
  static const char *const n[] = {"OK", "BAD_INPUT", "ERR_CTL", "ERR_NO_SCHEME",
                                  "ERR_COLON_SEG", "ERR_USERINFO", "ERR_BRACKET",
                                  "ERR_BRACKET_IP", "ERR_PORT", "ERR_HOST_CHAR"};
  return (unsigned)e < sizeof n / sizeof n[0] ? n[e] : "?";
}

static int is_alpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
static int is_digit(char c) { return c >= '0' && c <= '9'; }
static int is_hex(char c) { return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

/* shouldEscape(c, encodeHost) == false, for ASCII c other than '%'. */
static int host_char_ok(char c) {
  if (is_alpha(c) || is_digit(c)) return 1;
  return strchr("!$&'()*+,;=:[]<>\"-_.~", c) != NULL && c != '\0';
}

static int userinfo_char_ok(char c) {
  if (is_alpha(c) || is_digit(c)) return 1;
  return c != '\0' && strchr("-._:~!$&'()*+,;=%@", c) != NULL;
}

/* validOptionalPort: "" or ':' followed by digits only. */
static int valid_optional_port(const char *p, size_t n) {
  size_t i;
  if (n == 0) return 1;
  if (p[0] != ':') return 0;
  for (i = 1; i < n; ++i)
    if (!is_digit(p[i])) return 0;
  return 1;
}

static int parse_ipv4(const char *s, size_t n) {
  size_t i = 0;
  int fields = 0;
  while (i <= n) {
    size_t st = i;
    int v = 0;
    while (i < n && is_digit(s[i])) {
      v = v * 10 + (s[i] - '0');
      if (i - st >= 3 || v > 255) return 0;
      i++;
    }
    if (i == st) return 0;
    if (i - st > 1 && s[st] == '0') return 0; /* no leading zeros */
    fields++;
    if (i == n) break;
    if (s[i] != '.' || fields == 4) return 0;
    i++;
  }
  return fields == 4;
}

int gu_parse_ipv6(const char *s) {
  size_t n = strlen(s), p = 0;
  int i = 0, ellipsis = -1;
  if (n >= 2 && s[0] == ':' && s[1] == ':') {
    ellipsis = 0;
    p = 2;
    if (p == n) return 1;
  }
  while (i < 16) {
    size_t off = 0;
    while (p + off < n && is_hex(s[p + off])) {
      off++;
      if (off > 4) return 0;
    }
    if (off == 0) return 0;
    if (p + off < n && s[p + off] == '.') {
      if (ellipsis < 0 && i != 12) return 0;
      if (i + 4 > 16) return 0;
      if (!parse_ipv4(s + p, n - p)) return 0;
      i += 4;
      p = n;
      break;
    }
    i += 2;
    p += off;
    if (p == n) break;
    if (s[p] != ':' || p + 1 == n) return 0;
    p++;
    if (s[p] == ':') {
      if (ellipsis >= 0) return 0;
      ellipsis = i;
      p++;
      if (p == n) break;
    }
  }
  if (p != n) return 0;
  if (i < 16) return ellipsis >= 0;
  return ellipsis < 0;
}

static void copy_n(char *dst, const char *src, size_t n) {
  memcpy(dst, src, n);
  dst[n] = '\0';
}

/* parseHost (go1.27 net/url): a '[' anywhere but at index 0 is an invalid
 * IP-literal; a bracketed host must be an IPv6 literal (IPv4 rejected);
 * http/https use the first ':' when there are several (urlstrictcolons),
 * other schemes the last one. Returns URL.Host or an error. */
static gu_err parse_host(const char *scheme, const char *h, size_t n, char *out) {
  size_t i;
  int open = -1; /* strings.LastIndex(host, "[") */
  for (i = n; i-- > 0;)
    if (h[i] == '[') { open = (int)i; break; }
  if (open > 0) return GU_ERR_BRACKET_IP;
  if (open == 0) {
    size_t close = n;
    char inner[GU_MAX];
    for (i = n; i-- > 0;)
      if (h[i] == ']') { close = i; break; }
    if (close == n) return GU_ERR_BRACKET;
    if (!valid_optional_port(h + close + 1, n - close - 1)) return GU_ERR_PORT;
    for (i = 1; i < close; ++i)
      if (!host_char_ok(h[i])) return GU_ERR_HOST_CHAR;
    copy_n(inner, h + 1, close - 1);
    if (!gu_parse_ipv6(inner)) return GU_ERR_BRACKET_IP;
  } else {
    size_t first = n, last = n;
    for (i = 0; i < n; ++i)
      if (h[i] == ':') {
        if (first == n) first = i;
        last = i;
      }
    if (first != n) {
      size_t k = (last != first && (strcmp(scheme, "http") == 0 || strcmp(scheme, "https") == 0))
                     ? first
                     : last;
      if (!valid_optional_port(h + k, n - k)) return GU_ERR_PORT;
    }
  }
  for (i = 0; i < n; ++i)
    if (!host_char_ok(h[i])) return GU_ERR_HOST_CHAR;
  copy_n(out, h, n);
  return GU_OK;
}

/* URL.Hostname / URL.Port (splitHostPort). */
static void split_host_port(gu_url *u) {
  size_t n = strlen(u->host), i, hn = n;
  u->port[0] = '\0';
  for (i = n; i-- > 0;)
    if (u->host[i] == ':') {
      if (valid_optional_port(u->host + i, n - i)) {
        hn = i;
        copy_n(u->port, u->host + i + 1, n - i - 1);
      }
      break;
    }
  if (hn >= 2 && u->host[0] == '[' && u->host[hn - 1] == ']')
    copy_n(u->hostname, u->host + 1, hn - 2);
  else
    copy_n(u->hostname, u->host, hn);
}

void gu_parse(const char *raw, gu_url *u) {
  size_t n = strlen(raw), i, rlen, alen, at;
  const char *rest, *auth;
  memset(u, 0, sizeof *u);
  if (n >= GU_MAX) { u->err = GU_BAD_INPUT; return; }
  for (i = 0; i < n; ++i) {
    unsigned char c = (unsigned char)raw[i];
    if (c >= 0x80 || c == '%') { u->err = GU_BAD_INPUT; return; }
  }
  /* Parse: cut the fragment first, then parse() rejects CTL bytes in the rest. */
  for (i = 0; i < n; ++i)
    if (raw[i] == '#') { n = i; break; }
  for (i = 0; i < n; ++i)
    if ((unsigned char)raw[i] < 0x20 || raw[i] == 0x7f) { u->err = GU_ERR_CTL; return; }
  /* getScheme */
  rest = raw;
  rlen = n;
  for (i = 0; i < n; ++i) {
    char c = raw[i];
    if (is_alpha(c)) continue;
    if (is_digit(c) || c == '+' || c == '-' || c == '.') {
      if (i == 0) break;
      continue;
    }
    if (c == ':') {
      size_t k;
      if (i == 0) { u->err = GU_ERR_NO_SCHEME; return; }
      for (k = 0; k < i; ++k)
        u->scheme[k] = (char)((raw[k] >= 'A' && raw[k] <= 'Z') ? raw[k] + 32 : raw[k]);
      u->scheme[i] = '\0';
      rest = raw + i + 1;
      rlen = n - i - 1;
    }
    break;
  }
  /* query: a single trailing '?' is ForceQuery, otherwise cut at the first '?' */
  for (i = 0; i < rlen; ++i)
    if (rest[i] == '?') { rlen = i; break; }
  if (rlen == 0 || rest[0] != '/') {
    if (u->scheme[0]) { u->opaque = 1; return; }
    for (i = 0; i < rlen && rest[i] != '/'; ++i)
      if (rest[i] == ':') { u->err = GU_ERR_COLON_SEG; return; }
  }
  if (rlen < 2 || rest[0] != '/' || rest[1] != '/') return; /* no authority */
  if (!u->scheme[0] && rlen >= 3 && rest[2] == '/') return;
  auth = rest + 2;
  alen = rlen - 2;
  for (i = 0; i < alen; ++i)
    if (auth[i] == '/') { alen = i; break; }
  at = alen;
  for (i = alen; i-- > 0;)
    if (auth[i] == '@') { at = i; break; }
  if (at == alen) {
    u->err = parse_host(u->scheme, auth, alen, u->host);
  } else {
    u->err = parse_host(u->scheme, auth + at + 1, alen - at - 1, u->host);
    if (u->err == GU_OK) {
      for (i = 0; i < at; ++i)
        if (!userinfo_char_ok(auth[i])) { u->err = GU_ERR_USERINFO; break; }
      u->has_user = 1;
    }
  }
  if (u->err != GU_OK) { u->host[0] = '\0'; return; }
  split_host_port(u);
}
