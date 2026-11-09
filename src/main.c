/* CLI (never runs a shell):
 *   argossh results fixtures/cases.tsv <dir>   regenerate cases.csv + sweep.csv
 *   argossh case pre|post <proxy>              show both levels (TSV escapes)
 *   argossh parse-dump <file>                  url model per line, for scripts/crosscheck_go.go */
#include "argo_model.h"
#include "cx9_util.h"
#include <stdio.h>
#include <string.h>

static void esc_field(FILE *f, const char *s) {
  char e[4 * AM_CMD_MAX];
  if (cx9_escape(s, strlen(s), e, sizeof e) != 0) e[0] = '\0';
  cx9_csv_field(f, e);
}

static void row(FILE *f, const char *id, const char *kind, am_version v, const am_result *r) {
  fprintf(f, "%s,%s,%s,%s,%s,", id, kind, am_version_name(v),
          r->label == AL_BAD_INPUT ? "BAD_INPUT" : r->parsed ? gu_err_name(r->url.err) : "-",
          r->validated ? am_valid_name(r->valid) : "-");
  esc_field(f, r->url.hostname);
  fputc(',', f);
  esc_field(f, r->url.port);
  fprintf(f, ",%d,%d,%d,%d,%d,%d,%d,%s\n", r->has_proxycmd, r->l1.subst, r->l1.ops, r->l1.syntax,
          r->l2.subst, r->l2.ops, r->l2.syntax, am_label_name(r->label));
}

static int results(const char *cases, const char *dir) {
  char path[1024], line[3 * CX9_FIELD_MAX];
  FILE *in = fopen(cases, "r"), *out, *sw;
  int c;
  static am_result r;
  if (!in) return 1;
  snprintf(path, sizeof path, "%s/cases.csv", dir);
  out = fopen(path, "w");
  if (!out) { fclose(in); return 1; }
  fputs("id,kind,version,url_parse,validation,hostname,port,proxycmd,l1_subst,l1_ops,"
        "l1_syntax,l2_subst,l2_ops,l2_syntax,label\n", out);
  while (fgets(line, sizeof line, in)) {
    char *f[CX9_MAX_FIELDS], proxy[CX9_FIELD_MAX];
    int v;
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, f, CX9_MAX_FIELDS) != 5 || cx9_unescape(f[2], proxy, sizeof proxy) < 0) {
      fclose(in); fclose(out);
      return 1;
    }
    for (v = 0; v < 2; ++v) {
      am_environ((am_version)v, proxy, &r);
      row(out, f[0], f[1], (am_version)v, &r);
    }
  }
  fclose(in);
  fclose(out);
  /* One-byte sweep: socks5://a<c>b:1080 for every printable ASCII byte but '%'. */
  snprintf(path, sizeof path, "%s/sweep.csv", dir);
  sw = fopen(path, "w");
  if (!sw) return 1;
  fputs("byte_hex,url_parse,pre_label,post_validation,post_label\n", sw);
  for (c = 0x20; c < 0x7f; ++c) {
    char proxy[32];
    static am_result a, b;
    if (c == '%') continue;
    snprintf(proxy, sizeof proxy, "socks5://a%cb:1080", c);
    am_environ(AM_PRE, proxy, &a);
    am_environ(AM_POST, proxy, &b);
    fprintf(sw, "%02x,%s,%s,%s,%s\n", c, gu_err_name(a.url.err), am_label_name(a.label),
            b.validated ? am_valid_name(b.valid) : "-", am_label_name(b.label));
  }
  fclose(sw);
  return 0;
}

static void show(const char *tag, const sl_report *s) {
  int i;
  printf("%s: subst=%d param=%d ops=%d syntax=%d words(first command)=%d\n", tag, s->subst,
         s->param, s->ops, s->syntax, s->nwords);
  for (i = 0; i < s->nwords; ++i) {
    char e[4 * SL_WORD_MAX];
    cx9_escape(s->words[i], strlen(s->words[i]), e, sizeof e);
    printf("  [%d] %s%s\n", i, e, s->expanded[i] ? "   (contains an expansion)" : "");
  }
}

int main(int argc, char **argv) {
  static am_result r;
  if (argc == 4 && strcmp(argv[1], "results") == 0) return results(argv[2], argv[3]);
  if (argc == 4 && strcmp(argv[1], "case") == 0 &&
      (strcmp(argv[2], "pre") == 0 || strcmp(argv[2], "post") == 0)) {
    char proxy[CX9_FIELD_MAX], e[4 * AM_CMD_MAX];
    if (cx9_unescape(argv[3], proxy, sizeof proxy) < 0) return 2;
    am_environ(strcmp(argv[2], "post") == 0 ? AM_POST : AM_PRE, proxy, &r);
    printf("label=%s url=%s validation=%s\n", am_label_name(r.label),
           r.parsed ? gu_err_name(r.url.err) : "-", r.validated ? am_valid_name(r.valid) : "-");
    cx9_escape(r.git_ssh_command, strlen(r.git_ssh_command), e, sizeof e);
    printf("GIT_SSH_COMMAND (string only, not executed): %s\n", e);
    show("level 1", &r.l1);
    if (r.proxy_value[0]) {
      cx9_escape(r.proxy_value, strlen(r.proxy_value), e, sizeof e);
      printf("level 2 input: %s\n", e);
      show("level 2", &r.l2);
    }
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "parse-dump") == 0) {
    char line[3 * CX9_FIELD_MAX], raw[CX9_FIELD_MAX], h[4 * GU_MAX], p[4 * GU_MAX];
    FILE *in = fopen(argv[2], "r");
    if (!in) return 1;
    while (fgets(line, sizeof line, in)) {
      gu_url u;
      size_t n = strlen(line);
      if (n && line[n - 1] == '\n') line[--n] = '\0';
      if (cx9_unescape(line, raw, sizeof raw) < 0) continue;
      gu_parse(raw, &u);
      cx9_escape(u.hostname, strlen(u.hostname), h, sizeof h);
      cx9_escape(u.port, strlen(u.port), p, sizeof p);
      printf("%s\t%s\t%s\t%s\t%s\n", line, u.err == GU_OK ? "OK" : "ERR", u.err == GU_OK ? h : "",
             u.err == GU_OK ? p : "", am_valid_name(am_validate_proxy_url(raw)));
    }
    fclose(in);
    return 0;
  }
  fprintf(stderr, "usage: %s results <cases.tsv> <dir> | case pre|post <proxy> | parse-dump <file>\n",
          argv[0]);
  return 2;
}
