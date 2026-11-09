/* Tests for the Argo CD GIT_SSH_COMMAND proxy model. Run under ASan +
 * UBSan with -fno-sanitize-recover (scripts/build.sh test). */
#include "argo_model.h"
#include "cx9_util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks, failures;
#define CHECK(c, what)                                                    \
  do {                                                                    \
    checks++;                                                             \
    if (!(c)) {                                                           \
      failures++;                                                         \
      printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, what);               \
    }                                                                     \
  } while (0)

#define MAXCASES 80
typedef struct {
  char id[64], kind[16], proxy[CX9_FIELD_MAX], hand[2][32];
} tcase;
static tcase cases[MAXCASES];
static int ncases;
static am_result R; /* large: keep it off the stack */

static void load_cases(const char *dir) {
  char path[512], line[3 * CX9_FIELD_MAX];
  FILE *f;
  snprintf(path, sizeof path, "%s/cases.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open cases.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f) && ncases < MAXCASES) {
    char *fl[CX9_MAX_FIELDS];
    tcase *c = &cases[ncases];
    if (line[0] == '#' || line[0] == '\n') continue;
    if (cx9_split_tsv(line, fl, CX9_MAX_FIELDS) != 5 || strlen(fl[0]) >= 64 ||
        strlen(fl[1]) >= 16 || strlen(fl[3]) >= 32 || strlen(fl[4]) >= 32 ||
        cx9_unescape(fl[2], c->proxy, sizeof c->proxy) < 0) {
      CHECK(0, "cases.tsv row");
      continue;
    }
    strcpy(c->id, fl[0]);
    strcpy(c->kind, fl[1]);
    strcpy(c->hand[0], fl[3]);
    strcpy(c->hand[1], fl[4]);
    ncases++;
  }
  fclose(f);
  CHECK(ncases >= 30, "at least 30 fixture cases");
}

static void test_hand_labels(void) {
  int i, v, pos = 0, neg = 0;
  for (i = 0; i < ncases; ++i) {
    for (v = 0; v < 2; ++v) {
      am_environ((am_version)v, cases[i].proxy, &R);
      CHECK(strcmp(am_label_name(R.label), cases[i].hand[v]) == 0, cases[i].id);
    }
    if (strcmp(cases[i].kind, "pos") == 0) {
      am_label a, b;
      am_environ(AM_PRE, cases[i].proxy, &R);
      a = R.label;
      am_environ(AM_POST, cases[i].proxy, &R);
      b = R.label;
      CHECK((a == AL_L1_INJECTION || a == AL_L2_ONLY) && b == AL_REJECTED, "pos differs");
      pos++;
    }
    if (strcmp(cases[i].kind, "neg") == 0) {
      am_label a, b;
      am_environ(AM_PRE, cases[i].proxy, &R);
      a = R.label;
      am_environ(AM_POST, cases[i].proxy, &R);
      b = R.label;
      CHECK(a == b, "neg: same label before and after");
      neg++;
    }
  }
  CHECK(pos >= 8 && neg >= 8, "enough positive and negative fixtures");
}

/* fixtures/expected.tsv: scripts/derive_expected.py (Python, written from
 * creds.go and the go1.27 net/url sources). */
static void test_expected(const char *dir) {
  char path[512], line[3 * CX9_FIELD_MAX];
  FILE *f;
  int rows = 0, i;
  snprintf(path, sizeof path, "%s/expected.tsv", dir);
  f = fopen(path, "r");
  CHECK(f != NULL, "open expected.tsv");
  if (!f) return;
  while (fgets(line, sizeof line, f)) {
    char *fl[CX9_MAX_FIELDS];
    int n;
    if (strncmp(line, "id\t", 3) == 0) continue;
    n = cx9_split_tsv(line, fl, CX9_MAX_FIELDS);
    CHECK(n == 10, "expected.tsv row");
    if (n != 10) continue;
    for (i = 0; i < ncases; ++i) {
      char buf[4 * GU_MAX], l1[32], l2[32];
      const char *url;
      if (strcmp(cases[i].id, fl[0]) != 0) continue;
      am_environ(strcmp(fl[1], "post") == 0 ? AM_POST : AM_PRE, cases[i].proxy, &R);
      rows++;
      url = R.label == AL_BAD_INPUT ? "BAD_INPUT" : R.parsed ? gu_err_name(R.url.err) : "-";
      CHECK(strcmp(fl[2], url) == 0, fl[0]);
      CHECK(strcmp(fl[3], R.validated ? am_valid_name(R.valid) : "-") == 0, fl[0]);
      cx9_escape(R.url.hostname, strlen(R.url.hostname), buf, sizeof buf);
      CHECK(strcmp(fl[4], buf[0] ? buf : "-") == 0, fl[0]);
      cx9_escape(R.url.port, strlen(R.url.port), buf, sizeof buf);
      CHECK(strcmp(fl[5], buf[0] ? buf : "-") == 0, fl[0]);
      CHECK(atoi(fl[6]) == R.has_proxycmd, fl[0]);
      snprintf(l1, sizeof l1, "%d,%d,%d", R.l1.subst, R.l1.ops, R.l1.syntax);
      snprintf(l2, sizeof l2, "%d,%d,%d", R.l2.subst, R.l2.ops, R.l2.syntax);
      CHECK(strcmp(fl[7], l1) == 0, fl[0]);
      CHECK(strcmp(fl[8], l2) == 0, fl[0]);
      CHECK(strcmp(fl[9], am_label_name(R.label)) == 0, fl[0]);
    }
  }
  fclose(f);
  CHECK(rows == 2 * ncases, "every case has a pre and a post row");
}

static unsigned long long rng = 0x2545f4914f6cdd1dULL;
static unsigned next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return (unsigned)(rng >> 32);
}

static int safe_host(const char *h) {
  if (strchr(h, ':')) return gu_parse_ipv6(h);
  if (!*h) return 0;
  for (; *h; ++h)
    if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-", *h)) return 0;
  return 1;
}

/* Generated proxies: after the fix nothing but CLEAN, REJECTED, NO_PROXY or
 * ENV_ERROR is possible, and an accepted proxy has a safe host. */
static void test_invariants(void) {
  static const char *heads[] = {"socks5://", "socks5h://", "http://", "socks4://", "", "socks5:"};
  static const char alpha[] = "a1.-:[]@'\"$()`;&|<> \n#?/{}~*!=,+_";
  int k, injected_pre = 0;
  for (k = 0; k < 30000; ++k) {
    char proxy[96];
    size_t len = next() % 24, j, o;
    am_label pre;
    o = (size_t)snprintf(proxy, sizeof proxy, "%s", heads[next() % 6]);
    for (j = 0; j < len; ++j) proxy[o++] = alpha[next() % (sizeof alpha - 1)];
    if (next() % 2) o += (size_t)snprintf(proxy + o, sizeof proxy - o, ":%u", next() % 70000);
    proxy[o] = '\0';
    am_environ(AM_PRE, proxy, &R);
    pre = R.label;
    if (pre == AL_L1_INJECTION || pre == AL_L2_ONLY) injected_pre++;
    am_environ(AM_POST, proxy, &R);
    CHECK(R.label != AL_L1_INJECTION && R.label != AL_L2_ONLY, "post never injects");
    if (R.label == AL_CLEAN) {
      CHECK(R.valid == AV_OK && safe_host(R.url.hostname), "accepted host is safe");
      CHECK(R.l1.nwords == 11 && strcmp(R.l1.words[8], "ProxyCommand=" AM_SCRIPT_PATH) == 0,
            "post ProxyCommand is the script path");
    }
    if (pre == AL_CLEAN || pre == AL_L1_INJECTION || pre == AL_L2_ONLY)
      CHECK(R.label == AL_CLEAN || R.label == AL_REJECTED, "post outcome after a parsed pre");
  }
  CHECK(injected_pre > 100, "the generator reaches the bug before the fix");
}

/* The lexer itself, and inputs at the limits. */
static void test_adversarial(void) {
  static sl_report s;
  static char big[5000];
  size_t i;
  sl_analyze("a 'b c' \"d $x\" `e` ; f", &s);
  CHECK(s.subst == 1 && s.param == 1 && s.ops == 1 && !s.syntax && s.nwords == 4, "lexer mix");
  CHECK(strcmp(s.words[1], "b c") == 0, "single quotes keep spaces");
  sl_analyze("echo '' \"\"", &s);
  CHECK(s.nwords == 3 && s.words[1][0] == '\0', "empty quotes make empty words");
  sl_analyze("x 'unterminated", &s);
  CHECK(s.syntax == 1, "unterminated single quote");
  sl_analyze("x $(a 'b)' c", &s);
  CHECK(s.syntax == 1 && s.subst == 1, "quote inside $( hides the )");
  sl_analyze("x \\$y z\\;w", &s);
  CHECK(s.param == 0 && s.ops == 0 && strcmp(s.words[1], "$y") == 0 &&
            strcmp(s.words[2], "z;w") == 0,
        "backslash escapes");
  sl_analyze("x \\$(y)", &s);
  CHECK(s.subst == 0 && s.ops == 2, "an escaped $ leaves ( and ) as operators");
  sl_analyze("a\n", &s);
  CHECK(s.ops == 0, "a trailing newline is not a second command");
  for (i = 0; i + 2 < 4000; i += 2) memcpy(big + i, "$(", 2);
  big[3998] = '\0';
  sl_analyze(big, &s);
  CHECK(s.subst == 1999 && s.syntax == 1, "deep nesting, no overflow");
  memset(big, 'a', sizeof big - 1);
  big[sizeof big - 1] = '\0';
  am_environ(AM_PRE, big, &R);
  CHECK(R.label == AL_BAD_INPUT, "proxy longer than the domain");
  memcpy(big, "socks5://", 9);
  big[1023] = '\0';
  am_environ(AM_PRE, big, &R);
  CHECK(R.label == AL_CLEAN && strlen(R.url.hostname) == 1014, "1023-byte proxy, opaque-free host");
  CHECK(gu_parse_ipv6("1:2:3:4:5:6:7:8") && !gu_parse_ipv6("1:2:3:4:5:6:7:8:9") &&
            gu_parse_ipv6("::") && !gu_parse_ipv6(":::") && !gu_parse_ipv6("1::2::3") &&
            gu_parse_ipv6("::ffff:1.2.3.4") && !gu_parse_ipv6("::ffff:01.2.3.4") &&
            gu_parse_ipv6("1:2:3:4:5:6:7::") && !gu_parse_ipv6("12345::"),
        "IPv6 parser edges");
  CHECK(am_validate_proxy_url("socks5://h:99999999999999999999") == AV_ERR_PORT_RANGE,
        "huge port does not overflow");
}

/* Unverified observation of the model (README, LIMITATIONS): after the fix,
 * " %h %p" is not quoted, so git's shell splits it off the ProxyCommand
 * value. Tested so that a change in the model is noticed, not as a claim. */
static void test_post_observation(void) {
  am_environ(AM_POST, "socks5://127.0.0.1:1080", &R);
  CHECK(R.l1.nwords == 11, "post: 11 words");
  CHECK(strcmp(R.l1.words[9], "%h") == 0 && strcmp(R.l1.words[10], "%p") == 0,
        "post: %h and %p are separate words for git's shell");
  am_environ(AM_PRE, "socks5://127.0.0.1:1080", &R);
  CHECK(R.l1.nwords == 9 &&
            strcmp(R.l1.words[8], "ProxyCommand=connect-proxy -S 127.0.0.1:1080 -5 %h %p") == 0,
        "pre: the quoted value is one word");
}

/* PRACTICE.md levels. */
static void test_practice(void) {
  am_environ(AM_PRE, "socks5://127.0.0.1:1080", &R);
  CHECK(R.label == AL_CLEAN, "practice_level_1");
  am_environ(AM_PRE, "socks5://host;id:1080", &R);
  CHECK(R.label == AL_L2_ONLY && R.l1.ops == 0 && R.l2.ops == 1, "practice_level_2");
  am_environ(AM_PRE, "socks5://evil'$(id>argocd-ssh-proxy-poc-id)'host:1080", &R);
  CHECK(R.label == AL_L1_INJECTION && R.l1.subst == 1, "practice_level_3");
  am_environ(AM_PRE, "socks5://host|id:1080", &R);
  CHECK(R.label == AL_ENV_ERROR && R.url.err == GU_ERR_HOST_CHAR, "practice_level_4");
  am_environ(AM_POST, "socks5://evil'$(id>argocd-ssh-proxy-poc-id)'host:1080", &R);
  CHECK(R.label == AL_REJECTED && R.valid == AV_ERR_HOST_CHARS, "practice_level_5");
  am_environ(AM_POST, "socks5://[::1]:1080", &R);
  CHECK(R.label == AL_CLEAN, "practice_level_6");
  am_environ(AM_POST, "http://proxy.example.com:3128", &R);
  CHECK(R.label == AL_REJECTED && R.valid == AV_ERR_SCHEME, "practice_level_7");
  am_environ(AM_POST, "socks5://127.0.0.1:1080", &R);
  CHECK(strcmp(R.l1.words[9], "%h") == 0, "practice_level_8");
}

int main(int argc, char **argv) {
  const char *dir = argc > 1 ? argv[1] : "fixtures";
  load_cases(dir);
  test_hand_labels();
  test_expected(dir);
  test_invariants();
  test_adversarial();
  test_post_observation();
  test_practice();
  printf("%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
