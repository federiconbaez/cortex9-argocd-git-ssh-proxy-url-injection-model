#include "shlex.h"
#include <string.h>

typedef struct {
  const char *s;
  size_t i, n;
  sl_report *r;
  int depth;     /* > 0 inside a command substitution */
  int first_cmd; /* still in the first simple command at depth 0 */
  int in_word;
  size_t wlen;
} lx;

static int name_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; }
static int name_char(char c) { return name_start(c) || (c >= '0' && c <= '9'); }

/* Open a word if none is open (quotes alone, as in '', still make a word). */
static int start_word(lx *L) {
  sl_report *r = L->r;
  if (L->depth || !L->first_cmd) return 0;
  if (!L->in_word) {
    if (r->nwords >= SL_MAX_WORDS) return 0;
    L->in_word = 1;
    L->wlen = 0;
    r->nwords++;
  }
  return 1;
}

static void put(lx *L, char c) {
  sl_report *r = L->r;
  if (!start_word(L)) return;
  if (L->wlen + 1 < SL_WORD_MAX) {
    r->words[r->nwords - 1][L->wlen++] = c;
    r->words[r->nwords - 1][L->wlen] = '\0';
  }
}

static void mark_expanded(lx *L) {
  if (L->depth) return;
  put(L, '$');
  if (L->first_cmd && L->in_word && L->r->nwords > 0)
    L->r->expanded[L->r->nwords - 1] = 1;
}

static void end_word(lx *L) { L->in_word = 0; }

static void lex_until(lx *L, char stop);

/* After a '$' (not in single quotes). Returns 1 if it was an expansion. */
static int dollar(lx *L) {
  const char *s = L->s;
  size_t i = L->i; /* points after '$' */
  if (i < L->n && s[i] == '(') {
    L->r->subst++;
    mark_expanded(L);
    L->i = i + 1;
    L->depth++;
    lex_until(L, ')');
    L->depth--;
    return 1;
  }
  if (i < L->n && s[i] == '{') {
    L->r->param++;
    mark_expanded(L);
    while (i < L->n && s[i] != '}') i++;
    if (i >= L->n) L->r->syntax = 1;
    L->i = i < L->n ? i + 1 : i;
    return 1;
  }
  if (i < L->n && (name_start(s[i]) || strchr("@*#?$!-0123456789", s[i]) != NULL)) {
    L->r->param++;
    mark_expanded(L);
    if (name_start(s[i]))
      while (i < L->n && name_char(s[i])) i++;
    else
      i++;
    L->i = i;
    return 1;
  }
  return 0;
}

static void backquote(lx *L) {
  L->r->subst++;
  mark_expanded(L);
  while (L->i < L->n && L->s[L->i] != '`') {
    if (L->s[L->i] == '\\' && L->i + 1 < L->n) L->i++;
    L->i++;
  }
  if (L->i >= L->n) L->r->syntax = 1;
  else L->i++;
}

static void dquote(lx *L) {
  while (L->i < L->n) {
    char c = L->s[L->i++];
    if (c == '"') return;
    if (c == '\\' && L->i < L->n && strchr("$`\"\\\n", L->s[L->i])) {
      if (L->s[L->i] != '\n') put(L, L->s[L->i]);
      L->i++;
    } else if (c == '$') {
      if (!dollar(L)) put(L, '$');
    } else if (c == '`') {
      backquote(L);
    } else {
      put(L, c);
    }
  }
  L->r->syntax = 1;
}

static void lex_until(lx *L, char stop) {
  while (L->i < L->n) {
    char c = L->s[L->i];
    if (stop && c == stop) {
      L->i++;
      end_word(L);
      return;
    }
    L->i++;
    if (c == ' ' || c == '\t') {
      end_word(L);
    } else if (c == '\\') {
      if (L->i < L->n) {
        if (L->s[L->i] != '\n') put(L, L->s[L->i]);
        L->i++;
      }
    } else if (c == '\'') {
      size_t st = L->i;
      start_word(L);
      while (L->i < L->n && L->s[L->i] != '\'') L->i++;
      if (L->i >= L->n) { L->r->syntax = 1; return; }
      for (; st < L->i; ++st) put(L, L->s[st]);
      L->i++;
    } else if (c == '"') {
      start_word(L);
      dquote(L);
    } else if (c == '`') {
      backquote(L);
    } else if (c == '$') {
      if (!dollar(L)) put(L, '$');
    } else if (c == '#' && !L->in_word) {
      while (L->i < L->n && L->s[L->i] != '\n') L->i++;
    } else if (strchr(";&|<>()\n", c)) {
      end_word(L);
      if (c == '\n' && L->i >= L->n && !L->depth) continue; /* trailing newline */
      if (!L->depth) {
        L->r->ops++;
        L->first_cmd = 0;
      }
      if (c == '(' && L->depth) {
        L->depth++;
        lex_until(L, ')');
        L->depth--;
      }
    } else {
      put(L, c);
    }
  }
  if (stop) L->r->syntax = 1;
}

void sl_analyze(const char *s, sl_report *r) {
  lx L;
  memset(r, 0, sizeof *r);
  memset(&L, 0, sizeof L);
  L.s = s;
  L.n = strlen(s);
  L.r = r;
  L.first_cmd = 1;
  lex_until(&L, 0);
}
