/* A static POSIX-sh lexer used to *read* a command string, never to run it.
 * It counts what a shell would do with the string: command substitutions
 * ($(...) and backquotes), parameter expansions, and unquoted control or
 * redirection operators, and it dequotes the words of the first simple
 * command. Arithmetic, here-documents, aliases and reserved words are
 * outside the model (see LIMITATIONS.md). */
#ifndef SHLEX_H
#define SHLEX_H
#include <stddef.h>

#define SL_MAX_WORDS 32
#define SL_WORD_MAX 1024

typedef struct {
  int subst;    /* $( ... ) or ` ... ` outside single quotes (nested ones too) */
  int param;    /* $name, ${...}, $@, $1 ... outside single quotes */
  int ops;      /* unquoted ; & | < > ( ) or a newline between commands */
  int syntax;   /* unterminated quote or substitution */
  int nwords;   /* words of the first simple command */
  int expanded[SL_MAX_WORDS]; /* word contains an expansion: dequoted text is not final */
  char words[SL_MAX_WORDS][SL_WORD_MAX];
} sl_report;

void sl_analyze(const char *s, sl_report *r);
#endif
