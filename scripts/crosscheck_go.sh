#!/bin/sh
# Optional, local: compare the C url model with the real Go net/url on the
# fixture proxies plus one-byte sweeps. Needs a Go toolchain; not in CI.
# Run after "sh scripts/build.sh results /tmp/r" (builds build/argossh).
set -eu
tmp=${TMPDIR:-/tmp}/cx9-argo-crosscheck
mkdir -p "$tmp"
grep -v '^#' fixtures/cases.tsv | cut -f3 > "$tmp/inputs.txt"
python3 scripts/crosscheck_inputs.py >> "$tmp/inputs.txt"
go run scripts/crosscheck_go.go "$tmp/inputs.txt" > "$tmp/go.tsv"
./build/argossh parse-dump "$tmp/inputs.txt" > "$tmp/c.tsv"
diff "$tmp/go.tsv" "$tmp/c.tsv"
echo "crosscheck: $(wc -l < "$tmp/go.tsv") inputs identical ($(go version))"
