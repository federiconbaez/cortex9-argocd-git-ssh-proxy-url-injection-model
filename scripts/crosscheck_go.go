//go:build ignore

// Local, optional cross-check of the C url model against the real Go
// net/url and net packages (stdlib only, no network, nothing executed).
// It is NOT part of CI. Usage, from the repo root:
//
//	sh scripts/build.sh results /tmp/r   # builds build/argossh
//	sh scripts/crosscheck_go.sh
//
// Each input line uses the TSV escapes of fixtures/cases.tsv. For every line
// it prints: input, OK|ERR, Hostname(), Port(), and the result of a
// re-statement of validateProxyURLWithSchemes (1149cdc:95-133, v3.3.15).
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var hostRe = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

func unescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'x':
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
		}
	}
	return b.String()
}

func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func validate(raw string) string {
	p, err := url.Parse(raw)
	if err != nil {
		return "ERR_PARSE"
	}
	if p.Scheme != "socks5" && p.Scheme != "socks5h" {
		return "ERR_SCHEME"
	}
	h := p.Hostname()
	if h == "" {
		return "ERR_EMPTY_HOST"
	}
	if strings.Contains(h, ":") {
		if net.ParseIP(h) == nil {
			return "ERR_IPV6"
		}
	} else if !hostRe.MatchString(h) {
		return "ERR_HOST_CHARS"
	}
	ps := p.Port()
	if ps == "" {
		return "ERR_NO_PORT"
	}
	n, err := strconv.Atoi(ps)
	if err != nil || n < 1 || n > 65535 {
		return "ERR_PORT_RANGE"
	}
	return "OK"
}

func main() {
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		raw := unescape(line)
		u, err := url.Parse(raw)
		if err != nil {
			fmt.Printf("%s\tERR\t\t\t%s\n", line, validate(raw))
			continue
		}
		fmt.Printf("%s\tOK\t%s\t%s\t%s\n", line, escape(u.Hostname()), escape(u.Port()), validate(raw))
	}
}
