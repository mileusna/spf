package spf

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	spfDelimiters = []byte(".-+,/_=")
	macroSyntax   = regexp.MustCompile("%[^{_\\-%}]")
	macroMatch    = regexp.MustCompile("%{[^}]+}")
	macroReplacer = strings.NewReplacer("%%", "%", "%_", " ", "%-", "%20")
)

type macro struct {
	ip     net.IP
	domain string
	sender string
	helo   string
}

func (c check) macro(m string, ip net.IP, domain, sender, helo string) (string, Result) {
	if len(macroSyntax.FindAllString(m, -1)) != 0 {
		return m, PermError
	}

	m = macroReplacer.Replace(m)

	mac := macro{
		ip:     ip,
		domain: domain,
		sender: sender,
		helo:   helo,
	}

	return macroMatch.ReplaceAllStringFunc(m, mac.eval), None
}

func (m macro) eval(s string) string {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "%{"), "}")
	sep := ""
	n := 0
	reverse := false

	var t string
	for i, b := range s {
		switch {
		case i == 0:
			switch b {
			case 'i':
				t = m.ip.String()
			case 's':
				t = m.sender
			case 'l':
				l, _ := senderParts(m.sender)
				t = l
			case 'o':
				_, o := senderParts(m.sender)
				t = o
			case 'd':
				t = m.domain
			case 'p':
				// TODO: p
			case 'v':
				if m.ip.To4() != nil {
					t = "in-addr"
				} else {
					t = "ip6"
				}
			case 'h':
				t = m.helo
			}

		case b >= '0' && b <= '9':
			n, _ = strconv.Atoi(string(b))

		case b == 'r':
			reverse = true

		case bytes.ContainsRune(spfDelimiters, b):
			sep = string(b)
		}
	}

	if sep != "" || reverse || n != 0 {
		if sep == "" {
			sep = "."
		}
		p := strings.Split(t, sep)
		if reverse {
			for i := len(p)/2 - 1; i >= 0; i-- {
				opp := len(p) - 1 - i
				p[i], p[opp] = p[opp], p[i]
			}
		}

		t = ""
		c := 0
		for i := len(p) - 1; i >= 0; i-- {
			if t != "" {
				t = "." + t
			}
			t = p[i] + t

			c++
			if n != 0 && c == n {
				break
			}
		}
	}
	return t
}

func senderParts(s string) (string, string) {
	parts := strings.SplitN(s, "@", 2)
	switch len(parts) {
	case 0:
		return "", ""
	case 1:
		return parts[0], ""
	default:
		return parts[0], parts[1]
	}
}

/*

    Some special cases:
   o  A literal "%" is expressed by "%%".
   o  "%_" expands to a single " " space.
   o  "%-" expands to a URL-encoded space, viz., "%20".
7.2.  Macro Definitions
   The following macro letters are expanded in term arguments:
      s = <sender>
      l = local-part of <sender>
      o = domain of <sender>
      d = <domain>
      i = <ip>
      p = the validated domain name of <ip> (do not use)
      v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
      h = HELO/EHLO domain
Kitterman                    Standards Track                   [Page 29]

RFC 7208              Sender Policy Framework (SPF)           April 2014
   <domain>, <sender>, and <ip> are defined in Section 4.1.
   The following macro letters are allowed only in "exp" text:
      c = SMTP client IP (easily readable format)
      r = domain name of host performing the check
      t = current timestamp
*/
