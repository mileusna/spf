package spf_test

import (
	"net"
	"testing"

	"github.com/mileusna/spf"
)

func TestLookup(t *testing.T) {
	if s, r := spf.LookupSPF("naslovi.net"); s == "" {
		t.Fatal("SPF to naslovi.net failed", r.String())
	}

	if s, r := spf.LookupSPF("aviokarte.rs"); s == "" {
		t.Fatal("SPF to aviokarte.rs failed", r.String())
	}

	if _, r := spf.LookupSPF("naslovi.dsdrs"); r != spf.None {
		t.Fatal("SPF on invalid domain should be NONE, returned", r.String())
	}
}

func TestParse(t *testing.T) {
	////fmt.Println(spf.ParseSPF("v=spf1 mx +a include:_spf.ha.rs ip4:87.237.206.36 -ip4:87.237.205.215 ip4:87.237.204.223 include:_spf.google.com ~all"))
	//fmt.Println(spf.ParseSPF("v=spf1 +a redirect=_spf.mailspot.com"))
}

type testData struct {
	ip     net.IP
	domain string
	sender string
	helo   string
	result spf.Result
}

func newTestData(ip, domain, sender, helo string, expResult spf.Result) testData {
	return testData{
		ip:     net.ParseIP(ip),
		domain: domain,
		sender: sender,
		helo:   helo,
		result: expResult,
	}
}
func TestCheckHost(t *testing.T) {

	ip := "87.237.204.223"
	ip2 := "87.237.205.46"

	data := []testData{
		newTestData(ip, "aviokarte.rs", "milos@aviokarte.rs", "", spf.Pass),
		newTestData(ip, "naslovi.net", "milos@naslovi.net", "", spf.Pass),
		newTestData(ip, "netmark.rs", "milos@netmark.rs", "", spf.Fail),
		newTestData(ip, "gmail.com", "mileusna@gmail.com", "", spf.Softfail),
		newTestData(ip, "hotmail.com", "mileusna@hotmail.com", "", spf.Softfail),
		newTestData(ip2, "netmark.rs", "milos@netmark.rs", "", spf.Pass),
		newTestData(ip2, "naslovi.net", "milos@naslovi.net", "", spf.Softfail),
	}

	for _, d := range data {
		if r := spf.CheckHost(d.ip, d.domain, d.sender, d.helo); r != d.result {
			t.Fatal("CheckHost", d.ip, d.domain, d.sender, "should", d.result, "returned:", r)
		}
	}

}

func TestMacro(t *testing.T) {
	sender := "strong-bad@email.example.com"
	ip := net.ParseIP("192.0.2.3")

	test := map[string]string{
		"%{s}":                              "strong-bad@email.example.com",
		"%{o}":                              "email.example.com",
		"%{d}":                              "email.example.com",
		"%{d4}":                             "email.example.com",
		"%{d3}":                             "email.example.com",
		"%{d2}":                             "example.com",
		"%{d1}":                             "com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l}":                              "strong-bad",
		"%{l-}":                             "strong.bad",
		"%{lr}":                             "strong-bad",
		"%{lr-}":                            "bad.strong",
		"%{l1r-}":                           "strong",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp._spf.%{d2}":              "bad.strong.lp._spf.example.com",
		"%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}":  "3.2.0.192.in-addr.strong.lp._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
	}

	for m, r := range test {
		res := spf.Macro(m, ip, "email.example.com", sender, "hello.server")
		if res != r {
			t.Fatal(m, "result shold be", r, "returned:", res)
		}
	}
}
