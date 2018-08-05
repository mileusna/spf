package spf

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// LookupSPF returns spf txt record
// if no records found or more than one record found, r value will be set accordingly to None or PermError
// If dns lookup faild, r will be set to TempError
func LookupSPF(domain string) (spf string, r Result) {
	txts, err := lookupTXT(domain)
	if err != nil {
		return "", TempError
	}

	var spfs []string
	for _, txt := range txts {
		txt = strings.ToLower(txt)
		if txt == "v=spf1" || strings.HasPrefix(txt, "v=spf1 ") {
			spfs = append(spfs, txt)
		}
	}

	switch len(spfs) {
	case 0:
		return "", None
	case 1:
		return spfs[0], Result("")
	default:
		return "", PermError
	}
}

// lookupTXT using miekg DNS since net.LookupTXT returns error if no TXT records
// returns slice of TXT records and error
func lookupTXT(d string) ([]string, error) {
	var txt []string

	r, _, err := dnsQuest(d, dns.TypeTXT)
	if err != nil {
		return txt, err
	}

	for _, answ := range r.Answer {
		t := answ.(*dns.TXT)
		txt = append(txt, strings.Join(t.Txt, ""))
	}
	return txt, nil
}

func lookupA(d string) ([]net.IP, error) {
	var ips []net.IP

	r, _, err := dnsQuest(d, dns.TypeA)
	if err != nil {
		return ips, err
	}

	for _, answ := range r.Answer {
		a := answ.(*dns.A)
		ips = append(ips, a.A)
	}

	return ips, nil
}

func lookupAAAA(d string) ([]net.IP, error) {
	var ips []net.IP

	r, _, err := dnsQuest(d, dns.TypeAAAA)
	if err != nil {
		return ips, err
	}

	for _, answ := range r.Answer {
		a := answ.(*dns.AAAA)
		ips = append(ips, a.AAAA)
	}

	return ips, nil
}

func lookupMX(d string) ([]string, error) {
	var mxs []string

	r, _, err := dnsQuest(d, dns.TypeMX)
	if err != nil {
		return mxs, err
	}

	for _, answ := range r.Answer {
		mx := answ.(*dns.MX)
		mxs = append(mxs, mx.Mx)
	}

	return mxs, nil
}

func lookupPTR(ip net.IP) ([]string, error) {
	var hosts []string

	ipstr := ip.String()
	if ip.To4() != nil {
		ipstr += ".in-addr.arpa."
	} else {
		ipstr += "ip6.arpa."
	}

	r, _, err := dnsQuest(ipstr, dns.TypePTR)
	if err != nil {
		return hosts, err
	}

	for _, answ := range r.Answer {
		p := answ.(*dns.PTR)
		hosts = append(hosts, p.Ptr)
	}

	return hosts, nil
}

func dnsQuest(d string, t uint16) (r *dns.Msg, rtt time.Duration, err error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.SetQuestion(dns.Fqdn(d), t)
	m.RecursionDesired = true

	c := new(dns.Client)
	return c.Exchange(m, "8.8.8.8:53")
}

func init() {
	//config, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
}
