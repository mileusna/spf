package spf

import (
	"fmt"
	"net"
	"testing"
)

func TestPTR(t *testing.T) {
	c := check{
		cnt: 0,
	}
	ip := net.ParseIP("223.204.237.87")

	fmt.Println(c.checkPTR(ip, "aviokarte.rs", ""))
}

// Macro exports macro for testing
func Macro(m string, ip net.IP, domain, sender, helo string) string {
	if sender == "" {
		sender = "postmaster@" + helo
	}

	c := check{
		cnt: 0,
		//ip:  ip,
	}

	r, _ := c.macro(m, ip, domain, sender, helo)
	return r
}

// ParseSPF exports parseSPF for testing
func ParseSPF(spf string) []interface{} {
	return parseSPF(spf)
}
