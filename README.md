# SPF package for Go/GoLang

This package provides Sender Policy Framework (SPF) check for Go based on [RFC 7208](https://tools.ietf.org/html/rfc7208#section-4.6.3).

## TODO

Still have some issues to fix/add, like exp= modifier etc.

## Example
```go
package main

import (
    "net"

    "github.com/mileusna/spf"
)

func main() {
    // optional, set DNS server which will be used by resolver.
    // Default is Google's 8.8.8.8:53
    spf.DNSServer = "1.1.1.1:53"

    ip := net.ParseIP("123.123.123.123")
    r := spf.CheckHost(ip, "domain.com", "name@domain.com", "");
    // returns spf check result
    // "PASS" / "FAIL" / "SOFTFAIL" / "NEUTRAL" / "NONE" / "TEMPERROR" / "PERMERROR"

    // if you only need to retrive SPF record as string from DNS
    spfRecord, _ := spf.LookupSPF("domain.com")
}
```