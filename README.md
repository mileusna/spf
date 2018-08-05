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
    ip := net.ParseIP("123.123.123.123")
    r := spf.CheckHost(ip, "domain.com", "name@domain.com", "");
    // returns spf check result
    // "pass" / "fail" / "softfail" / "neutral" / "none" / "temperror" / "permerror"
}
```