module github.com/myusername/RealiTLScanner

go 1.21

require github.com/oschwald/geoip2-golang v1.9.0

require (
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

// Personal fork for learning TLS fingerprinting techniques.
// Upstream: https://github.com/XTLS/RealiTLScanner
// Notes:
//   - studying how JA3/JA4 fingerprints are collected
//   - may experiment with additional cipher suite detection
