package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	HasReality  bool
	CertExpiry  time.Time
	Fingerprint string
	Error       error
}

// Scanner performs TLS/REALITY detection scans.
type Scanner struct {
	Timeout    time.Duration
	Concurrent int
	Geo        *Geo
}

// NewScanner creates a new Scanner with sensible defaults.
func NewScanner(timeout time.Duration, concurrent int, geo *Geo) *Scanner {
	return &Scanner{
		Timeout:    timeout,
		Concurrent: concurrent,
		Geo:        geo,
	}
}

// Scan scans a list of targets concurrently and returns results.
func (s *Scanner) Scan(targets []string, port string) []ScanResult {
	sem := make(chan struct{}, s.Concurrent)
	resultCh := make(chan ScanResult, len(targets))

	for _, ip := range targets {
		sem <- struct{}{}
		go func(ip string) {
			defer func() { <-sem }()
			resultCh <- s.scanOne(ip, port)
		}(ip)
	}

	// Drain semaphore to wait for all goroutines.
	for i := 0; i < s.Concurrent; i++ {
		sem <- struct{}{}
	}
	close(resultCh)

	var results []ScanResult
	for r := range resultCh {
		results = append(results, r)
	}
	return results
}

// scanOne performs a TLS handshake against a single host and detects REALITY.
func (s *Scanner) scanOne(ip, port string) ScanResult {
	addr := net.JoinHostPort(ip, port)
	result := ScanResult{IP: ip, Port: port}

	dialer := &net.Dialer{Timeout: s.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // We want to inspect even self-signed/REALITY certs.
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		result.Error = fmt.Errorf("dial: %w", err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = fmt.Errorf("no peer certificates")
		return result
	}

	cert := state.PeerCertificates[0]
	result.CertExpiry = cert.NotAfter
	result.Fingerprint = fingerprintCert(cert.Raw)
	result.ServerName = cert.Subject.CommonName
	result.HasReality = detectReality(state)

	return result
}

// detectReality heuristically detects REALITY protocol by examining TLS state.
// REALITY proxies typically present certificates that don't chain to a known CA
// and use specific TLS extensions.
func detectReality(state tls.ConnectionState) bool {
	if len(state.PeerCertificates) == 0 {
		return false
	}
	cert := state.PeerCertificates[0]
	// REALITY certs are self-signed or have mismatched issuer/subject.
	if cert.Issuer.String() == cert.Subject.String() {
		return true
	}
	// Check for suspiciously short validity windows typical of REALITY.
	validity := cert.NotAfter.Sub(cert.NotBefore)
	if validity < 24*time.Hour {
		return true
	}
	return false
}

// fingerprintCert returns a short hex fingerprint of raw DER certificate bytes.
func fingerprintCert(raw []byte) string {
	if len(raw) < 4 {
		return ""
	}
	return fmt.Sprintf("%02x%02x%02x%02x", raw[0], raw[1], raw[2], raw[3])
}
