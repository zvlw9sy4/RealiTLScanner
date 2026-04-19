package main

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Stats tracks scanning progress and results
type Stats struct {
	Scanned   atomic.Int64
	Reality   atomic.Int64
	TLS       atomic.Int64
	Errors    atomic.Int64
	StartTime time.Time
}

// NewStats initializes a new Stats instance
func NewStats() *Stats {
	return &Stats{
		StartTime: time.Now(),
	}
}

// IncrScanned increments the total scanned counter
func (s *Stats) IncrScanned() {
	s.Scanned.Add(1)
}

// IncrReality increments the Reality detected counter
func (s *Stats) IncrReality() {
	s.Reality.Add(1)
}

// IncrTLS increments the plain TLS detected counter
func (s *Stats) IncrTLS() {
	s.TLS.Add(1)
}

// IncrErrors increments the error counter
func (s *Stats) IncrErrors() {
	s.Errors.Add(1)
}

// Elapsed returns the duration since scanning started
func (s *Stats) Elapsed() time.Duration {
	return time.Since(s.StartTime)
}

// Rate returns the scanning rate in hosts per second
func (s *Stats) Rate() float64 {
	elapsed := s.Elapsed().Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(s.Scanned.Load()) / elapsed
}

// Summary returns a formatted summary string of the current stats
func (s *Stats) Summary() string {
	return fmt.Sprintf(
		"Scanned: %d | Reality: %d | TLS: %d | Errors: %d | Elapsed: %s | Rate: %.1f/s",
		s.Scanned.Load(),
		s.Reality.Load(),
		s.TLS.Load(),
		s.Errors.Load(),
		s.Elapsed().Round(time.Second),
		s.Rate(),
	)
}

// Print outputs the current stats summary to stdout
func (s *Stats) Print() {
	fmt.Println(s.Summary())
}

// StartPeriodicReport starts a goroutine that prints stats at the given interval.
// It stops when the done channel is closed.
func (s *Stats) StartPeriodicReport(interval time.Duration, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.Print()
			case <-done:
				// Print final stats before exiting
				s.Print()
				return
			}
		}
	}()
}
