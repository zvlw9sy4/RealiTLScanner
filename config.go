package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// Config holds all runtime configuration for the scanner.
type Config struct {
	// Input
	CIDR      string
	InputFile string

	// Scanning
	Concurrency int
	Timeout     time.Duration
	Port        int
	Retries     int

	// Output
	OutputFile  string
	OutputJSON  bool
	Verbose     bool
	Quiet       bool

	// Geo
	GeoDBPath   string
	ShowGeo     bool
}

// ParseConfig parses command-line flags and returns a validated Config.
func ParseConfig() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.CIDR, "cidr", "", "CIDR range to scan (e.g. 1.2.3.0/24)")
	flag.StringVar(&cfg.InputFile, "input", "", "File containing IPs or CIDRs to scan, one per line")

	flag.IntVar(&cfg.Concurrency, "concurrency", 100, "Number of concurrent scanners")
	flag.DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Connection timeout per host")
	flag.IntVar(&cfg.Port, "port", 443, "TLS port to scan")
	flag.IntVar(&cfg.Retries, "retries", 1, "Number of retries on failure")

	flag.StringVar(&cfg.OutputFile, "output", "", "Output file path (default: stdout)")
	flag.BoolVar(&cfg.OutputJSON, "json", false, "Output results in JSON format")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&cfg.Quiet, "quiet", false, "Suppress all non-result output")

	flag.StringVar(&cfg.GeoDBPath, "geodb", "GeoLite2-Country.mmdb", "Path to MaxMind GeoLite2 country database")
	flag.BoolVar(&cfg.ShowGeo, "geo", false, "Annotate results with country information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "RealiTLScanner - Detect REALITY TLS targets\n\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -cidr 1.2.3.0/24 -json -output results.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -input targets.txt -concurrency 200 -timeout 3s\n", os.Args[0])
	}

	flag.Parse()

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// validate checks that the configuration is consistent and complete.
func (c *Config) validate() error {
	if c.CIDR == "" && c.InputFile == "" {
		return fmt.Errorf("either -cidr or -input must be specified")
	}
	if c.CIDR != "" && c.InputFile != "" {
		return fmt.Errorf("-cidr and -input are mutually exclusive")
	}
	if c.Concurrency < 1 {
		return fmt.Errorf("-concurrency must be at least 1")
	}
	if c.Timeout < 100*time.Millisecond {
		return fmt.Errorf("-timeout must be at least 100ms")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("-port must be between 1 and 65535")
	}
	if c.Retries < 0 {
		return fmt.Errorf("-retries must be non-negative")
	}
	if c.Verbose && c.Quiet {
		return fmt.Errorf("-verbose and -quiet are mutually exclusive")
	}
	return nil
}
