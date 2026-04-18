package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of scanning a single host.
type ScanResult struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	IsReality   bool      `json:"is_reality"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// OutputWriter handles writing scan results to various formats.
type OutputWriter struct {
	mu         sync.Mutex
	format     string
	file       *os.File
	csvWriter  *csv.Writer
	results    []ScanResult
	headerDone bool
}

// NewOutputWriter creates a new OutputWriter for the given format and file path.
// Supported formats: "json", "csv", "text".
// If filePath is empty, output is written to stdout.
func NewOutputWriter(format, filePath string) (*OutputWriter, error) {
	var f *os.File
	var err error

	if filePath == "" {
		f = os.Stdout
	} else {
		f, err = os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file: %w", err)
		}
	}

	ow := &OutputWriter{
		format:  format,
		file:    f,
		results: make([]ScanResult, 0, 64),
	}

	if format == "csv" {
		ow.csvWriter = csv.NewWriter(f)
	}

	return ow, nil
}

// Write appends a ScanResult to the output.
func (ow *OutputWriter) Write(result ScanResult) error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	switch ow.format {
	case "json":
		ow.results = append(ow.results, result)
	case "csv":
		if !ow.headerDone {
			header := []string{"ip", "port", "is_reality", "fingerprint", "country", "asn", "scanned_at", "error"}
			if err := ow.csvWriter.Write(header); err != nil {
				return err
			}
			ow.headerDone = true
		}
		row := []string{
			result.IP,
			fmt.Sprintf("%d", result.Port),
			fmt.Sprintf("%v", result.IsReality),
			result.Fingerprint,
			result.Country,
			result.ASN,
			result.ScannedAt.Format(time.RFC3339),
			result.Error,
		}
		if err := ow.csvWriter.Write(row); err != nil {
			return err
		}
		ow.csvWriter.Flush()
	default: // text
		if result.IsReality {
			fmt.Fprintf(ow.file, "[+] REALITY %s:%d | country=%s asn=%s fingerprint=%s\n",
				result.IP, result.Port, result.Country, result.ASN, result.Fingerprint)
		} else if result.Error != "" {
			fmt.Fprintf(ow.file, "[-] ERR    %s:%d | %s\n", result.IP, result.Port, result.Error)
		} else {
			fmt.Fprintf(ow.file, "[ ] plain  %s:%d | country=%s asn=%s\n",
				result.IP, result.Port, result.Country, result.ASN)
		}
	}
	return nil
}

// Close finalises the output (flushes JSON array, closes file).
func (ow *OutputWriter) Close() error {
	ow.mu.Lock()
	defer ow.mu.Unlock()

	if ow.format == "json" {
		enc := json.NewEncoder(ow.file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ow.results); err != nil {
			return err
		}
	}

	if ow.file != os.Stdout {
		return ow.file.Close()
	}
	return nil
}
