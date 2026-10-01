package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigurationRejectsAmbiguousOrIncompleteInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	for _, input := range []string{
		`{}`,
		`{"unexpected":true}`,
		`{"source":"https://agents.example.com"}{"source":"https://other.example.com"}`,
		strings.Repeat(" ", 65537),
	} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readConfig(path); err == nil {
			t.Fatalf("accepted invalid configuration: %q", input[:min(len(input), 100)])
		}
	}
}

func TestClientFingerprintMappingRejectsAmbiguity(t *testing.T) {
	valid := strings.Repeat("a", 64)
	if _, err := actors(map[string]string{valid: "controller"}); err != nil {
		t.Fatal(err)
	}
	for _, input := range []map[string]string{
		{valid: ""},
		{"not-hex": "controller"},
		{valid: "controller", strings.ToUpper(valid): "other"},
	} {
		if _, err := actors(input); err == nil {
			t.Fatal("accepted invalid certificate mapping")
		}
	}
}

func TestInspectorFingerprintIsDistinctFromWriters(t *testing.T) {
	writer := strings.Repeat("a", 64)
	reader := strings.Repeat("b", 64)
	writers, err := actors(map[string]string{writer: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	if pins, err := inspectors([]string{reader}, writers); err != nil || len(pins) != 1 {
		t.Fatalf("valid inspector certificate rejected: %v", err)
	}
	for _, values := range [][]string{{writer}, {reader, strings.ToUpper(reader)}, {"not-hex"}} {
		if _, err := inspectors(values, writers); err == nil {
			t.Fatal("accepted ambiguous inspector certificate")
		}
	}
}
