package main

import (
	"os"
	"strings"
	"testing"
)

// The tests set every WHATAP_ variable they depend on. A value inherited from
// the shell would be parsed by tests that never mention it, and a licence or
// server address could point a test at a real collector.
func TestMain(m *testing.M) {
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); strings.HasPrefix(name, "WHATAP_") {
			if err := os.Unsetenv(name); err != nil {
				panic(err)
			}
		}
	}
	os.Exit(m.Run())
}
