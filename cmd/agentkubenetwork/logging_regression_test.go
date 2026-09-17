package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCLIFatalAtEveryLevel(t *testing.T) {
	if level := os.Getenv("AGENT_LOGGING_FATAL_HELPER"); level != "" {
		os.Args = []string{"agentkubenetwork", "-source=invalid", "-log-level=" + level, "-log-interval=0"}
		main()
		return
	}
	for _, level := range []string{"debug", "info", "warn", "error"} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCLIFatalAtEveryLevel$")
		cmd.Env = append(os.Environ(), "AGENT_LOGGING_FATAL_HELPER="+level)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err == nil {
			t.Fatal("fatal exited successfully")
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "agentkubenetwork: unsupported source") {
			t.Fatalf("fatal hidden at %s: %s", level, stderr.String())
		}
	}
}

func TestCLIStdinDefaultJSONLUnchanged(t *testing.T) {
	input, err := os.ReadFile("../../testdata/observations.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var baseline bytes.Buffer
	if err := runArgs(nil, bytes.NewReader(input), &baseline, nil); err != nil {
		t.Fatal(err)
	}
	if baseline.Len() == 0 {
		t.Fatal("fixture produced no windows")
	}
	for _, level := range []string{"debug", "info", "warn", "error"} {
		var output bytes.Buffer
		if err := runArgs([]string{"-stdout=jsonl", "-log-level=" + level, "-log-interval=0"}, bytes.NewReader(input), &output, nil); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(baseline.Bytes(), output.Bytes()) {
			t.Fatal("stdin output changed")
		}
	}
}
