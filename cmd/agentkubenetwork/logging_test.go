package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/whatap/agentkubenetwork/internal/collector"
)

func TestCLIStdoutSelection(t *testing.T) {
	setTagCountTestConfig(t)
	for _, export := range []string{"none", "tagcount"} {
		for _, mode := range []string{"raw", "windows", "both"} {
			if export == "tagcount" && mode == "raw" {
				continue
			}
			for _, stdout := range []string{"auto", "jsonl", "none"} {
				t.Run(export+"/"+mode+"/"+stdout, func(t *testing.T) {
					var output bytes.Buffer
					opened := false
					err := runArgs([]string{"-source=ebpf", "-pod-identity=false", "-conntrack=false", "-process=false", "-export=" + export, "-output-mode=" + mode, "-stdout=" + stdout}, strings.NewReader(""), &output, func(collector.OpenOptions) (collector.EventReader, error) {
						opened = true
						return &cliEventReader{}, nil
					})
					if stdout == "none" && export == "none" {
						if err == nil || opened {
							t.Fatalf("sole sink disabled: %v opened=%v", err, opened)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					wantOutput := stdout == "jsonl" || stdout == "auto" && export == "none"
					if (output.Len() > 0) != wantOutput {
						t.Fatalf("stdout bytes=%d, want output=%v", output.Len(), wantOutput)
					}
				})
			}
		}
	}
}

type forbiddenInput struct{ t *testing.T }

func (r forbiddenInput) Read([]byte) (int, error) {
	r.t.Fatal("invalid flags read stdin")
	return 0, io.EOF
}
func TestCLIStdoutInvalidBeforeIO(t *testing.T) {
	for _, value := range []string{"", "JSONL", "bogus", "none"} {
		err := runArgs([]string{"-stdout=" + value}, forbiddenInput{t}, io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
			t.Fatal("invalid flags attached")
			return nil, io.EOF
		})
		if err == nil {
			t.Fatalf("accepted stdout=%q", value)
		}
	}
}
