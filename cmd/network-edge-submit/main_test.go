package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSummaryAndInvalidJSON(t *testing.T) {
	var out, errs bytes.Buffer
	input := `{"schemaVersion":"network.coverage/v0"}
{"schemaVersion":"network.flow/v1alpha1","partial":true}
{"schemaVersion":"network.flow/v1alpha1"}
`
	if n := run([]string{"-address", "127.0.0.1:12345"}, strings.NewReader(input), &out, &errs); n != 0 {
		t.Fatal(n, errs.String())
	}
	for _, s := range []string{`"accepted":0`, `"skipped_partial":1`, `"skipped_unmeasured":1`, `"ignored":1`, `"stage":"node_queue"`} {
		if !strings.Contains(out.String(), s) {
			t.Fatal(out.String(), s)
		}
	}
	for _, s := range []string{`{`, `{}`, `{"schemaVersion":"network.window/v1"}`, `null`} {
		if run([]string{"-address", "127.0.0.1:12345"}, strings.NewReader(s), &out, &errs) == 0 {
			t.Fatal("accepted malformed", s)
		}
	}
}
