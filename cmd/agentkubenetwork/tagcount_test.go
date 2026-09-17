package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/app"
	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	xio "github.com/whatap/golib/io"
	"github.com/whatap/golib/util/hexa32"
)

func setTagCountTestConfig(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	out := xio.NewDataOutputX()
	out.WriteDecimal(123)
	out.WriteBlob([]byte("0123456789abcdef"))
	data := out.ToByteArray()
	data = append(data, make([]byte, (8-len(data)%8)%8)...)
	in := xio.NewDataInputX(data)
	var tokens []string
	for i := 0; i < len(data); i += 8 {
		tokens = append(tokens, hexa32.ToString32(in.ReadLong()))
	}
	t.Setenv("WHATAP_ACCESSKEY", strings.Join(tokens, "-"))
	t.Setenv("WHATAP_LICENSE", strings.Join(tokens, "-"))
	t.Setenv("WHATAP_SERVER_HOST", "127.0.0.1")
	t.Setenv("WHATAP_SERVER_PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	t.Setenv("WHATAP_OBJECT_NAME", "kube-network-node")
	return listener
}

func TestCLIRejectsInvalidTagCountOptionsBeforeAttaching(t *testing.T) {
	setTagCountTestConfig(t)
	for _, args := range [][]string{
		{"-export=other"},
		{"-export=tagcount", "-source=stdin"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=raw"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-window=61s"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-window=1500us"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-tagcount-queue=0"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-tagcount-queue=16385"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-tagcount-timeout=0"},
		{"-export=tagcount", "-source=ebpf", "-output-mode=windows", "-tagcount-drain-timeout=0"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			opened := false
			err := runArgs(append([]string{"-pod-identity=false"}, args...), strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return nil, io.ErrUnexpectedEOF
			})
			if err == nil || opened {
				t.Fatalf("invalid export settings reached attach: err=%v opened=%v", err, opened)
			}
		})
	}
}

func TestCLITagCountKeyErrorsAreRedactedBeforeAttach(t *testing.T) {
	setTagCountTestConfig(t)
	const secret = "SECRET-must-not-appear-in-error"
	t.Setenv("WHATAP_ACCESSKEY", secret)
	t.Setenv("WHATAP_LICENSE", secret)
	opened := false
	err := runArgs([]string{"-source=ebpf", "-pod-identity=false", "-output-mode=windows", "-export=tagcount"}, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
		opened = true
		return nil, io.ErrUnexpectedEOF
	})
	if err == nil || opened || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe key validation: err=%v opened=%v", err, opened)
	}
}

func TestTagCountRunClosesAndReportsWhenBPFOpenFails(t *testing.T) {
	setTagCountTestConfig(t)
	var summary bytes.Buffer
	config := bpfRunConfig{NodeName: "node", Events: app.EventOptions{OutputMode: "windows", WindowSize: 5 * time.Second}}
	err := runTagCount(context.Background(), io.Discard, &summary, func(collector.OpenOptions) (collector.EventReader, error) {
		return nil, io.ErrUnexpectedEOF
	}, config, tagcountRunOptions{QueueCapacity: 4, Timeout: time.Second, DrainTimeout: time.Second})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("BPF open error lost: %v", err)
	}
	var got tagcount.Summary
	if err := json.Unmarshal(summary.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Stage != "tcp_write" || got.Written != 0 || got.Pending != 0 || got.Queued != 0 {
		t.Fatalf("invented delivery after attach failure: %+v", got)
	}
}

func TestTagCountRunReportsPartialWithoutDialing(t *testing.T) {
	listener := setTagCountTestConfig(t)
	var output, summary bytes.Buffer
	reader := &cliEventReader{}
	config := bpfRunConfig{NodeName: "node", Events: app.EventOptions{OutputMode: "windows", WindowSize: 5 * time.Second, AllowedLateness: time.Second}}
	err := runTagCount(context.Background(), &output, &summary, func(collector.OpenOptions) (collector.EventReader, error) {
		return reader, nil
	}, config, tagcountRunOptions{QueueCapacity: 4, Timeout: time.Second, DrainTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var got tagcount.Summary
	if err := json.Unmarshal(summary.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.SkippedPartial != 1 || got.Written != 0 || got.Queued != 0 || got.Failed != 0 || !reader.closed {
		t.Fatalf("partial-only run: %+v closed=%v", got, reader.closed)
	}
	if !strings.Contains(output.String(), `"partial":true`) {
		t.Fatal("partial window disappeared from diagnostic JSONL")
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("partial-only run opened a backend connection")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("unexpected listener error: %v", err)
	}
}

func TestCLIDefaultDoesNotEnableTagCountFromEnvironment(t *testing.T) {
	t.Setenv("WHATAP_ACCESSKEY", "invalid-should-not-be-read")
	reader := &cliEventReader{}
	err := runArgs([]string{"-source=ebpf", "-pod-identity=false", "-conntrack=false", "-process=false"}, strings.NewReader(""), io.Discard, func(collector.OpenOptions) (collector.EventReader, error) {
		return reader, nil
	})
	if err != nil || !reader.closed {
		t.Fatalf("default behavior changed: %v", err)
	}
}
