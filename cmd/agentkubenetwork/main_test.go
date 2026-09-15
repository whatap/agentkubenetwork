package main

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/flow"
)

type cliEventReader struct {
	read   bool
	closed bool
}

func (r *cliEventReader) Read() (collector.Event, error) {
	if r.read {
		return collector.Event{}, io.EOF
	}
	r.read = true
	return collector.Event{Kind: collector.EventKindConnect, TimestampNS: 123, Family: collector.AddressFamilyIPv4, Protocol: collector.ProtocolTCP, OldState: collector.TCPStateSynSent, NewState: collector.TCPStateEstablished, SourcePort: 41000, DestinationPort: 8080, SourceAddress: [16]byte{10, 0, 0, 1}, DestinationAddress: [16]byte{10, 0, 0, 2}}, nil
}
func (r *cliEventReader) Close() error { r.closed = true; return nil }

type idleCLIReader struct {
	first cliEventReader
	stop  chan struct{}
	once  sync.Once
}

func (r *idleCLIReader) Read() (collector.Event, error) {
	if !r.first.read {
		return r.first.Read()
	}
	<-r.stop
	return collector.Event{}, io.EOF
}
func (r *idleCLIReader) Close() error { r.once.Do(func() { close(r.stop) }); return nil }

func TestCLIDurationFlushesAndInterruptsIdleReader(t *testing.T) {
	reader := &idleCLIReader{stop: make(chan struct{})}
	var output bytes.Buffer
	open := func(collector.OpenOptions) (collector.EventReader, error) { return reader, nil }
	if err := runArgs([]string{"-source=ebpf", "-output-mode=windows", "-duration=100ms", "-conntrack=false", "-process=false"}, bytes.NewReader(nil), &output, open); err != nil {
		t.Fatal(err)
	}
	var window flow.Window
	if err := json.NewDecoder(&output).Decode(&window); err != nil {
		t.Fatal(err)
	}
	if window.ObservationCount != 1 || !window.Partial {
		t.Fatalf("shutdown lost or overstated the window: %+v", window)
	}
	select {
	case <-reader.stop:
	default:
		t.Fatal("idle reader not interrupted")
	}
}

func TestCLIRejectsInvalidConfigurationBeforeAttaching(t *testing.T) {
	for _, arg := range []string{"-output-mode=invalid", "-window=0", "-allowed-lateness=-1s", "-max-windows=-1", "-output-queue=-1", "-output-drain-timeout=-1s", "-max-events=-1"} {
		t.Run(arg, func(t *testing.T) {
			opened := false
			open := func(collector.OpenOptions) (collector.EventReader, error) {
				opened = true
				return nil, io.ErrUnexpectedEOF
			}
			err := runArgs([]string{"-source=ebpf", arg}, bytes.NewReader(nil), io.Discard, open)
			if err == nil || opened {
				t.Fatalf("invalid config reached kernel attach: err=%v opened=%v", err, opened)
			}
		})
	}
}

func TestCLIWiresWindowSizeIntoRealEventPath(t *testing.T) {
	reader := &cliEventReader{}
	var output bytes.Buffer
	open := func(options collector.OpenOptions) (collector.EventReader, error) { return reader, nil }
	err := runArgs([]string{"-source=ebpf", "-node-name=node", "-output-mode=windows", "-window=100ms", "-conntrack=false", "-process=false"}, bytes.NewReader(nil), &output, open)
	if err != nil {
		t.Fatal(err)
	}
	var window flow.Window
	if err := json.NewDecoder(&output).Decode(&window); err != nil {
		t.Fatal(err)
	}
	if window.WindowEnd.Sub(window.WindowStart) != 100*time.Millisecond || window.ObservationCount != 1 || window.Flow.NodeName != "node" {
		t.Fatalf("CLI window options were not applied: %+v", window)
	}
	if !reader.closed {
		t.Fatal("BPF reader not closed")
	}
}
