package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/tagcount"
	"github.com/whatap/agentkubenetwork/internal/topology"
	"github.com/whatap/golib/lang/pack"
)

// roomTopologyExporter accepts a summary only while it has room, like the
// bounded TagCount queue. A refused summary is not recorded as exported.
type roomTopologyExporter struct {
	recordingTypedExporter
	room      int // summaries accepted before refusing; negative is unlimited
	refusals  int
	freeAfter int // when positive, room becomes unlimited after this many refusals
	summaries []topology.Summary
}

func (e *roomTopologyExporter) ExportTopology(s topology.Summary) error {
	if e.room == 0 && e.freeAfter > 0 && e.refusals >= e.freeAfter {
		e.room = -1
	}
	if e.room == 0 {
		e.refusals++
		return topology.ErrNotQueued
	}
	if e.room > 0 {
		e.room--
	}
	e.summaries = append(e.summaries, s)
	return nil
}

var backlogTestStart = time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)

// backlogTestHTTP is one relationship per destination: 10.0.1.<destination>.
func backlogTestHTTP(at time.Time, destination int) any {
	tx := topologyTestHTTP(at)
	tx.Flow.Destination.Address = fmt.Sprintf("10.0.1.%d", destination)
	return tx
}

func backlogDestinations(summaries []topology.Summary) string {
	addresses := make([]string, len(summaries))
	for i, s := range summaries {
		addresses[i] = s.Destination.Address
	}
	return strings.Join(addresses, " ")
}

func TestTopologyWindowLargerThanTheQueueIsExportedWhole(t *testing.T) {
	exporter := &roomTopologyExporter{room: 2}
	var output bytes.Buffer
	encoder, err := newEventOutput(&output, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 5; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	closed := backlogTestStart.Add(time.Minute)
	for _, step := range []struct {
		room int
		want string
	}{
		{0, "10.0.1.1 10.0.1.2"}, // the exporter had room for two
		{0, "10.0.1.1 10.0.1.2"}, // a full queue is neither an error nor a loss
		{1, "10.0.1.1 10.0.1.2 10.0.1.3"},
		{10, "10.0.1.1 10.0.1.2 10.0.1.3 10.0.1.4 10.0.1.5"},
		{10, "10.0.1.1 10.0.1.2 10.0.1.3 10.0.1.4 10.0.1.5"}, // nothing is sent twice
	} {
		exporter.room += step.room
		if err := encoder.Flush(closed); err != nil {
			t.Fatalf("a full export queue stopped the run: %v", err)
		}
		if got := backlogDestinations(exporter.summaries); got != step.want {
			t.Fatalf("exported %q; want %q", got, step.want)
		}
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	if len(exporter.summaries) != 5 {
		t.Fatalf("shutdown changed the exported window: %q", backlogDestinations(exporter.summaries))
	}
	// Waiting for room must not repeat the diagnostic record of a summary.
	if got := strings.Count(output.String(), `"schemaVersion":"`+topology.SchemaVersion+`"`); got != 5 {
		t.Fatalf("diagnostic output has %d summary records; want 5", got)
	}
}

func TestTopologyBacklogBeyondMaxEntriesStopsTheRun(t *testing.T) {
	exporter := &roomTopologyExporter{} // never has room
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 2
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, options)
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 2; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Flush(backlogTestStart.Add(time.Minute)); err != nil {
		t.Fatalf("a window that fits the bound must wait, not fail: %v", err)
	}
	if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Minute+time.Second), 3)); err != nil {
		t.Fatal(err)
	}
	err = encoder.Flush(backlogTestStart.Add(2 * time.Minute))
	if err == nil || !strings.Contains(err.Error(), "wait for the export queue") {
		t.Fatalf("an export that cannot keep up must stop the run: %v", err)
	}
	if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(2*time.Minute+time.Second), 4)); err == nil {
		t.Fatal("the run continued after the summary backlog overflowed")
	}
	_ = encoder.Close()
	if len(exporter.summaries) != 0 {
		t.Fatalf("exported without room: %q", backlogDestinations(exporter.summaries))
	}
}

func closeWithin(t *testing.T, encoder *eventOutput, limit time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- encoder.Close() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("Close did not return within %v", limit)
		return nil
	}
}

func TestTopologyShutdownWaitsForQueueRoom(t *testing.T) {
	exporter := &roomTopologyExporter{room: 1, freeAfter: 3}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 4; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := closeWithin(t, encoder, 5*time.Second); err != nil {
		t.Fatalf("shutdown gave up on a queue that drained: %v", err)
	}
	if got := backlogDestinations(exporter.summaries); got != "10.0.1.1 10.0.1.2 10.0.1.3 10.0.1.4" || exporter.refusals != 3 {
		t.Fatalf("exported %q after %d refusals; want the whole window after 3", got, exporter.refusals)
	}
}

// The bound on waiting summaries stops an exporter that cannot keep up while
// windows keep closing. Nothing follows the last window, so at shutdown it joins
// the summaries that still wait instead of being refused for their sake.
func TestTopologyShutdownHandsOverTheLastWindowBehindTheBacklog(t *testing.T) {
	exporter := &roomTopologyExporter{room: 1, freeAfter: 3}
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 4
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, options)
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 4; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Flush(backlogTestStart.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := backlogDestinations(exporter.summaries); got != "10.0.1.1" {
		t.Fatalf("exported %q; want one summary queued and three waiting", got)
	}
	for destination := 5; destination <= 7; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(2*time.Minute+time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := closeWithin(t, encoder, 5*time.Second); err != nil {
		t.Fatalf("shutdown refused the last window: %v", err)
	}
	if got := backlogDestinations(exporter.summaries); got != "10.0.1.1 10.0.1.2 10.0.1.3 10.0.1.4 10.0.1.5 10.0.1.6 10.0.1.7" {
		t.Fatalf("exported %q; want both windows whole and in order", got)
	}
}

// burstRoomExporter also tells the pipeline how many summaries one flush may
// queue, like the TagCount exporter does.
type burstRoomExporter struct {
	roomTopologyExporter
	burst int
}

func (e *burstRoomExporter) TopologyBurst() int { return e.burst }

// The per-flush share leaves queue room for the detailed records that arrive
// while collection runs. At shutdown no detailed record follows, so the wait
// hands over as much as the queue takes instead of one share per pass.
func TestTopologyShutdownDrainIsNotPacedByTheFlushShare(t *testing.T) {
	exporter := &burstRoomExporter{roomTopologyExporter: roomTopologyExporter{room: -1}, burst: 1}
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 256
	options.OutputDrainTimeout = 30 * time.Millisecond
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, options)
	if err != nil {
		t.Fatal(err)
	}
	const relationships = 200
	for destination := 1; destination <= relationships; destination++ {
		tx := topologyTestHTTP(backlogTestStart.Add(time.Second))
		tx.Flow.Destination.Address = fmt.Sprintf("10.0.%d.%d", destination/250, destination%250+1)
		if err := encoder.Encode(tx); err != nil {
			t.Fatal(err)
		}
	}
	if err := closeWithin(t, encoder, 5*time.Second); err != nil {
		t.Fatalf("the shutdown wait was paced like a running flush: %v", err)
	}
	if len(exporter.summaries) != relationships {
		t.Fatalf("exported %d summaries; want %d", len(exporter.summaries), relationships)
	}
}

// Only a positive share bounds a flush. A share that is not positive must not
// stop every offer.
func TestTopologyNonPositiveShareDoesNotBoundAFlush(t *testing.T) {
	exporter := &burstRoomExporter{roomTopologyExporter: roomTopologyExporter{room: -1}, burst: -1}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 3; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Flush(backlogTestStart.Add(2 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := backlogDestinations(exporter.summaries); got != "10.0.1.1 10.0.1.2 10.0.1.3" {
		t.Fatalf("exported %q; want the whole window in one flush", got)
	}
	_ = encoder.Close()
}

// One flush can hand over one share per collection tick. A share so small that
// a window's ticks cannot hand over the entry bound would stop the run once
// the summaries pile up, so it is refused when the pipeline starts.
func TestTopologyRefusesAQueueTooSmallForTheEntryBound(t *testing.T) {
	for _, tc := range []struct {
		burst int
		ok    bool
	}{{1, false}, {2, true}} {
		exporter := &burstRoomExporter{roomTopologyExporter: roomTopologyExporter{room: -1}, burst: tc.burst}
		options := topologyTestOptions(exporter)
		options.Topology.MaxEntries = 4096 // one minute has 2400 ticks of 25 ms
		_, err := newEventOutput(io.Discard, "node", time.Now, options)
		if tc.ok && err != nil {
			t.Fatalf("share %d: %v", tc.burst, err)
		}
		if !tc.ok && (err == nil || !strings.Contains(err.Error(), "queue is too small")) {
			t.Fatalf("share %d: a queue that cannot keep up with the entry bound was accepted: %v", tc.burst, err)
		}
	}
}

// After a terminal export failure nothing is offered again. Shutdown says how
// many summaries were left waiting instead of returning without a word.
func TestTopologyShutdownCountsSummariesLeftBehindByAFailedExport(t *testing.T) {
	exporter := &failingTopologyExporter{room: 1, err: errors.New("collector connection lost")}
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, topologyTestOptions(exporter))
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 3; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	if err := encoder.Flush(backlogTestStart.Add(2 * time.Minute)); err == nil || !strings.Contains(err.Error(), "collector connection lost") {
		t.Fatalf("the failed export did not stop the flush: %v", err)
	}
	err = closeWithin(t, encoder, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "2 summaries were not exported") {
		t.Fatalf("shutdown hid the summaries left behind: %v", err)
	}
}

// failingTopologyExporter accepts room summaries and then fails for good.
type failingTopologyExporter struct {
	recordingTypedExporter
	room int
	err  error
}

func (e *failingTopologyExporter) ExportTopology(topology.Summary) error {
	if e.room == 0 {
		return e.err
	}
	e.room--
	return nil
}

func TestTopologyShutdownReportsSummariesItCouldNotQueue(t *testing.T) {
	exporter := &roomTopologyExporter{room: 1} // one summary, then never again
	options := topologyTestOptions(exporter)
	options.OutputDrainTimeout = 20 * time.Millisecond
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return backlogTestStart.Add(time.Second) }, options)
	if err != nil {
		t.Fatal(err)
	}
	for destination := 1; destination <= 3; destination++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(time.Second), destination)); err != nil {
			t.Fatal(err)
		}
	}
	err = closeWithin(t, encoder, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "2 summaries were not queued") {
		t.Fatalf("shutdown hid summaries it could not queue: %v", err)
	}
	if got := backlogDestinations(exporter.summaries); got != "10.0.1.1" {
		t.Fatalf("exported %q; want only the summary that had room", got)
	}
}

// The real bounded exporter is exercised here: 40 relationships close in one
// window while the queue holds 4. Connect observations carry no SRTT sample, so
// the detail exporter skips their windows and only summaries use the queue.
func TestTopologyWindowLargerThanTheRealQueueReachesTheWire(t *testing.T) {
	sender := &topologyWireSender{}
	exporter, err := tagcount.NewExporter(sender, tagcount.ExporterConfig{NodeName: "node", QueueCapacity: 4, DrainTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exporter.Close() })
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 64
	at := backlogTestStart.Add(time.Second)
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at.Add(time.Second) }, options)
	if err != nil {
		t.Fatal(err)
	}
	const relationships = 40
	for i := 1; i <= relationships; i++ {
		observation := flow.Observation{ObservedAt: at, Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "egress",
			Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: fmt.Sprintf("10.0.2.%d", i), Port: 8080}}}
		if err := encoder.Encode(observation); err != nil {
			t.Fatal(err)
		}
	}
	if err := closeWithin(t, encoder, 10*time.Second); err != nil {
		t.Fatalf("the window was not handed over whole: %v", err)
	}
	// RunEventsWithOptions owns the exporter's drain after eventOutput closes.
	if err := exporter.Close(); err != nil {
		t.Fatalf("the exporter lost records: %v", err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	peers := map[string]int{}
	for _, wire := range sender.frames {
		p, ok := pack.ToPack(wire).(*pack.TagCountPack)
		if !ok || p.Category != tagcount.TopologyCategory {
			t.Fatalf("unexpected record on the wire: %v", p)
		}
		for _, side := range []string{"src_address", "dst_address"} {
			if address := p.Tags.GetString(side); address != "10.0.0.1" {
				peers[address]++
			}
		}
	}
	if len(sender.frames) != relationships || len(peers) != relationships {
		t.Fatalf("wire carried %d summaries for %d peers; want %d for %d", len(sender.frames), len(peers), relationships, relationships)
	}
	if summary := exporter.Snapshot(); summary.Dropped != 0 || summary.Failed != 0 || summary.Pending != 0 || summary.Written != relationships {
		t.Fatalf("queue accounting: %+v", summary)
	}
}

// gatedWireSender holds every record until the gate opens, like a collector
// connection that has not taken anything from the queue yet.
type gatedWireSender struct {
	topologyWireSender
	gate chan struct{}
}

func (s *gatedWireSender) Send(ctx context.Context, p *pack.TagCountPack) error {
	select {
	case <-s.gate:
		return s.topologyWireSender.Send(ctx, p)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A closed window arrives as one burst. One flush queues at most half of the
// send queue, so the detailed records that arrive with the burst still find
// room; the rest of the window follows on later flushes.
func TestTopologyBurstLeavesQueueRoomForDetailRecords(t *testing.T) {
	sender := &gatedWireSender{gate: make(chan struct{})}
	exporter, err := tagcount.NewExporter(sender, tagcount.ExporterConfig{NodeName: "node", QueueCapacity: 16, DrainTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	release := sync.OnceFunc(func() { close(sender.gate) })
	t.Cleanup(func() { release(); _ = exporter.Close() })
	options := topologyTestOptions(exporter)
	options.Topology.MaxEntries = 64
	at := backlogTestStart.Add(time.Second)
	encoder, err := newEventOutput(io.Discard, "node", func() time.Time { return at }, options)
	if err != nil {
		t.Fatal(err)
	}
	const relationships, details = 40, 6
	for i := 1; i <= relationships; i++ {
		observation := flow.Observation{ObservedAt: at, Flow: flow.FlowKey{NodeName: "node", Protocol: "tcp", Direction: "egress",
			Source: flow.Endpoint{Address: "10.0.0.1", Port: 40000}, Destination: flow.Endpoint{Address: fmt.Sprintf("10.0.2.%d", i), Port: 8080}}}
		if err := encoder.Encode(observation); err != nil {
			t.Fatal(err)
		}
	}
	// The first flush closes the detail windows, the second the summary window.
	for _, watermark := range []time.Duration{10 * time.Second, 2 * time.Minute} {
		if err := encoder.Flush(backlogTestStart.Add(watermark)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i <= details; i++ {
		if err := encoder.Encode(backlogTestHTTP(backlogTestStart.Add(2*time.Minute), i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := exporter.Snapshot(); got.Dropped != 0 {
		t.Fatalf("the summary burst left no queue room for %d detailed records: %+v", got.Dropped, got)
	}
	release()
	if err := closeWithin(t, encoder, 10*time.Second); err != nil {
		t.Fatalf("the window was not handed over whole: %v", err)
	}
	if err := exporter.Close(); err != nil {
		t.Fatalf("the exporter lost records: %v", err)
	}
	sender.mu.Lock()
	defer sender.mu.Unlock()
	categories := map[string]int{}
	for _, wire := range sender.frames {
		p, ok := pack.ToPack(wire).(*pack.TagCountPack)
		if !ok {
			t.Fatal("invalid TagCount wire")
		}
		categories[p.Category]++
	}
	// Each detailed HTTP record is also one relationship of the next window.
	if categories[tagcount.TopologyCategory] != relationships+details || categories[tagcount.HTTPCategory] != details || len(categories) != 2 {
		t.Fatalf("wire carried %v; want %d summaries and %d HTTP records", categories, relationships+details, details)
	}
}
