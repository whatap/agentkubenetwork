package app

import (
	"errors"
	"fmt"
	"time"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/agentkubenetwork/internal/topology"
)

// The event pipeline is the single owner of the bounded summary accumulator.
// Transactions already carry request-time identity snapshots; never enrich them
// again while producing a summary at response/flush time.
func (e *eventOutput) observeTopology(record any) error {
	if e.topology == nil {
		return nil
	}
	var err error
	switch value := record.(type) {
	case l7.Transaction:
		err = e.topology.ObserveL7(value)
	case *l7.Transaction:
		err = e.topology.ObserveL7(*value) // exportTyped has rejected nil.
	case dns.Transaction:
		err = e.topology.ObserveDNS(value)
	case *dns.Transaction:
		err = e.topology.ObserveDNS(*value)
	}
	if err != nil {
		return fmt.Errorf("aggregate topology observation: %w", err)
	}
	return nil
}

// exportTopology hands the summaries of closed windows to the exporter. The
// exporter never waits for queue room, so a summary it has no room for stays
// in the backlog, in order, and is offered again on the next flush. A window is
// exported whole or the run stops with an error; it is never thinned silently.
// last marks the window flushed at shutdown.
func (e *eventOutput) exportTopology(summaries []topology.Summary, last bool) error {
	for _, summary := range summaries {
		// Preserve a removed batch in diagnostic JSONL even if its remote export
		// fails. No record in this batch is retried under a different identity.
		record := struct {
			SchemaVersion string `json:"schemaVersion"`
			topology.Summary
		}{topology.SchemaVersion, summary}
		if err := e.queuedOutput.Encode(record); err != nil {
			return err
		}
	}
	// An exporter that cannot keep up must stop the run instead of letting the
	// backlog grow: it may hold at most as many summaries as the aggregator.
	// Nothing follows the last window, so it joins whatever still waits and the
	// shutdown wait decides.
	if waiting := len(e.topologyBacklog) + len(summaries); !last && waiting > e.topologyLimit {
		e.exportFailure = fmt.Errorf("export topology summary: %d summaries wait for the export queue, more than the topology entry bound %d", waiting, e.topologyLimit)
		return e.exportFailure
	}
	e.topologyBacklog = append(e.topologyBacklog, summaries...)
	return e.offerTopologyBacklog(e.topologyBurst)
}

// offerTopologyBacklog offers the waiting summaries in order until the exporter
// has no room or share summaries are queued. A running flush passes its share
// (topologyBurst), which leaves queue room for the detailed records; a share
// that is not positive is no bound. Having no room is not an error; any other
// rejection is terminal.
func (e *eventOutput) offerTopologyBacklog(share int) error {
	exporter := e.exporter.(TopologyExporter) // validated before starting output.
	queued := 0
	var err error
	for queued < len(e.topologyBacklog) && (share <= 0 || queued < share) {
		if err = exporter.ExportTopology(e.topologyBacklog[queued]); err != nil {
			break
		}
		queued++
	}
	rest := copy(e.topologyBacklog, e.topologyBacklog[queued:])
	clear(e.topologyBacklog[rest:])
	e.topologyBacklog = e.topologyBacklog[:rest]
	if rest == 0 {
		e.topologyBacklog = nil // do not keep the storage of a large window
	}
	if err == nil || errors.Is(err, topology.ErrNotQueued) {
		return nil
	}
	e.exportFailure = fmt.Errorf("export topology summary: %w", err)
	return e.exportFailure
}

// drainTopologyBacklog runs at shutdown, when no later flush will offer the
// backlog again and no detailed record competes for the queue, so it offers as
// much as the queue takes. It waits for queue room, bounded by the output drain
// timeout, and reports the summaries it could not queue instead of dropping them.
func (e *eventOutput) drainTopologyBacklog() error {
	deadline := time.Now().Add(e.drainTimeout)
	for len(e.topologyBacklog) > 0 {
		if !time.Now().Before(deadline) {
			e.exportFailure = fmt.Errorf("export topology summary: %d summaries were not queued within the %s output drain timeout", len(e.topologyBacklog), e.drainTimeout)
			e.topologyBacklog = nil // counted here; nothing offers them again
			return e.exportFailure
		}
		time.Sleep(time.Millisecond)
		if err := e.offerTopologyBacklog(0); err != nil {
			return err
		}
	}
	return nil
}

// topologyLeftBehind counts, after a terminal export failure, the summaries that
// will never be offered: those that waited and the windows still open.
func (e *eventOutput) topologyLeftBehind() error {
	if n := len(e.topologyBacklog) + len(e.topology.FlushAll()); n > 0 {
		return fmt.Errorf("export topology summary: %d summaries were not exported after the export failed", n)
	}
	return nil
}
