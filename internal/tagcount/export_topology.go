package tagcount

import "github.com/whatap/agentkubenetwork/internal/topology"

// ExportTopology snapshots presence evidence through the shared bounded queue.
// It deliberately adds neither observer identity nor a per-record ID: repeated
// and cross-observer evidence for a relationship/bucket must remain MAX-safe.
//
// A full queue must not thin a summary window silently, so it is not counted as
// loss here: ErrNotQueued leaves the summary with the caller, which offers it
// again. Detailed records keep their counted overflow.
func (e *Exporter) ExportTopology(s topology.Summary) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	p, err := PackForTopology(s, e.pcode, e.oid)
	if err != nil {
		return err
	}
	if !e.offerLocked(p) {
		return topology.ErrNotQueued
	}
	return nil
}

// TopologyBurst is how many summaries one flush may queue. A closed window is
// handed over as one burst; taking half of the queue at a time leaves room for
// the detailed records that arrive with it.
func (e *Exporter) TopologyBurst() int { return max(1, cap(e.queue)/2) }
