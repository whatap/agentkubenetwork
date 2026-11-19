package tagcount

import "github.com/whatap/agentkubenetwork/internal/topology"

// ExportTopology snapshots presence evidence through the shared bounded queue.
// It deliberately adds neither observer identity nor a per-record ID: repeated
// and cross-observer evidence for a relationship/bucket must remain MAX-safe.
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
	e.enqueueLocked(p)
	return nil
}
