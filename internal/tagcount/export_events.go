package tagcount

import (
	"errors"
	"strconv"

	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/l7"
	"github.com/whatap/golib/lang/pack"
)

// ExportL7 snapshots one HTTP observation through the same bounded queue as L4.
// Observations from different observer processes are not unique fleet requests.
func (e *Exporter) ExportL7(transaction l7.Transaction) error {
	return e.exportEvent(transaction.Flow.NodeName, func() (*pack.TagCountPack, error) {
		return PackForL7(transaction, e.pcode, e.oid)
	})
}

// ExportDNS keeps an absent response distinct from a measured zero latency.
func (e *Exporter) ExportDNS(transaction dns.Transaction) error {
	return e.exportEvent(transaction.NodeName, func() (*pack.TagCountPack, error) {
		return PackForDNS(transaction, e.pcode, e.oid)
	})
}

// ExportL7Drop exports collector/correlation coverage, not a request failure.
func (e *Exporter) ExportL7Drop(drop l7.Drop) error {
	return e.exportEvent(drop.NodeName, func() (*pack.TagCountPack, error) {
		return PackForL7Drop(drop, e.pcode, e.oid)
	})
}

func (e *Exporter) exportEvent(node string, build func() (*pack.TagCountPack, error)) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return ErrClosed
	}
	if e.err != nil {
		return e.err
	}
	if node != e.config.NodeName {
		return errors.New("event observer node does not match tagcount exporter")
	}
	p, err := build()
	if err != nil {
		return err
	}
	e.enqueueLocked(p)
	return nil
}

// enqueueLocked never waits for network I/O or queue space. The caller owns mu.
func (e *Exporter) enqueueLocked(p *pack.TagCountPack) {
	// A single input fragment can produce indistinguishable coverage records.
	// Preserve those observations instead of assigning one storage identity to
	// all of them. Include dropped attempts in the ordinal; never reuse it.
	if id := p.Tags.GetString("record_id"); id != "" {
		p.Tags.PutString("record_id", id+"."+strconv.FormatUint(e.summary.Queued+e.summary.Dropped+1, 10))
	}
	select {
	case e.queue <- p:
		e.summary.Queued++
	default:
		e.summary.Dropped++
	}
}
