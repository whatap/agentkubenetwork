package app

import (
	"errors"
	"fmt"

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

func (e *eventOutput) exportTopology(summaries []topology.Summary) error {
	exporter := e.exporter.(TopologyExporter) // validated before starting output.
	var firstErr error
	for _, summary := range summaries {
		// Preserve a removed batch in diagnostic JSONL even if its remote export
		// fails. No record in this batch is retried under a different identity.
		record := struct {
			SchemaVersion string `json:"schemaVersion"`
			topology.Summary
		}{topology.SchemaVersion, summary}
		if err := e.queuedOutput.Encode(record); err != nil {
			return errors.Join(firstErr, err)
		}
		if e.exportFailure == nil {
			if err := exporter.ExportTopology(summary); err != nil {
				firstErr = fmt.Errorf("export topology summary: %w", err)
				e.exportFailure = firstErr
			}
		}
	}
	return firstErr
}
