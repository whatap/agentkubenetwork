package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/whatap/agentkubenetwork/internal/collector"
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

// DestinationResolver translates an original (pre-NAT) flow tuple into the
// NAT-rewritten backend endpoint, reporting the resolution mechanism.
type DestinationResolver interface {
	Resolve(protocol string, source, destination flow.Endpoint) (flow.Endpoint, string, bool)
}

// ProcessResolver turns the kernel-reported host PID into process identity
// (comm, cmdline, container ID). A false result means only the bare PID is
// known; callers must not fabricate identity in that case.
type ProcessResolver interface {
	Lookup(pid uint32) (flow.Process, bool)
}

type EventOptions struct {
	OutputMode          string
	WindowSize          time.Duration
	AllowedLateness     time.Duration
	MaxWindows          int
	OutputQueueCapacity int
	OutputDrainTimeout  time.Duration
}

func RunEvents(reader collector.EventReader, output io.Writer, nodeName string, maxEvents int, now func() time.Time, resolver DestinationResolver, processes ProcessResolver) error {
	return RunEventsWithOptions(context.Background(), reader, output, nodeName, maxEvents, now, resolver, processes, EventOptions{})
}

func RunEventsWithOptions(ctx context.Context, reader collector.EventReader, output io.Writer, nodeName string, maxEvents int, now func() time.Time, resolver DestinationResolver, processes ProcessResolver, options EventOptions) (retErr error) {
	if ctx == nil {
		return errors.New("context is required")
	}
	if maxEvents < 0 {
		return errors.New("max events must not be negative")
	}
	if now == nil {
		return errors.New("wall clock is required")
	}

	encoder, err := newEventOutput(output, nodeName, now, options)
	if err != nil {
		return err
	}
	var readErr error
	defer func() { retErr = errors.Join(readErr, retErr, encoder.Close()) }()
	correlator := l7.NewCorrelator(l7.Config{})
	dnsCorrelator := dns.NewCorrelator(0)
	defer func() {
		for _, transaction := range dnsCorrelator.Finish(encoder.captureTime()) {
			if err := encoder.Encode(transaction); err != nil {
				retErr = errors.Join(retErr, err)
				break
			}
		}
	}()
	stream, cancel, capture := pumpEvents(reader, maxEvents, now)
	encoder.captureTime = capture.time
	defer cancel()
	ticker := time.NewTicker(resolutionRetryInterval)
	defer ticker.Stop()
	pending := make([]pendingResolution, 0)
	cancelled := false
	ctxDone := ctx.Done()
	retryTick := ticker.C
	for stream != nil || len(pending) > 0 {
		if cancelled && stream == nil {
			for _, item := range pending {
				if err := encoder.Encode(resolutionRecord(item, "capture_ended")); err != nil {
					return fmt.Errorf("finalize pending observation: %w", err)
				}
			}
			return nil
		}
		var incoming timedEvent
		select {
		case <-ctxDone:
			// Stop and join before draining every successful Read, including
			// the event blocked behind the bounded pump queue.
			accepted := cancel()
			tail := make(chan timedEvent, len(accepted))
			for _, event := range accepted {
				tail <- event
			}
			close(tail)
			stream = tail
			cancelled, ctxDone, retryTick = true, nil, nil
			continue
		case <-encoder.failed:
			return fmt.Errorf("write event output: %w", encoder.Err())
		case <-retryTick:
			remaining := pending[:0]
			for _, item := range pending {
				resolveObservation(resolver, &item.observation)
				item.attempts++
				if item.observation.DestinationResolved != nil || !time.Now().Before(item.deadline) {
					if err := encoder.Encode(resolutionRecord(item, "retry_deadline")); err != nil {
						return fmt.Errorf("encode resolved observation: %w", err)
					}
				} else {
					remaining = append(remaining, item)
				}
			}
			clear(pending[len(remaining):])
			pending = remaining
			for _, transaction := range dnsCorrelator.Expire(capture.watermark()) {
				if err := encoder.Encode(transaction); err != nil {
					return fmt.Errorf("expire DNS transaction: %w", err)
				}
			}
			watermark := capture.watermark()
			for _, item := range pending {
				if item.observation.ObservedAt.Before(watermark) {
					watermark = item.observation.ObservedAt
				}
			}
			if err := encoder.Flush(watermark); err != nil {
				return fmt.Errorf("flush flow windows: %w", err)
			}
			continue
		case value, ok := <-stream:
			if !ok {
				stream = nil
				continue
			}
			incoming = value
			capture.consume()
		}
		if incoming.err != nil {
			if !errors.Is(incoming.err, io.EOF) {
				readErr = fmt.Errorf("read BPF event: %w", incoming.err)
			}
			stream = nil
			continue
		}
		event, observedAt := incoming.event, incoming.observedAt
		if event.Kind == collector.EventKindL7CoverageDrop {
			drop, err := event.L7CoverageDrop(nodeName, observedAt)
			if err != nil {
				return fmt.Errorf("convert L7 coverage drop: %w", err)
			}
			if err := encoder.Encode(drop); err != nil {
				return fmt.Errorf("encode L7 coverage drop: %w", err)
			}
			continue
		}
		if event.Kind == collector.EventKindDNS {
			fragment, err := event.DNSFragment(nodeName, observedAt)
			if err != nil {
				return fmt.Errorf("convert BPF DNS event: %w", err)
			}
			enrichment := flow.Observation{ObservedAt: observedAt, Flow: flow.FlowKey{
				NodeName: nodeName, Protocol: "udp", Direction: "connection",
				Source: fragment.Source, Destination: fragment.Destination,
			}}
			resolveObservation(resolver, &enrichment)
			attachProcess(processes, event.PID, &enrichment)
			fragment.ObserverPID = event.PID
			fragment.Process = enrichment.Process
			fragment.SourceResolved = enrichment.SourceResolved
			fragment.DestinationResolved = enrichment.DestinationResolved
			for _, transaction := range dnsCorrelator.Process(fragment) {
				if err := encoder.Encode(transaction); err != nil {
					return fmt.Errorf("encode DNS transaction: %w", err)
				}
			}
			continue
		}
		if event.Kind == collector.EventKindL7Fragment {
			fragment, err := event.L7Fragment(nodeName, observedAt)
			if err != nil {
				return fmt.Errorf("convert BPF L7 event: %w", err)
			}
			enrichment := flow.Observation{ObservedAt: observedAt, Flow: flow.FlowKey{
				NodeName: nodeName, Protocol: "tcp", Direction: "connection",
				Source: fragment.SourceEndpoint, Destination: fragment.DestinationEndpoint,
			}}
			resolveObservation(resolver, &enrichment)
			attachProcess(processes, event.PID, &enrichment)
			fragment.Process = enrichment.Process
			fragment.SourceResolved = enrichment.SourceResolved
			fragment.DestinationResolved = enrichment.DestinationResolved
			for _, result := range correlator.Process(fragment) {
				if result.Transaction != nil {
					if err := encoder.Encode(result.Transaction); err != nil {
						return fmt.Errorf("encode L7 transaction: %w", err)
					}
				}
				if result.Drop != nil {
					if err := encoder.Encode(result.Drop); err != nil {
						return fmt.Errorf("encode L7 coverage drop: %w", err)
					}
				}
			}
			continue
		}
		observation, err := event.Observation(nodeName, observedAt)
		if err != nil {
			return fmt.Errorf("convert BPF event: %w", err)
		}
		resolveObservation(resolver, &observation)
		attachProcess(processes, event.PID, &observation)
		if resolver != nil && event.Kind == collector.EventKindConnect && observation.Flow.Direction == "egress" {
			// A new establishment with the same tuple ends the earlier
			// enrichment opportunity. Never join across socket generations.
			remaining := pending[:0]
			for _, earlier := range pending {
				if earlier.observation.Flow == observation.Flow {
					if err := encoder.Encode(resolutionRecord(earlier, "tuple_reused")); err != nil {
						return fmt.Errorf("encode superseded observation: %w", err)
					}
				} else {
					remaining = append(remaining, earlier)
				}
			}
			clear(pending[len(remaining):])
			pending = remaining
			// Retry budgets use elapsed time, independently of the semantic observation clock.
			item := pendingResolution{observation: observation, deadline: time.Now().Add(resolutionGrace), attempts: 1}
			if observation.DestinationResolved == nil && len(pending) < maxPendingResolutions {
				pending = append(pending, item)
				continue
			}
			if err := encoder.Encode(resolutionRecord(item, "queue_full")); err != nil {
				return fmt.Errorf("encode resolved observation: %w", err)
			}
			continue
		}
		if err := encoder.Encode(observation); err != nil {
			return fmt.Errorf("encode BPF observation: %w", err)
		}
	}
	return nil
}

// attachProcess records which userspace process issued the sampled socket
// call. PID zero means the kernel sampled the socket from a context with no
// owning task (softirq, timer) and is left unattributed. When the resolver is
// absent or cannot read /proc, only the kernel PID is kept.
func attachProcess(processes ProcessResolver, pid uint32, observation *flow.Observation) {
	if pid == 0 {
		return
	}
	if processes != nil {
		if process, ok := processes.Lookup(pid); ok {
			process.PID = pid
			observation.Process = &process
			return
		}
	}
	observation.Process = &flow.Process{PID: pid}
}

// resolveObservation annotates a flow observation with the conntrack-resolved
// endpoint. TCP sample flows may have been canonically reordered, so both
// tuple orders are attempted; the side that matched an original conntrack
// tuple keeps its raw address while the opposite side gains the resolved one.
func resolveObservation(resolver DestinationResolver, observation *flow.Observation) {
	if resolver == nil {
		return
	}
	key := observation.Flow
	if key.Direction == "egress" {
		if fresh, ok := resolver.(interface {
			ResolveAfter(string, flow.Endpoint, flow.Endpoint, time.Time) (flow.Endpoint, string, bool)
		}); ok {
			if resolved, via, ok := fresh.ResolveAfter(key.Protocol, key.Source, key.Destination, observation.ObservedAt); ok {
				observation.DestinationResolved = &flow.ResolvedEndpoint{Address: resolved.Address, Port: resolved.Port, Via: via}
			}
			return
		}
	}
	if resolved, via, ok := resolver.Resolve(key.Protocol, key.Source, key.Destination); ok {
		observation.DestinationResolved = &flow.ResolvedEndpoint{Address: resolved.Address, Port: resolved.Port, Via: via}
		return
	}
	if resolved, via, ok := resolver.Resolve(key.Protocol, key.Destination, key.Source); ok {
		observation.SourceResolved = &flow.ResolvedEndpoint{Address: resolved.Address, Port: resolved.Port, Via: via}
	}
}
