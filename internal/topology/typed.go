package topology

import (
	"github.com/whatap/agentkubenetwork/internal/dns"
	"github.com/whatap/agentkubenetwork/internal/l7"
)

// ObserveL7 uses the correlator's confirmed client-to-server tuple and its
// request-time identity snapshot. The observation timestamp is response time.
func (a *Aggregator) ObserveL7(t l7.Transaction) error {
	boundary := (t.Protocol == l7.ProtocolHTTP1 && t.LatencyBoundary == l7.BoundaryResponseStatus) ||
		(t.Protocol == l7.ProtocolHTTP2 && t.LatencyBoundary == l7.BoundaryResponseHeaders)
	if t.SchemaVersion != l7.SchemaVersion || !validTime(t.ObservedAt) || t.Flow.Protocol != "tcp" ||
		t.Flow.Direction != "client-to-server" || !boundary || t.StatusCode < 200 || t.StatusCode > 599 ||
		(t.Source != l7.SourceKernelPlaintext && t.Source != l7.SourceOpenSSL) ||
		!validRawEndpoint(t.Flow.Source) || !validRawEndpoint(t.Flow.Destination) ||
		!validResolved(t.SourceResolved) || !validResolved(t.DestinationResolved) {
		return ErrInvalidObservation
	}
	port := t.Flow.Destination.Port
	if t.DestinationResolved != nil {
		port = t.DestinationResolved.Port
	}
	return a.observe(t.ObservedAt, Summary{
		Source:      endpointFor(t.SourcePod, t.Flow.Source, t.SourceResolved),
		Destination: endpointFor(t.DestinationPod, t.Flow.Destination, t.DestinationResolved),
		Transport:   "tcp", Protocol: t.Protocol, Direction: DirectionRequest, DestinationPort: port,
		ResultObserved: true, ErrorObserved: t.StatusCode >= 400,
	})
}

// ObserveDNS does not turn timeout, orphan response, or parse/coverage loss into
// success. The existing DNS type has no matched bit: positive measured latency
// proves a matched query; zero includes both orphan and sub-microsecond samples
// and is therefore conservatively result-unconfirmed in this summary.
func (a *Aggregator) ObserveDNS(t dns.Transaction) error {
	if t.SchemaVersion != dns.SchemaVersion || !validTime(t.ObservedAt) || t.Protocol != "udp" ||
		!validResolved(t.ClientResolved) || !validResolved(t.ServerResolved) {
		return ErrInvalidObservation
	}
	switch t.Outcome {
	case dns.OutcomeResponse:
		if !validDNSCode(t.ResponseCode) {
			return ErrInvalidObservation
		}
	case dns.OutcomeNoResponse, dns.OutcomeIncomplete, dns.OutcomeParseError:
		if t.ResponseCode != "" || t.LatencyMicros != 0 {
			return ErrInvalidObservation
		}
	default:
		return ErrInvalidObservation
	}
	// Valid diagnostic DNS records may have wildcard/unbound tuples. They stay
	// in the original category but establish no drawable endpoint relationship.
	if !validRawEndpoint(t.Client) || !validRawEndpoint(t.Server) {
		return nil
	}
	s := Summary{Source: endpointFor(t.ClientPod, t.Client, t.ClientResolved),
		Destination: endpointFor(t.ServerPod, t.Server, t.ServerResolved),
		Transport:   "udp", Protocol: "dns", Direction: DirectionRequest, DestinationPort: t.Server.Port}
	if t.ServerResolved != nil {
		s.DestinationPort = t.ServerResolved.Port
	}
	if t.Outcome == dns.OutcomeParseError {
		s.Direction, s.DestinationPort = DirectionUnknown, 0
		if compareEndpoint(s.Source, s.Destination) > 0 {
			s.Source, s.Destination = s.Destination, s.Source
		}
	}
	s.ResultObserved = t.Outcome == dns.OutcomeResponse && t.LatencyMicros > 0
	s.ErrorObserved = s.ResultObserved && t.ResponseCode != "NOERROR"
	return a.observe(t.ObservedAt, s)
}

func validDNSCode(code string) bool {
	for i := uint8(0); i < 16; i++ {
		if code == dns.ResponseCodeString(i) {
			return true
		}
	}
	return false
}
