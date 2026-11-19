package topology

import (
	"math"
	"net/netip"
	"time"

	"github.com/whatap/agentkubenetwork/internal/flow"
)

func validTime(t time.Time) bool {
	seconds := t.Unix()
	return !t.IsZero() && seconds >= 0 && seconds <= (math.MaxInt64-int64(t.Nanosecond())/int64(time.Millisecond))/1000 && t.UnixMilli() > 0
}

func validAddress(address string) bool {
	ip, err := netip.ParseAddr(address)
	return err == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
}

func validRawEndpoint(endpoint flow.Endpoint) bool {
	return validAddress(endpoint.Address) && endpoint.Port != 0
}

func validResolved(endpoint *flow.ResolvedEndpoint) bool {
	return endpoint == nil || (validRawEndpoint(flow.Endpoint{Address: endpoint.Address, Port: endpoint.Port}) && validText(endpoint.Via, 32))
}

func validEndpoint(endpoint Endpoint) bool {
	if endpoint.Kind == KindUnresolvedAddress {
		return endpoint.UID == "" && endpoint.Name == "" && endpoint.Namespace == "" && validAddress(endpoint.Address)
	}
	return endpoint.Address == "" && validText(endpoint.Kind, 63) && validText(endpoint.Namespace, 63) && validText(endpoint.Name, 253) && validText(endpoint.UID, 253)
}

// ValidateSummary is shared by the producer and wire pack boundary. Numeric
// fields remain representable int64 milliseconds; absence is never a result.
func ValidateSummary(s Summary) error {
	span := s.WindowEnd.Sub(s.WindowStart)
	if !validText(s.ClusterID, 253) || !validTime(s.WindowStart) || !validTime(s.WindowEnd) ||
		span < time.Millisecond || span > time.Minute || span%time.Millisecond != 0 ||
		!s.WindowStart.Equal(s.WindowStart.Truncate(span)) || !s.Observed ||
		!validEndpoint(s.Source) || !validEndpoint(s.Destination) ||
		s.LastSeenMS < s.WindowStart.UnixMilli() || s.LastSeenMS >= s.WindowEnd.UnixMilli() ||
		(s.ErrorObserved && !s.ResultObserved) {
		return ErrInvalidObservation
	}
	if s.Direction == DirectionUnknown {
		if s.DestinationPort != 0 || s.ResultObserved || s.ErrorObserved {
			return ErrInvalidObservation
		}
	} else if s.Direction != DirectionRequest || s.DestinationPort == 0 {
		return ErrInvalidObservation
	}
	switch s.Protocol {
	case "tcp":
		if s.Transport != "tcp" || s.Direction != DirectionUnknown {
			return ErrInvalidObservation
		}
	case "http1", "http2":
		if s.Transport != "tcp" || s.Direction != DirectionRequest {
			return ErrInvalidObservation
		}
	case "dns":
		if s.Transport != "udp" {
			return ErrInvalidObservation
		}
	default:
		return ErrInvalidObservation
	}
	return nil
}
