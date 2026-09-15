package bridge

import (
	"errors"
	"github.com/whatap/agentkubenetwork/internal/flow"
	"math/big"
	"net/netip"
	"regexp"
)

const maxSafe = 1<<53 - 1

var token = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,32}$`)

func printable(s string, n int) bool {
	if len(s) == 0 || len(s) > n {
		return false
	}
	for i := range s {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
func endpoint(a string, p uint16) bool {
	ip, e := netip.ParseAddr(a)
	return e == nil && ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() && p != 0
}
func validateWindow(w flow.Window) error {
	bad := errors.New("invalid network edge window")
	start, end := w.WindowStart.UnixMilli(), w.WindowEnd.UnixMilli()
	if w.WindowStart.Unix() < 0 || w.WindowEnd.Unix() < 0 || w.WindowStart.Unix() > maxSafe/1000 || w.WindowEnd.Unix() > maxSafe/1000 || start <= 0 || end <= start || end > maxSafe || end-start > 60000 {
		return bad
	}
	if !printable(w.Flow.NodeName, 253) || w.Flow.Protocol != "tcp" || !endpoint(w.Flow.Source.Address, w.Flow.Source.Port) || !endpoint(w.Flow.Destination.Address, w.Flow.Destination.Port) {
		return bad
	}
	if w.Process != nil && w.Process.ContainerID != "" && !printable(w.Process.ContainerID, 128) {
		return bad
	}
	for _, r := range []*flow.ResolvedEndpoint{w.SourceResolved, w.DestinationResolved} {
		if r != nil && (!endpoint(r.Address, r.Port) || !token.MatchString(r.Via)) {
			return bad
		}
	}
	d := w.RTT
	if d.Count < 1 || d.Count > 1000000000 || d.SumMicros < 1 || d.SumMicros > maxSafe || d.MinMicros < 1 || d.MinMicros > maxSafe || d.MaxMicros < d.MinMicros || d.MaxMicros > maxSafe {
		return bad
	}
	if d.Count == 1 {
		if d.SumMicros != d.MinMicros || d.SumMicros != d.MaxMicros {
			return bad
		}
		return nil
	}
	// Both extrema must actually occur; use big integers to avoid product overflow.
	n := new(big.Int).SetUint64(d.Count - 1)
	lo := new(big.Int).Mul(n, new(big.Int).SetUint64(d.MinMicros))
	lo.Add(lo, new(big.Int).SetUint64(d.MaxMicros))
	hi := new(big.Int).Mul(n, new(big.Int).SetUint64(d.MaxMicros))
	hi.Add(hi, new(big.Int).SetUint64(d.MinMicros))
	sum := new(big.Int).SetUint64(d.SumMicros)
	if sum.Cmp(lo) < 0 || sum.Cmp(hi) > 0 {
		return bad
	}
	return nil
}
