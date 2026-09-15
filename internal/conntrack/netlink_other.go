//go:build !linux

package conntrack

import (
	"errors"
	"time"
)

// NewNetlinkResolver is a stub for non-Linux builds; every refresh fails and
// lookups always miss.
func NewNetlinkResolver(ttl time.Duration) *Resolver {
	return newResolver(func() ([]Entry, error) {
		return nil, errors.New("conntrack netlink requires linux")
	}, ttl, time.Now)
}
