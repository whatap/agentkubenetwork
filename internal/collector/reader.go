package collector

import (
	"errors"
)

var ErrUnsupportedPlatform = errors.New("eBPF collector is supported only on Linux")

type OpenOptions struct {
	OpenSSLLibraries []string
}

type EventReader interface {
	Read() (Event, error)
	// Close must unblock a concurrent Read. A reader may additionally expose
	// InterruptRead to stop reading separately from releasing its resources.
	Close() error
}
