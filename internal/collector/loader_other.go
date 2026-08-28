//go:build !linux

package collector

func OpenBPF(_ ...OpenOptions) (EventReader, error) {
	return nil, ErrUnsupportedPlatform
}
