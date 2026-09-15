package bridge

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// preflightMap walks only bounded slices before invoking the SDK, whose reader
// trusts nested lengths. It deliberately rejects unsupported/noncanonical widths.
func preflightMap(b []byte) error {
	bad := errors.New("invalid bounded scalar MapValue")
	if len(b) < 2 || len(b) > 65536 || b[0] != 80 {
		return bad
	}
	p := 1
	take := func(n int) ([]byte, bool) {
		if n < 0 || n > len(b)-p {
			return nil, false
		}
		s := b[p : p+n]
		p += n
		return s, true
	}
	decimal := func() (int64, bool) {
		a, ok := take(1)
		if !ok {
			return 0, false
		}
		n := int(a[0])
		if n > 8 || n == 6 || n == 7 {
			return 0, false
		}
		a, ok = take(n)
		if !ok {
			return 0, false
		}
		var v int64
		if n > 0 && a[0]&128 != 0 {
			v = -1
		}
		for _, c := range a {
			v = v<<8 | int64(c)
		}
		return v, true
	}
	text := func(limit int) ([]byte, bool) {
		a, ok := take(1)
		if !ok {
			return nil, false
		}
		n := int(a[0])
		switch n {
		case 255:
			a, ok = take(2)
			if !ok {
				return nil, false
			}
			n = int(binary.BigEndian.Uint16(a))
		case 254:
			a, ok = take(4)
			if !ok {
				return nil, false
			}
			n = int(int32(binary.BigEndian.Uint32(a)))
		}
		if n < 0 || n > limit {
			return nil, false
		}
		a, ok = take(n)
		return a, ok && utf8.Valid(a)
	}
	count, ok := decimal()
	if !ok || count < 0 || count > 32 {
		return bad
	}
	keys := make(map[string]bool, int(count))
	for i := int64(0); i < count; i++ {
		key, ok := text(64)
		if !ok || keys[string(key)] {
			return bad
		}
		keys[string(key)] = true
		t, ok := take(1)
		if !ok {
			return bad
		}
		switch t[0] {
		case 50:
			if _, ok = text(512); !ok {
				return bad
			}
		case 20:
			if _, ok = decimal(); !ok {
				return bad
			}
		case 10:
			a, ok := take(1)
			if !ok || a[0] > 1 {
				return bad
			}
		default:
			return bad
		}
	}
	if p != len(b) {
		return bad
	}
	return nil
}
