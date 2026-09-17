package whatap

import (
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"strings"

	whatapio "github.com/whatap/golib/io"
)

const (
	maxLicenseKeyBytes = 1024
	maxLicenseWords    = (9 + 5 + maxLicenseKeyBytes + 7) / 8
	maxLicenseText     = maxLicenseWords*15 - 1
)

var errInvalidLicense = errors.New("whatap: invalid access key")

// Ported from npmagent/gointernal/lang/license/License.go (Build/Parse).
// Preflight all lengths and base32 words before calling golib's permissive,
// panic-based decoder. Build can leave up to seven arbitrary padding bytes.
func parseLicense(text string) (int64, []byte, error) {
	if len(text) == 0 || len(text) > maxLicenseText {
		return 0, nil, errInvalidLicense
	}
	tokens := strings.Split(text, "-")
	if len(tokens) > maxLicenseWords {
		return 0, nil, errInvalidLicense
	}
	raw := make([]byte, len(tokens)*8)
	for i, token := range tokens {
		word, err := licenseWord(token)
		if err != nil {
			return 0, nil, errInvalidLicense
		}
		binary.BigEndian.PutUint64(raw[i*8:], uint64(word))
	}
	width := int(raw[0])
	if (width > 5 && width != 8) || 1+width >= len(raw) {
		return 0, nil, errInvalidLicense
	}
	key, rest, err := takeBlob(raw[1+width:], maxLicenseKeyBytes)
	if err != nil || len(key) == 0 || len(rest) > 7 {
		return 0, nil, errInvalidLicense
	}
	in := whatapio.NewDataInputX(raw)
	pcode := in.ReadDecimal()
	if pcode == 0 {
		return 0, nil, errInvalidLicense
	}
	return pcode, in.ReadBlob(), nil
}

func licenseWord(token string) (int64, error) {
	if len(token) == 0 {
		return 0, errInvalidLicense
	}
	if token[0] != 'x' && token[0] != 'z' {
		if len(token) > 19 {
			return 0, errInvalidLicense
		}
		for i := range token {
			if token[i] < '0' || token[i] > '9' {
				return 0, errInvalidLicense
			}
		}
		n, err := strconv.ParseInt(token, 10, 64)
		if err != nil {
			return 0, errInvalidLicense
		}
		return n, nil
	}
	if len(token) < 2 || len(token) > 14 {
		return 0, errInvalidLicense
	}
	digits := token[1:]
	for i := range digits {
		if !((digits[i] >= '0' && digits[i] <= '9') || (digits[i] >= 'a' && digits[i] <= 'v') || (digits[i] >= 'A' && digits[i] <= 'V')) {
			return 0, errInvalidLicense
		}
	}
	n, err := strconv.ParseUint(digits, 32, 64)
	if err != nil || (token[0] == 'x' && n > math.MaxInt64) || (token[0] == 'z' && n > uint64(1)<<63) {
		return 0, errInvalidLicense
	}
	// Use the checked magnitude directly, without Unicode case folding.
	if token[0] == 'z' {
		return -int64(n), nil
	}
	return int64(n), nil
}

// takeBlob reads golib's one-, three-, or five-byte blob prefix without
// allocating from an untrusted length or accepting a truncated input.
func takeBlob(data []byte, max int) ([]byte, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errors.New("whatap: truncated blob")
	}
	prefix, size := 1, uint32(data[0])
	switch data[0] {
	case 255:
		if len(data) < 3 {
			return nil, nil, errors.New("whatap: truncated blob length")
		}
		prefix, size = 3, uint32(binary.BigEndian.Uint16(data[1:3]))
	case 254:
		if len(data) < 5 {
			return nil, nil, errors.New("whatap: truncated blob length")
		}
		prefix, size = 5, binary.BigEndian.Uint32(data[1:5])
	}
	if uint64(size) > uint64(max) || uint64(size) > uint64(len(data)-prefix) {
		return nil, nil, errors.New("whatap: invalid blob length")
	}
	end := prefix + int(size)
	return data[prefix:end], data[end:], nil
}
