package whatap

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	whatapio "github.com/whatap/golib/io"
	"github.com/whatap/golib/util/hexa32"
)

// Synthetic equivalent of license.Build, using deterministic random padding.
// No actual access keys, configuration files, or external repositories are used.
func syntheticLicense(pcode int64, key []byte) string {
	out := whatapio.NewDataOutputX().WriteDecimal(pcode).WriteBlob(key)
	return licenseFromBytes(out.ToByteArray())
}

func licenseFromBytes(raw []byte) string {
	data := append([]byte(nil), raw...)
	for len(data)%8 != 0 {
		data = append(data, byte(0xa0+len(data)%8))
	}
	tokens := make([]string, len(data)/8)
	for i := range tokens {
		tokens[i] = hexa32.ToString32(int64(binary.BigEndian.Uint64(data[i*8:])))
	}
	return strings.Join(tokens, "-")
}

func TestParseLicenseCompatibility(t *testing.T) {
	pcodes := []int64{1, -1, 127, 128, -128, -129, 32767, 32768, -32769, 8388607, 8388608, -8388609, math.MaxInt32, math.MinInt32, 1 << 32, (1 << 39) - 1, 1 << 39, -(1 << 39), math.MaxInt64, math.MinInt64}
	for _, pcode := range pcodes {
		for _, size := range []int{1, 7, 8, 15, 16, 17, 32, 253, 254, 1024} {
			key := make([]byte, size)
			for i := range key {
				key[i] = byte(i*29 + 7)
			}
			gotPcode, gotKey, err := parseLicense(syntheticLicense(pcode, key))
			if err != nil || gotPcode != pcode || !bytes.Equal(gotKey, key) {
				t.Fatalf("pcode=%d size=%d: decoded pcode=%d, error=%v", pcode, size, gotPcode, err)
			}
		}
	}
}

func TestLicenseWordCompatibility(t *testing.T) {
	for _, n := range []int64{0, 1, 9, 10, -1, -9, -10, 1 << 60, math.MaxInt64, math.MinInt64} {
		word, err := licenseWord(hexa32.ToString32(n))
		if err != nil || word != n {
			t.Fatalf("word %d: got %d, %v", n, word, err)
		}
	}
	for text, want := range map[string]int64{"xV": 31, "zVV": -1023, "9223372036854775807": math.MaxInt64} {
		got, err := licenseWord(text)
		if err != nil || got != want {
			t.Fatalf("word variant: got %d, %v; want %d", got, err, want)
		}
	}
	for _, text := range []string{"", "x", "z", "X1", "Z1", "+1", "-1", "xw", "xz", "x/", "xé", "xK", "zK", "xİ", "x8000000000000", "z8000000000001", "xvvvvvvvvvvvvv", "x10000000000000", "9223372036854775808", "18446744073709551616", "1 ", " 1", "1\n"} {
		if _, err := licenseWord(text); err == nil {
			t.Error("accepted malformed word")
		}
	}
}

func TestParseLicenseRejectsUnicodeWordVariants(t *testing.T) {
	for validWord, invalidWord := range map[string]string{"xk": "xK", "zk": "zK", "xi": "xİ"} {
		t.Run(validWord, func(t *testing.T) {
			raw := whatapio.NewDataOutputX().WriteDecimal(1).WriteBlob(make([]byte, 16)).ToByteArray()
			// The second word lies entirely inside the synthetic key blob.
			binary.BigEndian.PutUint64(raw[8:16], uint64(hexa32.ToLong32(validWord)))
			valid := licenseFromBytes(raw)
			if pcode, key, err := parseLicense(valid); err != nil || pcode != 1 || !bytes.Equal(key, raw[3:]) {
				t.Fatalf("invalid ASCII fixture: pcode=%d, error=%v", pcode, err)
			}
			invalid := strings.Replace(valid, "-"+validWord+"-", "-"+invalidWord+"-", 1)
			if invalid == valid {
				t.Fatal("fixture did not replace a complete word")
			}
			if _, _, err := parseLicense(invalid); err != errInvalidLicense {
				t.Fatal("Unicode license word must fail with the redacted license error")
			}
		})
	}
}

func TestParseLicenseRejectsMalformedAndRedacts(t *testing.T) {
	valid := syntheticLicense(12345, bytes.Repeat([]byte{0x91}, 16))
	invalid := map[string]string{
		"empty":               "",
		"secret":              "SYNTHETIC_SECRET_DO_NOT_ECHO",
		"empty word":          valid + "-",
		"extra words":         valid + "-0",
		"spaces":              " " + valid,
		"word overflow":       "x8000000000000-0-0",
		"invalid alphabet":    "x12345w-0-0",
		"too many words":      strings.Repeat("0-", maxLicenseWords) + "0",
		"too much text":       strings.Repeat("x", maxLicenseText+1),
		"invalid decimal":     licenseFromBytes([]byte{6, 1, 16, 1, 1, 1, 1, 1}),
		"truncated decimal":   licenseFromBytes([]byte{8}),
		"truncated blob":      licenseFromBytes([]byte{1, 1, 16, 1}),
		"negative blob":       licenseFromBytes([]byte{1, 1, 254, 255, 255, 255, 255}),
		"huge blob":           licenseFromBytes([]byte{1, 1, 254, 127, 255, 255, 255}),
		"oversized blob":      licenseFromBytes([]byte{1, 1, 255, 4, 1}),
		"zero pcode":          syntheticLicense(0, []byte{1, 2, 3}),
		"empty key":           syntheticLicense(1, nil),
		"key above limit":     syntheticLicense(1, make([]byte, maxLicenseKeyBytes+1)),
		"short blob prefix":   licenseFromBytes([]byte{5, 1, 2, 3, 4, 5, 254, 0}),
		"short ushort prefix": licenseFromBytes([]byte{5, 1, 2, 3, 4, 5, 255, 0}),
	}
	// A complete decimal ending at byte 7 leaves only a truncated blob prefix.
	invalid["truncated ushort length"] = licenseFromBytes([]byte{4, 1, 2, 3, 4, 255, 255, 255})
	for name, text := range invalid {
		t.Run(name, func(t *testing.T) {
			_, _, err := parseLicense(text)
			if err == nil {
				t.Fatal("accepted malformed license")
			}
			if err.Error() != "whatap: invalid access key" {
				t.Fatalf("license errors must be constant and redacted: %v", err)
			}
		})
	}
}

func TestTakeBlobBounds(t *testing.T) {
	for _, data := range [][]byte{nil, {255}, {255, 0}, {254}, {254, 0, 0, 0}, {254, 255, 255, 255, 255}, {4, 1, 2, 3}} {
		if _, _, err := takeBlob(data, 1024); err == nil {
			t.Fatalf("accepted truncated/invalid blob: %v", data)
		}
	}
	for _, prefix := range [][]byte{{3}, {255, 0, 3}, {254, 0, 0, 0, 3}} {
		data := append(append([]byte(nil), prefix...), 1, 2, 3, 4, 5)
		blob, rest, err := takeBlob(data, 3)
		if err != nil || !bytes.Equal(blob, []byte{1, 2, 3}) || !bytes.Equal(rest, []byte{4, 5}) {
			t.Fatalf("blob prefix compatibility: %v", err)
		}
	}
}

func FuzzParseLicense(f *testing.F) {
	f.Add(syntheticLicense(1234567, bytes.Repeat([]byte{0xa5}, 16)))
	f.Add("x8000000000000-0")
	f.Add(licenseFromBytes([]byte{1, 1, 254, 255, 255, 255, 255}))
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		pcode, key, err := parseLicense(text)
		if err == nil && (pcode == 0 || len(key) == 0 || len(key) > maxLicenseKeyBytes) {
			t.Fatal("invalid successful parse")
		}
		if err != nil && err.Error() != "whatap: invalid access key" {
			t.Fatal("unredacted parse error")
		}
	})
}
