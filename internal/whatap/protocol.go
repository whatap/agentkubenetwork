package whatap

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"net"

	whatapio "github.com/whatap/golib/io"
)

const (
	headerSize       = 22
	maxHandshakeBody = 1024
	maxFrameBody     = 8 * 1024 * 1024
	sourceAgent      = 1
	codeHide         = 0x01
	codeCipher       = 0x02
	codeTimeSync     = 0xfe
	codeKeyReset     = 0xff
)

type frameHeader struct {
	source      byte
	code        byte
	pcode       int64
	oid         int32
	transferKey int32
	size        int32
}

// Wire layout ported from npmagent/gointernal/net/secure/TcpSession.go
// (keyReset/Send), with NET_SECURE_CYPHER selected as in secure/Sender.go.
func makeFrame(code byte, pcode int64, oid, transferKey int32, body []byte) []byte {
	frame := make([]byte, headerSize+len(body))
	frame[0], frame[1] = sourceAgent, code
	binary.BigEndian.PutUint64(frame[2:10], uint64(pcode))
	binary.BigEndian.PutUint32(frame[10:14], uint32(oid))
	binary.BigEndian.PutUint32(frame[14:18], uint32(transferKey))
	binary.BigEndian.PutUint32(frame[18:22], uint32(len(body)))
	copy(frame[headerSize:], body)
	return frame
}

func parseHeader(raw *[headerSize]byte) frameHeader {
	return frameHeader{
		source:      raw[0],
		code:        raw[1],
		pcode:       int64(binary.BigEndian.Uint64(raw[2:10])),
		oid:         int32(binary.BigEndian.Uint32(raw[10:14])),
		transferKey: int32(binary.BigEndian.Uint32(raw[14:18])),
		size:        int32(binary.BigEndian.Uint32(raw[18:22])),
	}
}

func (h frameHeader) validIdentity(pcode int64, oid int32) bool {
	// Collectors can originate at the yard/proxy or echo the agent source.
	return (h.source == sourceAgent || h.source == 3 || h.source == 4) && h.pcode == pcode && h.oid == oid
}

// AES key normalization and zero-padded ECB are ported from
// npmagent/gointernal/util/crypto/Cypher.go. There is no plaintext fallback.
func masterCipher(key []byte) cipher.Block {
	var normalized [aes.BlockSize]byte
	copy(normalized[:], key)
	block, _ := aes.NewCipher(normalized[:]) // Always an AES-128 key.
	return block
}

func encryptECB(block cipher.Block, plain []byte) []byte {
	out := make([]byte, (len(plain)+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	copy(out, plain)
	for off := 0; off < len(out); off += aes.BlockSize {
		block.Encrypt(out[off:off+aes.BlockSize], out[off:off+aes.BlockSize])
	}
	return out
}

func decryptECB(block cipher.Block, encrypted []byte) ([]byte, error) {
	if len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("whatap: invalid encrypted body length")
	}
	out := make([]byte, len(encrypted))
	for off := 0; off < len(out); off += aes.BlockSize {
		block.Decrypt(out[off:off+aes.BlockSize], encrypted[off:off+aes.BlockSize])
	}
	return out, nil
}

func (c *Client) handshake(conn net.Conn) (int32, cipher.Block, error) {
	var ipv4 int32
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		if ip := addr.IP.To4(); ip != nil {
			ipv4 = int32(binary.BigEndian.Uint32(ip))
		}
	}
	hello := whatapio.NewDataOutputX().WriteText("hello").WriteText(c.objectName).WriteInt(ipv4).ToByteArray()
	if _, err := writeAll(conn, makeFrame(codeKeyReset, c.pcode, c.oid, 0, encryptECB(c.master, hello))); err != nil {
		return 0, nil, err
	}
	var raw [headerSize]byte
	if _, err := io.ReadFull(conn, raw[:]); err != nil {
		return 0, nil, err
	}
	h := parseHeader(&raw)
	if !h.validIdentity(c.pcode, c.oid) || h.code != codeKeyReset {
		return 0, nil, errors.New("whatap: invalid handshake header")
	}
	if h.size <= 0 || h.size > maxHandshakeBody || h.size%aes.BlockSize != 0 {
		return 0, nil, errors.New("whatap: invalid handshake body length")
	}
	body := make([]byte, int(h.size))
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	transferKey, block, err := c.decodeKeyReply(body)
	if err != nil {
		return 0, nil, err
	}
	// Legacy replies leave the header key empty; live proxies also echo the
	// issued key. Accept that echo only when it matches the decrypted body.
	if h.transferKey != 0 && h.transferKey != transferKey {
		return 0, nil, errors.New("whatap: key reply header/session mismatch")
	}
	return transferKey, block, nil
}

// Reply fields follow secure/SecurityMaster.go's UpdateNetCypherKey.
// Hide key and public IPv4 are consumed but never used for XOR or clock state.
func (c *Client) decodeKeyReply(body []byte) (int32, cipher.Block, error) {
	if len(body) > maxHandshakeBody {
		return 0, nil, errors.New("whatap: oversized key reply")
	}
	plain, err := decryptECB(c.master, body)
	if err != nil || len(plain) < 4 {
		return 0, nil, errors.New("whatap: invalid key reply")
	}
	transferKey := int32(binary.BigEndian.Uint32(plain[:4]))
	key, rest, err := takeBlob(plain[4:], aes.BlockSize)
	if err != nil || transferKey == 0 || len(key) != aes.BlockSize || len(rest) < 8 || len(rest)-8 >= aes.BlockSize {
		return 0, nil, errors.New("whatap: invalid session key reply")
	}
	for _, b := range rest[8:] {
		if b != 0 {
			return 0, nil, errors.New("whatap: invalid key reply padding")
		}
	}
	block, err := aes.NewCipher(key)
	return transferKey, block, err
}

func writeAll(w io.Writer, data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return total, io.ErrShortWrite
		}
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
