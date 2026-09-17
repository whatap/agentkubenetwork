package whatap

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/whatap/golib/lang/pack"
	"github.com/whatap/golib/util/hash"
)

// ErrAmbiguousDelivery means a data-frame write was attempted and then failed
// or was interrupted. The collector may have received it; do not retry it.
var ErrAmbiguousDelivery = errors.New("whatap: ambiguous delivery")

// ErrClosed is returned by Send after the terminal Close operation.
var ErrClosed = errors.New("whatap: client closed")

// Config contains explicit, prevalidated collector settings. Timeout must be
// positive; callers supply defaults. Servers must include numeric TCP ports.
type Config struct {
	AccessKey  string
	Servers    []string
	ObjectName string
	Timeout    time.Duration
}

// Client is a lazy, reusable transport. Construct it with NewClient and do not
// copy it. Send and Close may be called concurrently.
type Client struct {
	pcode      int64
	oid        int32
	objectName string
	servers    []string
	timeout    time.Duration
	master     cipher.Block

	dialContext func(context.Context, string, string) (net.Conn, error)
	gate        chan struct{}
	closeCtx    context.Context
	cancelClose context.CancelFunc
	closeOnce   sync.Once
	mu          sync.Mutex
	closed      bool
	session     *session
	readers     sync.WaitGroup
}

type session struct {
	conn        net.Conn
	transferKey int32
	block       cipher.Block
	closed      chan struct{}
	closeOnce   sync.Once
}

func (s *session) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
}

func (s *session) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// NewClient validates settings and the license without starting network I/O.
// The access key is never logged or retained as text in the Client.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Timeout <= 0 {
		return nil, errors.New("whatap: timeout must be positive")
	}
	if len(cfg.Servers) == 0 || len(cfg.Servers) > 32 {
		return nil, errors.New("whatap: expected 1 to 32 servers")
	}
	for i, server := range cfg.Servers {
		if !validServer(server) {
			return nil, fmt.Errorf("whatap: invalid server at index %d (expected host:numeric-port)", i)
		}
	}
	if len(cfg.ObjectName) == 0 || len(cfg.ObjectName) > 512 || !utf8.ValidString(cfg.ObjectName) || strings.TrimSpace(cfg.ObjectName) != cfg.ObjectName {
		return nil, errors.New("whatap: invalid object name")
	}
	for _, r := range cfg.ObjectName {
		if !unicode.IsGraphic(r) {
			return nil, errors.New("whatap: invalid object name")
		}
	}
	oid := hash.HashStr(cfg.ObjectName)
	if oid == 0 {
		return nil, errors.New("whatap: object name produces zero identity")
	}
	pcode, key, err := parseLicense(cfg.AccessKey)
	if err != nil {
		return nil, err
	}
	closeCtx, cancelClose := context.WithCancel(context.Background())
	c := &Client{
		pcode: pcode, oid: oid, objectName: cfg.ObjectName,
		servers: append([]string(nil), cfg.Servers...), timeout: cfg.Timeout,
		master: masterCipher(key), dialContext: (&net.Dialer{}).DialContext,
		gate: make(chan struct{}, 1), closeCtx: closeCtx, cancelClose: cancelClose,
	}
	c.gate <- struct{}{}
	return c, nil
}

func validServer(server string) bool {
	if len(server) == 0 || len(server) > 320 {
		return false
	}
	for _, r := range server {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	host, port, err := net.SplitHostPort(server)
	if err != nil || len(host) == 0 || len(port) == 0 || len(port) > 5 {
		return false
	}
	for i := range port {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return false
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if server[0] == '[' && !ip.Is6() {
			return false
		}
		for _, b := range ip.Zone() {
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.') {
				return false
			}
		}
		ip = ip.WithZone("").Unmap()
		return !ip.IsUnspecified() && !ip.IsMulticast() && ip != netip.AddrFrom4([4]byte{255, 255, 255, 255})
	}
	if server[0] == '[' {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 || strings.Trim(host, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range label {
			b := label[i]
			if !((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-') {
				return false
			}
		}
	}
	return true
}

// Identity returns the license pcode and golib/hash.HashStr(ObjectName) oid.
func (c *Client) Identity() (int64, int32) {
	return c.pcode, c.oid
}

// Send writes one window, preserving Time and leaving the input unchanged.
// Zero identity fields are filled in a copy; conflicting nonzero fields fail.
// Callers must not mutate the pack or its values until Send returns. A nil
// result promises TCP write completion only, not receipt, storage, or an ACK.
func (c *Client) Send(ctx context.Context, p *pack.TagCountPack) error {
	if ctx == nil {
		return errors.New("whatap: nil context")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	stopClose := context.AfterFunc(c.closeCtx, cancel)
	defer stopClose()
	select {
	case <-c.closeCtx.Done():
		return ErrClosed
	case <-ctx.Done():
		return c.operationError(ctx)
	case <-c.gate:
	}
	defer func() { c.gate <- struct{}{} }()
	if err := c.operationError(ctx); err != nil {
		return err
	}
	body, err := c.serialize(p)
	if err != nil {
		return err
	}
	if s := c.currentSession(); s != nil {
		attempted, err := c.sendFrame(ctx, s, body)
		if err == nil {
			return nil
		}
		c.dropSession(s)
		if attempted {
			return fmt.Errorf("%w: %w", ErrAmbiguousDelivery, err)
		}
	}
	var lastErr error
	for i, server := range c.servers {
		if err := c.operationError(ctx); err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		attemptCtx, cancelAttempt := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(c.servers)-i))
		s, err := c.connect(attemptCtx, server)
		cancelAttempt()
		if err != nil {
			lastErr = fmt.Errorf("whatap: connect server %d: %w", i, err)
			continue
		}
		attempted, err := c.sendFrame(ctx, s, body)
		if err == nil {
			return nil
		}
		c.dropSession(s)
		if attempted {
			return fmt.Errorf("%w: %w", ErrAmbiguousDelivery, err)
		}
		lastErr = err
	}
	if err := c.operationError(ctx); err != nil {
		return err
	}
	return fmt.Errorf("whatap: no collector connection: %w", lastErr)
}

func (c *Client) serialize(p *pack.TagCountPack) (body []byte, err error) {
	if p == nil || p.Tags == nil || p.Data == nil {
		return nil, errors.New("whatap: invalid TagCount pack")
	}
	if (p.Pcode != 0 && p.Pcode != c.pcode) || (p.Oid != 0 && p.Oid != c.oid) {
		return nil, errors.New("whatap: pack identity does not match client")
	}
	defer func() {
		if recover() != nil {
			body, err = nil, errors.New("whatap: cannot serialize TagCount pack")
		}
	}()
	copyPack := *p // golib's Write mutates tagHash; do not mutate the caller.
	copyPack.Pcode, copyPack.Oid = c.pcode, c.oid
	body = pack.ToBytesPack(&copyPack)
	if len(body) > maxFrameBody {
		return nil, errors.New("whatap: TagCount pack exceeds frame limit")
	}
	return body, nil
}

func (c *Client) operationError(ctx context.Context) error {
	if c.closeCtx.Err() != nil {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

func (c *Client) currentSession() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

func (c *Client) dropSession(s *session) {
	s.close()
	c.mu.Lock()
	if c.session == s {
		c.session = nil
	}
	c.mu.Unlock()
}

// Stop and join the cancellation callback before a connection can be reused.
func watchConnection(ctx context.Context, s *session) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		s.close()
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
		})
	}
}

func (c *Client) connect(ctx context.Context, server string) (_ *session, err error) {
	conn, err := c.dialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	s := &session{conn: conn, closed: make(chan struct{})}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		s.close()
		return nil, ErrClosed
	}
	c.session = s // Close must also interrupt an in-progress handshake.
	c.mu.Unlock()
	stop := watchConnection(ctx, s)
	defer func() {
		stop()
		if err != nil {
			c.dropSession(s)
		}
	}()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	s.transferKey, s.block, err = c.handshake(conn)
	stop()
	if ctxErr := c.operationError(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || s.isClosed() {
		return nil, ErrClosed
	}
	c.readers.Add(1) // Guarded with closed, so Close can safely Wait.
	go c.receive(s)
	return s, nil
}

func (c *Client) sendFrame(ctx context.Context, s *session, body []byte) (bool, error) {
	stop := watchConnection(ctx, s)
	defer stop()
	if err := c.operationError(ctx); err != nil {
		return false, err
	}
	if s.isClosed() {
		return false, net.ErrClosed
	}
	deadline, _ := ctx.Deadline()
	if err := s.conn.SetWriteDeadline(deadline); err != nil {
		return false, err
	}
	frame := makeFrame(codeCipher, c.pcode, c.oid, s.transferKey, encryptECB(s.block, body))
	if err := c.operationError(ctx); err != nil {
		return false, err
	}
	_, err := writeAll(s.conn, frame)
	stop()
	if ctxErr := c.operationError(ctx); ctxErr != nil {
		return true, ctxErr
	}
	return true, err
}

func (c *Client) receive(s *session) {
	defer c.readers.Done()
	defer c.dropSession(s)
	var raw [headerSize]byte
	var scratch [4096]byte
	for {
		if err := s.conn.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		// Idle connections remain reusable; once a frame starts its remaining
		// header and body must arrive within one timeout.
		if _, err := io.ReadFull(s.conn, raw[:1]); err != nil {
			return
		}
		if err := s.conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			return
		}
		if _, err := io.ReadFull(s.conn, raw[1:]); err != nil {
			return
		}
		h := parseHeader(&raw)
		if !h.validIdentity(c.pcode, c.oid) || h.size <= 0 || h.size > maxFrameBody {
			return
		}
		switch h.code {
		case codeTimeSync:
			if h.size != 16 {
				return
			}
		case codeHide, codeCipher:
			if h.transferKey != s.transferKey || (h.code == codeCipher && h.size%16 != 0) {
				return
			}
		default:
			return
		}
		// Deliberately discard, never decode or execute remote pack contents.
		for remaining := int(h.size); remaining > 0; {
			n := remaining
			if n > len(scratch) {
				n = len(scratch)
			}
			if _, err := io.ReadFull(s.conn, scratch[:n]); err != nil {
				return
			}
			remaining -= n
		}
	}
}

// Close permanently closes the client and waits for its readers to exit.
// It is idempotent and cancels dialing, handshakes, writes, and queued Sends.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.cancelClose()
		s := c.session
		c.session = nil
		c.mu.Unlock()
		if s != nil {
			s.close()
		}
		c.readers.Wait()
	})
	return nil
}
