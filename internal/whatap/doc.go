// Package whatap sends individual TagCount windows using the legacy WhaTap
// collector protocol. It uses proprietary, zero-padded AES-128 ECB, not TLS or
// AEAD: there is no authenticated server identity or ciphertext integrity.
// Deploy it only over a trusted network or a separately secured tunnel.
//
// NewClient validates configuration without DNS lookups, dialing, goroutines,
// or configuration-file access. Send connects lazily, reuses its connection,
// and serializes concurrent calls. A successful Send means only that the TCP
// write completed, not that the collector acknowledged or stored the window.
// Never automatically retry ErrAmbiguousDelivery; doing so can duplicate data.
//
// Each Send has one overall timeout, including waiting for another Send.
// Connection attempts share the remaining time across configured servers.
// Only failures before attempting a data-frame write permit failover. There
// are no queues, background reconnects, remote commands, or clock adjustments.
// One connection-scoped reader discards bounded incoming frames and exits on
// error or Close. Close is terminal and interrupts outstanding network I/O.
//
// Limits are 32 explicit host:port servers, a 512-byte UTF-8 object name, a
// 1024-byte license key blob, a 1024-byte handshake reply, and 8 MiB data frames.
// Session replies must contain a nonzero transfer key and a 16-byte AES key.
// IPv6 connections advertise zero for the legacy hello's IPv4-only field.
package whatap
