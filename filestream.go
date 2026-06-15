// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

// Chunked, ACK'd, resumable file transfer (TypeFileStream).
//
// Problem this solves: TypeFile ships a whole file as one frame and waits
// for a single ACK after the receiver has read every byte and flushed to
// disk. On any non-trivial path (relay, or a direct link that flips to
// relay under sustained one-way load) the transfer stalls — there is no
// reverse-path traffic to keep the tunnel's blackhole heuristic happy, no
// backpressure, and no progress. Transfers above ~64 KiB time out.
//
// TypeFileStream breaks the file into small chunks. Every chunk is ACK'd,
// so the reverse path always carries traffic, the receiver writes
// incrementally, and a dropped transfer resumes from the last contiguous
// byte. End-to-end integrity is verified with a SHA-256 over the whole
// file (the per-tunnel AEAD only protects individual datagrams).
//
// Wire format — every TypeFileStream frame's payload is:
//
//	[1]  kind
//	[16] transfer_id        (sha256(content)[:16] — stable across retries)
//	...  kind-specific body
//
// transfer_id is derived from the content hash so a retry of the same
// file lands on the same receiver-side .partial and resumes automatically.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Stream control-frame kinds (the first byte of a TypeFileStream payload).
const (
	streamKindInit    byte = 0x01 // sender→receiver: filename, size, full hash, chunk size
	streamKindChunk   byte = 0x02 // sender→receiver: offset + chunk bytes
	streamKindAck     byte = 0x03 // receiver→sender: highest contiguous offset received
	streamKindDone    byte = 0x04 // sender→receiver: end of stream; verify full hash
	streamKindInitAck byte = 0x05 // receiver→sender: resume offset (presence ⇒ peer supports stream)
	streamKindComplete byte = 0x06 // receiver→sender: final status after DONE
	streamKindAbort   byte = 0x07 // either direction: cancel + reason
)

// Defaults. Chunk size is deliberately held below 64 KiB: on the Mac↔GCP-VM
// rig, single tunnel writes at/above ~256 KiB are silently swallowed by the
// reliable-stream layer (a 64 KiB TypeFile transfer succeeds byte-perfect;
// 256 KiB stalls), so a large chunk would reproduce the very failure this
// protocol exists to avoid. 48 KiB chunks each ride the known-good path, and
// the per-chunk ACK keeps the reverse direction busy so the tunnel's
// blackhole heuristic does not flip the link mid-transfer. Window bounds the
// in-flight (unacked) bytes; 16 × 48 KiB = 768 KiB.
const (
	StreamChunkSize  = 48 * 1024
	streamWindow     = 16
	streamNegTimeout = 5 * time.Second  // wait for INIT-ACK before falling back to TypeFile
	streamStepTimeout = 60 * time.Second // max wait for an ACK / the final COMPLETE
	transferIDLen    = 16
)

// ErrStreamUnsupported is returned by SendFileStream when the peer does not
// answer INIT with an INIT-ACK within the negotiation window — i.e. it is a
// pre-TypeFileStream receiver. The caller should fall back to SendFile on a
// fresh connection.
var ErrStreamUnsupported = errors.New("dataexchange: peer does not support TypeFileStream")

// --- control-frame codec ---------------------------------------------------

func encodeStreamFrame(kind byte, id [transferIDLen]byte, body []byte) *Frame {
	p := make([]byte, 1+transferIDLen+len(body))
	p[0] = kind
	copy(p[1:1+transferIDLen], id[:])
	copy(p[1+transferIDLen:], body)
	return &Frame{Type: TypeFileStream, Payload: p}
}

func decodeStreamFrame(f *Frame) (kind byte, id [transferIDLen]byte, body []byte, ok bool) {
	if f == nil || f.Type != TypeFileStream || len(f.Payload) < 1+transferIDLen {
		return 0, id, nil, false
	}
	kind = f.Payload[0]
	copy(id[:], f.Payload[1:1+transferIDLen])
	body = f.Payload[1+transferIDLen:]
	return kind, id, body, true
}

func encodeInit(id [transferIDLen]byte, size uint64, hash [32]byte, chunkSize uint32, name string) *Frame {
	nb := []byte(name)
	if len(nb) > maxFilenameLen {
		nb = nb[:maxFilenameLen]
	}
	body := make([]byte, 8+32+4+2+len(nb))
	binary.BigEndian.PutUint64(body[0:8], size)
	copy(body[8:40], hash[:])
	binary.BigEndian.PutUint32(body[40:44], chunkSize)
	binary.BigEndian.PutUint16(body[44:46], uint16(len(nb)))
	copy(body[46:], nb)
	return encodeStreamFrame(streamKindInit, id, body)
}

func decodeInit(body []byte) (size uint64, hash [32]byte, chunkSize uint32, name string, ok bool) {
	if len(body) < 46 {
		return 0, hash, 0, "", false
	}
	size = binary.BigEndian.Uint64(body[0:8])
	copy(hash[:], body[8:40])
	chunkSize = binary.BigEndian.Uint32(body[40:44])
	nameLen := int(binary.BigEndian.Uint16(body[44:46]))
	if 46+nameLen > len(body) {
		return 0, hash, 0, "", false
	}
	name = string(body[46 : 46+nameLen])
	return size, hash, chunkSize, name, true
}

func encodeOffset(kind byte, id [transferIDLen]byte, off uint64) *Frame {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], off)
	return encodeStreamFrame(kind, id, b[:])
}

func decodeOffset(body []byte) (uint64, bool) {
	if len(body) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(body[0:8]), true
}

func encodeChunk(id [transferIDLen]byte, off uint64, data []byte) *Frame {
	body := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(body[0:8], off)
	copy(body[8:], data)
	return encodeStreamFrame(streamKindChunk, id, body)
}

func decodeChunk(body []byte) (off uint64, data []byte, ok bool) {
	if len(body) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(body[0:8]), body[8:], true
}

func encodeComplete(id [transferIDLen]byte, ok bool, msg string) *Frame {
	body := make([]byte, 1+len(msg))
	if !ok {
		body[0] = 1
	}
	copy(body[1:], msg)
	return encodeStreamFrame(streamKindComplete, id, body)
}

func decodeComplete(body []byte) (ok bool, msg string) {
	if len(body) < 1 {
		return false, "malformed complete"
	}
	return body[0] == 0, string(body[1:])
}

// --- sender ----------------------------------------------------------------

// StreamResult summarizes a completed (or failed) TypeFileStream transfer.
type StreamResult struct {
	BytesSent    int64  // chunk bytes actually written to the wire this run
	BytesResumed int64  // bytes the receiver already had (skipped)
	TotalBytes   int64  // file size
	Sha256       string // hex of the full-content hash declared in INIT
	OK           bool
	Message      string // receiver's COMPLETE message (empty on success)
}

// frameRW is the minimal connection surface the stream sender needs.
// Both *driver.Conn (the production transport) and net.Pipe ends (tests)
// satisfy it.
type frameRW interface {
	io.Reader
	io.Writer
	Close() error
}

// SendFileStream transfers a file using the chunked TypeFileStream protocol
// with a sliding window, end-to-end SHA-256 verification, and automatic
// resume (the receiver reports how many contiguous bytes it already has).
//
// Returns ErrStreamUnsupported if the peer never answers INIT with an
// INIT-ACK within the negotiation window — the caller should fall back to
// SendFile on a fresh connection. stepTimeout bounds the wait for any single
// ACK and for the final COMPLETE (0 ⇒ default).
func (c *Client) SendFileStream(name string, r io.ReadSeeker, size int64, stepTimeout time.Duration) (*StreamResult, error) {
	return streamSend(c.conn, name, r, size, stepTimeout)
}

func streamSend(conn frameRW, name string, r io.ReadSeeker, size int64, stepTimeout time.Duration) (*StreamResult, error) {
	if stepTimeout <= 0 {
		stepTimeout = streamStepTimeout
	}

	// Pass 1: hash the full content (the transfer_id is derived from it, so
	// resume across retries is automatic).
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("hash file: %w", err)
	}
	var fullHash [32]byte
	copy(fullHash[:], h.Sum(nil))
	var id [transferIDLen]byte
	copy(id[:], fullHash[:transferIDLen])
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek file: %w", err)
	}

	// INIT + negotiate.
	if err := WriteFrame(conn, encodeInit(id, uint64(size), fullHash, uint32(StreamChunkSize), name)); err != nil {
		return nil, fmt.Errorf("send INIT: %w", err)
	}
	initAck, err := recvFrameTimeout(conn, streamNegTimeout)
	if err != nil {
		return nil, ErrStreamUnsupported
	}
	kind, gotID, body, ok := decodeStreamFrame(initAck)
	if !ok || kind != streamKindInitAck || gotID != id {
		// A legacy receiver answers with a plain "ACK UNKNOWN(7)" TEXT
		// frame, or nothing useful — treat as unsupported.
		return nil, ErrStreamUnsupported
	}
	resumeOff, _ := decodeOffset(body)
	if resumeOff > uint64(size) {
		resumeOff = uint64(size) // defensive: receiver claims more than exists
	}

	// Reader goroutine owns all reads from here on. It feeds ACK offsets to
	// the window and delivers the terminal COMPLETE / error.
	acked := &atomic.Uint64{}
	acked.Store(resumeOff)
	notify := make(chan struct{}, 1)
	done := make(chan streamTerminal, 1)
	go streamReadLoop(conn, id, acked, notify, done)

	// Send chunks from the resume offset with a bounded in-flight window.
	if _, err := r.Seek(int64(resumeOff), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to resume offset: %w", err)
	}
	windowBytes := uint64(streamWindow * StreamChunkSize)
	buf := make([]byte, StreamChunkSize)
	offset := resumeOff
	for offset < uint64(size) {
		// Window gate: block until the receiver has acked enough that the
		// in-flight (unacked) bytes stay under the window.
		for offset-acked.Load() >= windowBytes {
			select {
			case <-notify:
			case t := <-done:
				return nil, t.errOrTimeout("waiting for window ACK")
			case <-time.After(stepTimeout):
				_ = conn.Close()
				return nil, fmt.Errorf("timed out after %s waiting for ACK (sent %d, acked %d)", stepTimeout, offset, acked.Load())
			}
		}
		n, rerr := io.ReadFull(r, buf)
		if n == 0 && rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read chunk at %d: %w", offset, rerr)
		}
		if werr := WriteFrame(conn, encodeChunk(id, offset, buf[:n])); werr != nil {
			return nil, fmt.Errorf("send chunk at %d: %w", offset, werr)
		}
		offset += uint64(n)
		if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
			return nil, fmt.Errorf("read chunk at %d: %w", offset, rerr)
		}
	}

	// DONE — receiver verifies the full hash and replies COMPLETE.
	if err := WriteFrame(conn, encodeStreamFrame(streamKindDone, id, nil)); err != nil {
		return nil, fmt.Errorf("send DONE: %w", err)
	}
	select {
	case t := <-done:
		if t.err != nil {
			return nil, fmt.Errorf("transfer failed: %w", t.err)
		}
		return &StreamResult{
			BytesSent:    int64(offset - resumeOff),
			BytesResumed: int64(resumeOff),
			TotalBytes:   size,
			Sha256:       hex.EncodeToString(fullHash[:]),
			OK:           t.completeOK,
			Message:      t.completeMsg,
		}, nil
	case <-time.After(stepTimeout):
		_ = conn.Close()
		return nil, fmt.Errorf("timed out after %s waiting for receiver to verify and COMPLETE", stepTimeout)
	}
}

type streamTerminal struct {
	err         error  // transport / protocol error
	completeOK  bool   // receiver verified the file
	completeMsg string // receiver's message
	complete    bool   // a COMPLETE was received
}

func (t streamTerminal) errOrTimeout(ctx string) error {
	if t.err != nil {
		return fmt.Errorf("%s: %w", ctx, t.err)
	}
	if t.complete && !t.completeOK {
		return fmt.Errorf("%s: receiver aborted: %s", ctx, t.completeMsg)
	}
	return fmt.Errorf("%s: stream closed", ctx)
}

// streamReadLoop consumes ACK and COMPLETE frames until a terminal event.
func streamReadLoop(conn frameRW, id [transferIDLen]byte, acked *atomic.Uint64, notify chan<- struct{}, done chan<- streamTerminal) {
	for {
		f, err := ReadFrame(conn)
		if err != nil {
			done <- streamTerminal{err: err}
			return
		}
		kind, gotID, body, ok := decodeStreamFrame(f)
		if !ok || gotID != id {
			continue // stray frame; ignore
		}
		switch kind {
		case streamKindAck:
			if off, ok := decodeOffset(body); ok {
				// Monotonic advance only.
				for {
					cur := acked.Load()
					if off <= cur || acked.CompareAndSwap(cur, off) {
						break
					}
				}
				select {
				case notify <- struct{}{}:
				default:
				}
			}
		case streamKindComplete:
			cok, msg := decodeComplete(body)
			done <- streamTerminal{completeOK: cok, completeMsg: msg, complete: true}
			return
		case streamKindAbort:
			done <- streamTerminal{err: fmt.Errorf("receiver abort: %s", string(body)), complete: true}
			return
		}
	}
}

// recvFrameTimeout reads one frame with a deadline, racing ReadFrame against
// a timer (driver.Conn has no read deadline we can set here). On timeout the
// blocked goroutine unwinds when the caller closes the connection.
func recvFrameTimeout(conn frameRW, d time.Duration) (*Frame, error) {
	type res struct {
		f   *Frame
		err error
	}
	ch := make(chan res, 1)
	go func() {
		f, err := ReadFrame(conn)
		ch <- res{f, err}
	}()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-time.After(d):
		return nil, fmt.Errorf("read timed out after %s", d)
	}
}

// --- receiver --------------------------------------------------------------

// StreamReceiver handles the receive side of TypeFileStream for a single
// connection. It writes incoming chunks contiguously to a .partial file
// (so the on-disk size is always the resume offset), verifies the full
// SHA-256 on DONE, and atomically renames into place. Decoupled from the
// daemon Service so it can be unit-tested with just a directory.
type StreamReceiver struct {
	receivedDir string
	onSaved     func(name, path string, size int64)
	nameSuffix  func(base string) string // produces the final unique filename

	mu        sync.Mutex
	transfers map[[transferIDLen]byte]*recvTransfer
}

type recvTransfer struct {
	file     *os.File
	partial  string
	name     string
	size     uint64
	hash     [32]byte
	cursor   uint64            // highest contiguous byte written
	pending  map[uint64][]byte // out-of-order chunks held until contiguous
	pendBytes int
}

// NewStreamReceiver builds a receiver writing into receivedDir. nameSuffix
// maps a base filename to a final unique name (nil ⇒ a timestamped default).
// onSaved (nil ok) fires after a verified file is renamed into place.
func NewStreamReceiver(receivedDir string, nameSuffix func(base string) string, onSaved func(name, path string, size int64)) *StreamReceiver {
	if nameSuffix == nil {
		nameSuffix = defaultStreamName
	}
	return &StreamReceiver{
		receivedDir: receivedDir,
		onSaved:     onSaved,
		nameSuffix:  nameSuffix,
		transfers:   make(map[[transferIDLen]byte]*recvTransfer),
	}
}

func defaultStreamName(base string) string {
	ts := time.Now().Format("20060102-150405.000")
	ext := filepath.Ext(base)
	stem := base[:len(base)-len(ext)]
	return fmt.Sprintf("%s-%s%s", stem, ts, ext)
}

// maxPendingBytes bounds the out-of-order buffer per transfer.
const maxPendingBytes = streamWindow * StreamChunkSize

// HandleFrame processes one TypeFileStream frame and returns the response
// frame to send back (nil ⇒ nothing to send). It never returns an error for
// protocol-level problems — those are reported to the peer via COMPLETE /
// ABORT frames so the connection loop stays simple.
func (sr *StreamReceiver) HandleFrame(f *Frame) *Frame {
	kind, id, body, ok := decodeStreamFrame(f)
	if !ok {
		return nil
	}
	switch kind {
	case streamKindInit:
		return sr.handleInit(id, body)
	case streamKindChunk:
		return sr.handleChunk(id, body)
	case streamKindDone:
		return sr.handleDone(id)
	case streamKindAbort:
		sr.discard(id)
		return nil
	default:
		return nil
	}
}

func (sr *StreamReceiver) handleInit(id [transferIDLen]byte, body []byte) *Frame {
	size, hash, _, name, ok := decodeInit(body)
	if !ok {
		return encodeComplete(id, false, "malformed INIT")
	}
	partialDir := filepath.Join(sr.receivedDir, ".partial")
	if err := os.MkdirAll(partialDir, 0700); err != nil {
		return encodeComplete(id, false, "mkdir partial: "+err.Error())
	}
	partial := filepath.Join(partialDir, hex.EncodeToString(id[:]))

	file, err := os.OpenFile(partial, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return encodeComplete(id, false, "open partial: "+err.Error())
	}
	// Resume from the contiguous bytes already on disk. Because we only
	// ever write contiguously, the file size IS the resume offset. Guard
	// against a stale/oversized .partial.
	info, err := file.Stat()
	var resume uint64
	if err == nil && info.Size() >= 0 && uint64(info.Size()) <= size {
		resume = uint64(info.Size())
	} else {
		_ = file.Truncate(0)
		resume = 0
	}

	sr.mu.Lock()
	// Replace any stale in-memory transfer for this id (e.g. a prior conn).
	if old := sr.transfers[id]; old != nil && old.file != nil {
		_ = old.file.Close()
	}
	sr.transfers[id] = &recvTransfer{
		file:    file,
		partial: partial,
		name:    sanitizeBase(name),
		size:    size,
		hash:    hash,
		cursor:  resume,
		pending: make(map[uint64][]byte),
	}
	sr.mu.Unlock()

	return encodeOffset(streamKindInitAck, id, resume)
}

func (sr *StreamReceiver) handleChunk(id [transferIDLen]byte, body []byte) *Frame {
	off, data, ok := decodeChunk(body)
	if !ok {
		return encodeComplete(id, false, "malformed CHUNK")
	}
	sr.mu.Lock()
	t := sr.transfers[id]
	if t == nil {
		sr.mu.Unlock()
		return encodeStreamFrame(streamKindAbort, id, []byte("no active transfer (send INIT first)"))
	}
	switch {
	case off == t.cursor:
		if werr := sr.writeAt(t, off, data); werr != nil {
			sr.mu.Unlock()
			return encodeComplete(id, false, werr.Error())
		}
		// Drain any buffered successors.
		for {
			next, has := t.pending[t.cursor]
			if !has {
				break
			}
			delete(t.pending, t.cursor)
			t.pendBytes -= len(next)
			if werr := sr.writeAt(t, t.cursor, next); werr != nil {
				sr.mu.Unlock()
				return encodeComplete(id, false, werr.Error())
			}
		}
	case off > t.cursor:
		// Out of order (transient reorder). Buffer if room; otherwise drop
		// and let the sender's window stall + retransmit re-drive it.
		if _, dup := t.pending[off]; !dup && t.pendBytes+len(data) <= maxPendingBytes {
			t.pending[off] = append([]byte(nil), data...)
			t.pendBytes += len(data)
		}
	default:
		// off < cursor: duplicate already-written bytes — ignore.
	}
	cursor := t.cursor
	sr.mu.Unlock()
	return encodeOffset(streamKindAck, id, cursor)
}

// writeAt appends a contiguous chunk at off (== cursor) and advances cursor.
// Caller holds sr.mu.
func (sr *StreamReceiver) writeAt(t *recvTransfer, off uint64, data []byte) error {
	if _, err := t.file.WriteAt(data, int64(off)); err != nil {
		return fmt.Errorf("write at %d: %w", off, err)
	}
	t.cursor += uint64(len(data))
	return nil
}

func (sr *StreamReceiver) handleDone(id [transferIDLen]byte) *Frame {
	sr.mu.Lock()
	t := sr.transfers[id]
	sr.mu.Unlock()
	if t == nil {
		return encodeComplete(id, false, "no active transfer")
	}

	if err := t.file.Sync(); err != nil {
		return encodeComplete(id, false, "fsync: "+err.Error())
	}
	if t.cursor != t.size {
		return encodeComplete(id, false, fmt.Sprintf("incomplete: have %d of %d bytes", t.cursor, t.size))
	}

	// Verify the full content hash before accepting the file.
	if _, err := t.file.Seek(0, io.SeekStart); err != nil {
		return encodeComplete(id, false, "seek for verify: "+err.Error())
	}
	h := sha256.New()
	if _, err := io.Copy(h, t.file); err != nil {
		return encodeComplete(id, false, "read for verify: "+err.Error())
	}
	if !bytes.Equal(h.Sum(nil), t.hash[:]) {
		// Keep .partial for inspection; drop the in-memory transfer.
		sr.discard(id)
		return encodeComplete(id, false, "sha256 mismatch — file corrupt, .partial retained")
	}

	_ = t.file.Close()
	finalName := sr.nameSuffix(t.name)
	finalPath := filepath.Join(sr.receivedDir, finalName)
	if err := os.Rename(t.partial, finalPath); err != nil {
		return encodeComplete(id, false, "rename: "+err.Error())
	}
	sr.forget(id)
	if sr.onSaved != nil {
		sr.onSaved(finalName, finalPath, int64(t.size))
	}
	return encodeComplete(id, true, "")
}

// discard closes and forgets a transfer but leaves the .partial on disk.
func (sr *StreamReceiver) discard(id [transferIDLen]byte) {
	sr.mu.Lock()
	if t := sr.transfers[id]; t != nil && t.file != nil {
		_ = t.file.Close()
	}
	delete(sr.transfers, id)
	sr.mu.Unlock()
}

func (sr *StreamReceiver) forget(id [transferIDLen]byte) {
	sr.mu.Lock()
	delete(sr.transfers, id)
	sr.mu.Unlock()
}

// Close releases any open .partial handles (call on connection teardown).
// The .partial files themselves remain for resume.
func (sr *StreamReceiver) Close() {
	sr.mu.Lock()
	for _, t := range sr.transfers {
		if t.file != nil {
			_ = t.file.Close()
		}
	}
	sr.transfers = make(map[[transferIDLen]byte]*recvTransfer)
	sr.mu.Unlock()
}

func sanitizeBase(name string) string {
	b := filepath.Base(name)
	if b == "." || b == "/" || b == "" {
		return "received.bin"
	}
	return b
}
