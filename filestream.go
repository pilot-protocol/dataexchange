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
	"crypto/rand"
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
	"syscall"
	"time"
)

// Stream control-frame kinds (the first byte of a TypeFileStream payload).
const (
	streamKindInit     byte = 0x01 // sender→receiver: filename, size, full hash, chunk size
	streamKindChunk    byte = 0x02 // sender→receiver: offset + chunk bytes
	streamKindAck      byte = 0x03 // receiver→sender: highest contiguous offset received
	streamKindDone     byte = 0x04 // sender→receiver: end of stream; verify full hash
	streamKindInitAck  byte = 0x05 // receiver→sender: resume offset (presence ⇒ peer supports stream)
	streamKindComplete byte = 0x06 // receiver→sender: final status after DONE
	streamKindAbort    byte = 0x07 // either direction: cancel + reason
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
	StreamChunkSize   = 48 * 1024
	streamWindow      = 16
	streamNegTimeout  = 5 * time.Second  // wait for INIT-ACK before falling back to TypeFile
	streamStepTimeout = 60 * time.Second // max wait for an ACK / the final COMPLETE
	transferIDLen     = 16
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
	if 46+nameLen != len(body) {
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
// SendFile on a fresh connection. A receiver that refuses the transfer at
// INIT (quota, disk space, too many transfers) answers with a COMPLETE
// instead; that comes back as a StreamResult with OK false and the reason in
// Message, and a nil error — not as ErrStreamUnsupported, since falling back
// would push the whole file at a peer that has just declined it.
// stepTimeout bounds the wait for any single ACK and for the final COMPLETE
// (0 ⇒ default).
func (c *Client) SendFileStream(name string, r io.ReadSeeker, size int64, stepTimeout time.Duration) (*StreamResult, error) {
	return streamSend(c.conn, name, r, size, stepTimeout)
}

func streamSend(conn frameRW, name string, r io.ReadSeeker, size int64, stepTimeout time.Duration) (*StreamResult, error) {
	return streamSendWithInit(conn, name, r, size, stepTimeout, func(id [transferIDLen]byte, declaredSize uint64, hash [32]byte, chunkSize uint32, filename string) (*Frame, error) {
		return encodeInit(id, declaredSize, hash, chunkSize, filename), nil
	})
}

// streamInitBuilder builds the INIT frame for a transfer, so the frame that
// opens a stream can vary while the chunk/ACK/resume state machine stays
// the same.
type streamInitBuilder func([transferIDLen]byte, uint64, [32]byte, uint32, string) (*Frame, error)

func streamSendWithInit(conn frameRW, name string, r io.ReadSeeker, size int64, stepTimeout time.Duration, buildInit streamInitBuilder) (*StreamResult, error) {
	if buildInit == nil {
		return nil, fmt.Errorf("dataexchange: stream INIT builder is required")
	}
	if size < 0 {
		return nil, fmt.Errorf("dataexchange: stream size must not be negative")
	}
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
	init, err := buildInit(id, uint64(size), fullHash, uint32(StreamChunkSize), name)
	if err != nil {
		return nil, fmt.Errorf("build INIT: %w", err)
	}
	if err := WriteFrame(conn, init); err != nil {
		return nil, fmt.Errorf("send INIT: %w", err)
	}
	initAck, err := recvFrameTimeout(conn, streamNegTimeout)
	if err != nil {
		return nil, ErrStreamUnsupported
	}
	kind, gotID, body, ok := decodeStreamFrame(initAck)
	if ok && kind == streamKindComplete && gotID == id {
		// The receiver speaks the protocol and said no (quota, disk full,
		// too many transfers). That is a refusal to report, not an old
		// receiver to retry against with the single-frame path — which
		// would push the whole file at a peer that just declined it.
		_, msg := decodeComplete(body)
		return &StreamResult{
			TotalBytes: size,
			Sha256:     hex.EncodeToString(fullHash[:]),
			OK:         false,
			Message:    msg,
		}, nil
	}
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
	// onPrepare runs after full-content integrity verification but before the
	// atomic rename. It lets a caller durably record work for the final path
	// before that path can become visible after a crash.
	onPrepare func([transferIDLen]byte, string, string, int64) error
	// onCommit runs after integrity verification and atomic rename, but before
	// onSaved. A required receipt recorder uses it to make the visible file
	// contingent on durable enforcement evidence; a callback error removes the
	// just-renamed file and turns COMPLETE into a failure.
	onCommit   func([transferIDLen]byte, string, string, int64) error
	nameSuffix func(base string) string // produces the final unique filename

	// quotaBytes caps total on-disk bytes under receivedDir (completed files
	// + .partial fragments). Enforced on INIT (declared size) and on every
	// chunk write so a peer cannot overrun the disk mid-stream. Zero ⇒ no
	// quota.
	quotaBytes int64

	mu        sync.Mutex
	transfers map[[transferIDLen]byte]*recvTransfer
}

type recvTransfer struct {
	file    *os.File
	partial string
	// private marks a .partial that only this transfer can use: another
	// live transfer already held the content-addressed one, so this one got
	// its own. Nothing can resume it, so it is removed if it does not finish.
	private bool
	// claim is this transfer's hold on partial (see activePartials). A retry
	// can take a stalled transfer's claim over; the old transfer then stops
	// writing.
	claim     *partialClaim
	name      string
	size      uint64
	hash      [32]byte
	cursor    uint64            // highest contiguous byte written
	pending   map[uint64][]byte // out-of-order chunks held until contiguous
	pendBytes int
	// quotaBudget is the number of additional bytes this transfer may still
	// write to disk before tripping the receiver quota. Snapshotted at INIT
	// (quota minus everything already on disk other than this .partial) and
	// debited as contiguous chunks land. -1 ⇒ unlimited (quota disabled).
	quotaBudget int64
}

// activePartials is the set of .partial paths a live transfer is writing.
//
// A .partial is named after the content hash so a retry resumes it. That also
// means two transfers of the same content at once — two peers sending the
// same file, or one sender on two connections — would open the same path,
// interleave their writes, and the second to finish would fail its rename
// because the first already moved the file. The first transfer to arrive
// claims the path; a concurrent one writes to a private .partial instead.
//
// A claim whose holder has written nothing for staleClaimAfter can be taken
// over. That is a sender retrying after a stall: it reconnects while this
// receiver still holds the stalled connection open (until the idle timeout,
// minutes later). The retry takes the .partial over and resumes where the
// stalled transfer stopped; the stalled one is refused any further write,
// its DONE, and the file itself if it sends a new INIT. Only an INIT that is
// accepted takes a claim over: one refused for quota, disk space or too many
// transfers leaves the quiet holder its file.
var activePartials = struct {
	sync.Mutex
	paths map[string]*partialClaim
}{paths: make(map[string]*partialClaim)}

// partialClaim is one transfer's hold on a .partial path.
type partialClaim struct {
	lastWrite time.Time
}

// live reports whether c's holder has written recently enough to keep it.
// Caller holds activePartials.
func (c *partialClaim) live() bool {
	return time.Since(c.lastWrite) < staleClaimAfter
}

// staleClaimAfter is how long a claim's holder may go without writing before
// another transfer of the same content may take the claim over.
//
// It is twice streamStepTimeout, the sender's default wait for each ACK
// before it gives up (pilotctl send-file sets 90s). A live transfer can be
// quiet for most of that wait — retransmission backoff, a very slow link.
// Taking its file over then would fail a transfer that was still going, and
// its sender would report the file rejected even though the other transfer
// delivered the content.
//
// The cost is on the retry side. A retry that arrives within this window —
// a sender reconnecting quickly while this receiver still holds the
// half-open connection of its first attempt — finds the .partial held, gets
// a private file like any concurrent transfer of the same content, and
// starts over from offset 0. The first attempt's .partial stays on disk
// meanwhile and counts against the quota (near the quota, enough to get the
// retry refused) until its connection times out and a later retry resumes
// it.
//
// A variable so tests can shorten it.
var staleClaimAfter = 2 * streamStepTimeout

// partialHeld reports whether a live transfer holds path.
func partialHeld(path string) bool {
	activePartials.Lock()
	defer activePartials.Unlock()
	held := activePartials.paths[path]
	return held != nil && held.live()
}

// claimPartial takes path for a new transfer, taking it over from a holder
// that has gone quiet; prev is that holder's claim (nil if path was free).
// It returns a nil claim when a live transfer holds path.
func claimPartial(path string) (c, prev *partialClaim) {
	activePartials.Lock()
	defer activePartials.Unlock()
	prev = activePartials.paths[path]
	if prev != nil && prev.live() {
		return nil, nil
	}
	c = &partialClaim{lastWrite: time.Now()}
	activePartials.paths[path] = c
	return c, prev
}

// stillHolds reports whether c is still the claim on path, and records a
// write by its holder when it is. A claim just refreshed cannot be taken
// over for staleClaimAfter, so a holder may act on the file right after.
func stillHolds(path string, c *partialClaim) bool {
	if c == nil {
		return true // a transfer that never needed a claim
	}
	activePartials.Lock()
	defer activePartials.Unlock()
	if activePartials.paths[path] != c {
		return false
	}
	c.lastWrite = time.Now()
	return true
}

// releasePartial gives up c's claim on path, if it still holds it.
func releasePartial(path string, c *partialClaim) {
	unclaimPartial(path, c, nil)
}

// unclaimPartial gives up c's claim on path, if it still holds it, and hands
// the path back to prev, the claim c took over (nil: leave it free).
func unclaimPartial(path string, c, prev *partialClaim) {
	activePartials.Lock()
	defer activePartials.Unlock()
	if activePartials.paths[path] != c {
		return
	}
	if prev != nil {
		activePartials.paths[path] = prev
	} else {
		delete(activePartials.paths, path)
	}
}

// privatePartial names a .partial only one transfer uses, beside the
// content-addressed one at shared.
func privatePartial(shared string) (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return shared + "." + hex.EncodeToString(suffix[:]), nil
}

// release gives up t's claim on its .partial and, for a private one, removes
// the file (a no-op once a finished transfer has renamed it into place).
func (t *recvTransfer) release() {
	releasePartial(t.partial, t.claim)
	if t.private {
		_ = os.Remove(t.partial)
	}
}

// errPartialTakenOver is returned to a stalled transfer whose .partial a
// retry of the same transfer has taken over.
var errPartialTakenOver = errors.New("a newer transfer of this file has taken it over")

// diskReserveBytes is left free on the receiving filesystem: a transfer that
// would take the disk below it is refused at INIT, so a large file cannot
// leave the node unable to store messages or its own state.
const diskReserveBytes = 16 << 20

// freeDiskBytes reports the space available on the filesystem holding dir;
// ok is false where that cannot be determined. A variable so tests can set it.
var freeDiskBytes = platformFreeDiskBytes

// NewStreamReceiver builds a receiver writing into receivedDir. nameSuffix
// maps a base filename to a final unique name (nil ⇒ a timestamped default).
// onSaved (nil ok) fires after a verified file is renamed into place. No disk
// quota is enforced — use NewStreamReceiverWithQuota to bound on-disk bytes.
func NewStreamReceiver(receivedDir string, nameSuffix func(base string) string, onSaved func(name, path string, size int64)) *StreamReceiver {
	return NewStreamReceiverWithQuotaAndCommit(receivedDir, nameSuffix, onSaved, nil, 0)
}

// NewStreamReceiverWithQuota is NewStreamReceiver with a disk quota:
// quotaBytes caps the total on-disk bytes under receivedDir (completed files
// plus retained .partial fragments). Enforced on INIT and on every chunk
// write so a peer cannot fill the disk mid-stream. Zero ⇒ unlimited.
func NewStreamReceiverWithQuota(receivedDir string, nameSuffix func(base string) string, onSaved func(name, path string, size int64), quotaBytes int64) *StreamReceiver {
	return NewStreamReceiverWithQuotaAndCommit(receivedDir, nameSuffix, onSaved, nil, quotaBytes)
}

// NewStreamReceiverWithQuotaAndCommit extends the normal receiver with a
// transactional commit hook: the hook runs after the final file is durable
// but before consumers are notified. A hook failure removes the final file
// and reports COMPLETE failure.
func NewStreamReceiverWithQuotaAndCommit(receivedDir string, nameSuffix func(base string) string, onSaved func(name, path string, size int64), onCommit func([transferIDLen]byte, string, string, int64) error, quotaBytes int64) *StreamReceiver {
	return NewStreamReceiverWithQuotaAndPrepareAndCommit(receivedDir, nameSuffix, onSaved, nil, onCommit, quotaBytes)
}

// NewStreamReceiverWithQuotaAndPrepareAndCommit adds a pre-rename durable
// preparation hook to the commit path. A preparation error leaves no
// final file visible; callers may keep the partial for retry/inspection.
func NewStreamReceiverWithQuotaAndPrepareAndCommit(receivedDir string, nameSuffix func(base string) string, onSaved func(name, path string, size int64), onPrepare, onCommit func([transferIDLen]byte, string, string, int64) error, quotaBytes int64) *StreamReceiver {
	if nameSuffix == nil {
		nameSuffix = defaultStreamName
	}
	if quotaBytes < 0 {
		quotaBytes = 0
	}
	return &StreamReceiver{
		receivedDir: receivedDir,
		onSaved:     onSaved,
		onPrepare:   onPrepare,
		onCommit:    onCommit,
		nameSuffix:  nameSuffix,
		quotaBytes:  quotaBytes,
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

// maxConcurrentTransfers caps how many in-flight receives one StreamReceiver
// (i.e. one peer connection) may hold open at once.
//
// handleInit opens a real *os.File per transfer and stores it under a
// PEER-CHOSEN 16-byte transfer ID. Without a cap, a peer could issue INIT
// repeatedly with fresh IDs and hold one file descriptor plus one .partial
// file each, exhausting the process FD limit in seconds. The existing
// quotaBytes gate bounds BYTES on disk but says nothing about descriptor
// count or map cardinality — and NewStreamReceiver defaults quota to 0,
// meaning unlimited.
//
// 64 is far above any legitimate use (bundles transfer a handful of files
// at a time) while keeping worst-case FD use per connection trivial.
const maxConcurrentTransfers = 64

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
	shared := filepath.Join(partialDir, hex.EncodeToString(id[:]))

	sr.mu.Lock()
	prior := sr.transfers[id]
	if prior != nil && !stillHolds(prior.partial, prior.claim) {
		// A second INIT for a transfer whose .partial a retry on another
		// connection has since taken over. The file is the retry's now:
		// drop this transfer without touching it, and start over as a new
		// one.
		delete(sr.transfers, id)
		if prior.file != nil {
			_ = prior.file.Close()
		}
		prior = nil
	}
	// A new id when already at capacity is refused before anything else:
	// no claim taken, no descriptor opened.
	full := prior == nil && len(sr.transfers) >= maxConcurrentTransfers
	sr.mu.Unlock()
	if full {
		return encodeComplete(id, false, "too many concurrent transfers")
	}

	partial, private := shared, false
	goPrivate := func() error {
		p, err := privatePartial(shared)
		partial, private = p, true
		return err
	}
	var claim, prev *partialClaim
	if prior != nil {
		// A second INIT for a transfer this receiver already holds: keep
		// its .partial (and the claim on it, refreshed just above).
		partial, private, claim = prior.partial, prior.private, prior.claim
	} else if partialHeld(shared) {
		// Another live transfer is writing this content. Take a private
		// .partial rather than share the file with it.
		if err := goPrivate(); err != nil {
			return encodeComplete(id, false, "partial name: "+err.Error())
		}
	}

	// Everything that can refuse the transfer runs before the claim is
	// taken: an INIT that is refused must not take the .partial over from a
	// holder that has only gone quiet.
	quotaBudget, refusal := sr.admit(partial, size)
	if refusal != "" {
		return encodeComplete(id, false, refusal)
	}
	if prior == nil {
		if claim, prev = claimPartial(partial); claim == nil {
			// A live transfer of the same content claimed the .partial
			// since partialHeld looked. Go private after all; that file
			// starts empty, so check again.
			if err := goPrivate(); err != nil {
				return encodeComplete(id, false, "partial name: "+err.Error())
			}
			if quotaBudget, refusal = sr.admit(partial, size); refusal != "" {
				return encodeComplete(id, false, refusal)
			}
			claim, prev = claimPartial(partial)
		}
	}
	// fail reports an INIT refused after the claim was taken, handing the
	// claim back to the transfer it was taken from.
	fail := func(reason string) *Frame {
		if prior == nil {
			unclaimPartial(partial, claim, prev)
			if private {
				_ = os.Remove(partial)
			}
		}
		return encodeComplete(id, false, reason)
	}

	file, err := os.OpenFile(partial, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fail("open partial: " + err.Error())
	}

	sr.mu.Lock()
	old := sr.transfers[id]
	if old == nil && len(sr.transfers) >= maxConcurrentTransfers {
		// Checked above, but another INIT can have taken the last slot
		// since. Release the file we just opened, or this rejection would
		// leak the very FD it exists to protect.
		sr.mu.Unlock()
		_ = file.Close()
		return fail("too many concurrent transfers")
	}
	// Resume from the contiguous bytes already on disk, as admit counted
	// on. A stale/oversized .partial starts over.
	info, err := file.Stat()
	resume := resumeOffset(info, err, size)
	if resume == 0 {
		_ = file.Truncate(0)
	}
	// Replace the in-memory transfer this INIT repeats, if any.
	if old != nil && old.file != nil {
		_ = old.file.Close()
	}
	sr.transfers[id] = &recvTransfer{
		file:        file,
		partial:     partial,
		private:     private,
		claim:       claim,
		name:        sanitizeBase(name),
		size:        size,
		hash:        hash,
		cursor:      resume,
		pending:     make(map[uint64][]byte),
		quotaBudget: quotaBudget,
	}
	sr.mu.Unlock()

	return encodeOffset(streamKindInitAck, id, resume)
}

// admit runs the checks that can refuse a transfer of size bytes into
// partial, without touching the file. It returns the transfer's quota budget
// (-1 without a quota), or why the transfer is refused.
func (sr *StreamReceiver) admit(partial string, size uint64) (quotaBudget int64, refusal string) {
	// Quota gate: reject up front if the declared size cannot fit alongside
	// what is already on disk (excluding this transfer's own .partial, which
	// resume credits back). Bounds disk use before a single chunk lands.
	quotaBudget = -1
	if sr.quotaBytes > 0 {
		used := dirSizeExcluding(sr.receivedDir, partial)
		budget := sr.quotaBytes - used
		if budget < 0 {
			budget = 0
		}
		// Compared unsigned: a declared size past the int64 range would
		// otherwise come out negative and pass.
		if size > uint64(budget) {
			return 0, fmt.Sprintf("receiver disk quota exceeded: need %d, %d of %d available",
				size, budget, sr.quotaBytes)
		}
		quotaBudget = budget
	}

	// Disk gate: the quota is a fixed number and can be larger than the
	// disk. Refuse now what cannot fit, instead of failing mid-transfer with
	// the disk full and the bytes already written stranded in a .partial.
	if free, ok := freeDiskBytes(filepath.Dir(partial)); ok {
		info, err := os.Stat(partial)
		need := size - resumeOffset(info, err, size)
		if need > free || free-need < diskReserveBytes {
			return 0, fmt.Sprintf("receiver disk full: need %d bytes, %d free (keeping %d in reserve)",
				need, free, int64(diskReserveBytes))
		}
	}
	return quotaBudget, ""
}

// resumeOffset is where a transfer of size bytes picks up in a .partial
// described by info (err from the stat). We only ever write contiguously, so
// the file size IS the resume offset — unless there is no file, or it is
// longer than the transfer and so stale: then it starts over at 0.
func resumeOffset(info os.FileInfo, err error, size uint64) uint64 {
	if err == nil && info.Size() >= 0 && uint64(info.Size()) <= size {
		return uint64(info.Size())
	}
	return 0
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
	// A chunk has to fit inside the size declared at INIT. Checking here
	// rather than at DONE keeps the .partial file bounded by the size the
	// receiver agreed to, whether the chunk is written now or buffered
	// for later.
	if off > t.size || uint64(len(data)) > t.size-off {
		sr.mu.Unlock()
		return encodeComplete(id, false,
			fmt.Sprintf("chunk at %d of %d bytes exceeds declared size %d", off, len(data), t.size))
	}
	switch {
	case off == t.cursor:
		if werr := sr.writeAt(t, off, data); werr != nil {
			sr.mu.Unlock()
			return sr.writeFailed(id, werr)
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
				return sr.writeFailed(id, werr)
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
// Caller holds sr.mu. Debits the per-transfer disk-quota budget and refuses
// the write if it would overrun, so a peer that lies about its declared size
// (sends more chunk bytes than INIT promised) still cannot exceed the quota.
func (sr *StreamReceiver) writeAt(t *recvTransfer, off uint64, data []byte) error {
	if !stillHolds(t.partial, t.claim) {
		return errPartialTakenOver
	}
	if t.quotaBudget >= 0 {
		if int64(len(data)) > t.quotaBudget {
			return fmt.Errorf("receiver disk quota exceeded at offset %d", off)
		}
		t.quotaBudget -= int64(len(data))
	}
	if _, err := t.file.WriteAt(data, int64(off)); err != nil {
		return fmt.Errorf("write at %d: %w", off, err)
	}
	t.cursor += uint64(len(data))
	return nil
}

// writeFailed answers a chunk whose write failed. A transfer whose file a
// retry has taken over can never write again, so it is ended here rather than
// holding its descriptor until the connection closes; one that ran the disk
// full is abandoned.
func (sr *StreamReceiver) writeFailed(id [transferIDLen]byte, werr error) *Frame {
	if errors.Is(werr, errPartialTakenOver) {
		sr.discard(id)
	} else {
		sr.abandonIfDiskFull(id, werr)
	}
	return encodeComplete(id, false, werr.Error())
}

func (sr *StreamReceiver) handleDone(id [transferIDLen]byte) *Frame {
	sr.mu.Lock()
	t := sr.transfers[id]
	sr.mu.Unlock()
	if t == nil {
		return encodeComplete(id, false, "no active transfer")
	}
	if !stillHolds(t.partial, t.claim) {
		// A retry of this transfer has taken the file over; it finishes it.
		sr.discard(id)
		return encodeComplete(id, false, errPartialTakenOver.Error())
	}

	if err := t.file.Sync(); err != nil {
		return encodeComplete(id, false, "fsync: "+err.Error())
	}
	if t.cursor != t.size {
		return encodeComplete(id, false, fmt.Sprintf("incomplete: have %d of %d bytes", t.cursor, t.size))
	}

	// Verify the full content hash before accepting the file. Reading
	// through the claim keeps it fresh while a large file is hashed, and
	// stops the hash if a retry has taken the file over all the same.
	if _, err := t.file.Seek(0, io.SeekStart); err != nil {
		return encodeComplete(id, false, "seek for verify: "+err.Error())
	}
	h := sha256.New()
	if _, err := io.Copy(h, heldReader{t}); err != nil {
		if errors.Is(err, errPartialTakenOver) {
			sr.discard(id)
			return encodeComplete(id, false, err.Error())
		}
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
	if sr.onPrepare != nil {
		if err := sr.onPrepare(id, finalName, finalPath, int64(t.size)); err != nil {
			sr.forget(id)
			return encodeComplete(id, false, "prepare: "+err.Error())
		}
	}
	// The claim again, right before the rename: fsync, the hash and
	// onPrepare all take time, and a retry that took the file over
	// meanwhile is writing it now. The check refreshes the claim, so it
	// cannot be taken over between here and the rename.
	if !stillHolds(t.partial, t.claim) {
		sr.forget(id)
		return encodeComplete(id, false, errPartialTakenOver.Error())
	}
	if err := os.Rename(t.partial, finalPath); err != nil {
		// Drop the in-memory transfer. t.file was already closed above, so
		// leaving the entry in place stranded a record holding a closed
		// handle — and a retried DONE for the same id would then read from
		// that closed file. The sha-mismatch branch above already calls
		// discard; this branch was the one that returned without any
		// cleanup. The .partial is deliberately left on disk for
		// inspection/resume, exactly as in the mismatch case.
		sr.forget(id)
		return encodeComplete(id, false, "rename: "+err.Error())
	}
	if sr.onCommit != nil {
		if err := sr.onCommit(id, finalName, finalPath, int64(t.size)); err != nil {
			if removeErr := os.Remove(finalPath); removeErr != nil && !os.IsNotExist(removeErr) {
				err = fmt.Errorf("%w; remove uncommitted file: %v", err, removeErr)
			}
			sr.forget(id)
			return encodeComplete(id, false, "commit: "+err.Error())
		}
	}
	sr.forget(id)
	if sr.onSaved != nil {
		sr.onSaved(finalName, finalPath, int64(t.size))
	}
	return encodeComplete(id, true, "")
}

// heldReader reads t's .partial while t still holds its claim, refreshing the
// claim on every read so a long verification does not make the transfer look
// stalled. Once a retry has taken the file over it fails with
// errPartialTakenOver.
type heldReader struct{ t *recvTransfer }

func (r heldReader) Read(p []byte) (int, error) {
	if !stillHolds(r.t.partial, r.t.claim) {
		return 0, errPartialTakenOver
	}
	return r.t.file.Read(p)
}

// discard closes and forgets a transfer but leaves the .partial on disk
// (unless it is a private one, which nothing could resume).
func (sr *StreamReceiver) discard(id [transferIDLen]byte) {
	sr.mu.Lock()
	t := sr.transfers[id]
	delete(sr.transfers, id)
	sr.mu.Unlock()
	if t != nil {
		if t.file != nil {
			_ = t.file.Close()
		}
		t.release()
	}
}

func (sr *StreamReceiver) forget(id [transferIDLen]byte) {
	sr.mu.Lock()
	t := sr.transfers[id]
	delete(sr.transfers, id)
	sr.mu.Unlock()
	if t != nil {
		t.release()
	}
}

// abandonIfDiskFull ends a transfer whose write failed for lack of space and
// deletes its .partial. Keeping it would hold the disk full — the receiver
// could then store neither messages nor its own state — for the sake of a
// resume that cannot succeed until space is freed anyway.
func (sr *StreamReceiver) abandonIfDiskFull(id [transferIDLen]byte, werr error) {
	if !errors.Is(werr, syscall.ENOSPC) {
		return
	}
	sr.mu.Lock()
	t := sr.transfers[id]
	delete(sr.transfers, id)
	sr.mu.Unlock()
	if t == nil {
		return
	}
	if t.file != nil {
		_ = t.file.Close()
	}
	// Delete the file while the claim is still held, then release it: once
	// released, another transfer can claim the path and create a new file
	// there. A retry that has taken the file over owns it; leave it be.
	if stillHolds(t.partial, t.claim) {
		_ = os.Remove(t.partial)
	}
	t.release()
}

// Close releases any open .partial handles (call on connection teardown).
// The .partial files themselves remain for resume, except private ones.
func (sr *StreamReceiver) Close() {
	sr.mu.Lock()
	transfers := sr.transfers
	sr.transfers = make(map[[transferIDLen]byte]*recvTransfer)
	sr.mu.Unlock()
	for _, t := range transfers {
		if t.file != nil {
			_ = t.file.Close()
		}
		t.release()
	}
}

// dirSizeExcluding sums the on-disk size of every regular file under dir,
// recursively, skipping the single file at excludePath (this transfer's own
// .partial, whose resume bytes are credited back into the budget). A missing
// directory counts as zero. Best-effort: unreadable entries are skipped.
func dirSizeExcluding(dir, excludePath string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if path == excludePath {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func sanitizeBase(name string) string {
	b := filepath.Base(name)
	if b == "." || b == "/" || b == "" {
		return "received.bin"
	}
	return b
}
