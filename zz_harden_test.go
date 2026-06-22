// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// --- item 1: oversized declared frame rejected without a huge allocation ---

// hugeDeclaredReader presents a frame header that declares `declared` payload
// bytes but only ever yields `avail` of them. It records the largest single
// Read buffer ReadFrame asks for, so the test can prove ReadFrame never sizes
// a single allocation to the attacker-declared length.
type hugeDeclaredReader struct {
	hdr       []byte
	hdrPos    int
	avail     int64 // payload bytes we are willing to emit
	emitted   int64
	maxBufAsk int
}

func (r *hugeDeclaredReader) Read(p []byte) (int, error) {
	if len(p) > r.maxBufAsk {
		r.maxBufAsk = len(p)
	}
	// Serve the header first.
	if r.hdrPos < len(r.hdr) {
		n := copy(p, r.hdr[r.hdrPos:])
		r.hdrPos += n
		return n, nil
	}
	if r.emitted >= r.avail {
		// Declared more than we will ever send: stall as EOF so ReadFrame
		// returns a short-read error rather than spinning.
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.avail-r.emitted {
		n = int(r.avail - r.emitted)
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	r.emitted += int64(n)
	return n, nil
}

func TestReadFrame_OversizedDeclaredNoHugeAlloc(t *testing.T) {
	t.Parallel()
	// Declare a frame just under the cap (so the cap check passes) but never
	// deliver the bytes. A correct implementation must NOT allocate the
	// declared size up front; it should grow incrementally and ultimately
	// fail with a short read.
	declared := MaxFrameSize - 1
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], TypeBinary)
	binary.BigEndian.PutUint32(hdr[4:8], declared)

	r := &hugeDeclaredReader{hdr: hdr[:], avail: 0}
	_, err := ReadFrame(r)
	if err == nil {
		t.Fatal("expected error reading a frame whose declared bytes never arrive")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	// The crux: ReadFrame must never ask for a single buffer anywhere near
	// the declared length. The bounded initial reservation is 64 KiB, so any
	// single Read ask should stay within a small multiple of that.
	if int64(r.maxBufAsk) >= int64(declared) {
		t.Fatalf("ReadFrame requested a %d-byte buffer for a %d-declared frame; "+
			"it must not pre-allocate the attacker-declared size", r.maxBufAsk, declared)
	}
	if r.maxBufAsk > readBoundedInitialCap*4 {
		t.Fatalf("max single read ask = %d, want <= %d (bounded growth expected)",
			r.maxBufAsk, readBoundedInitialCap*4)
	}
}

// TestReadFrame_OverCapStillRejected keeps the header-level cap guarantee:
// a frame whose declared length exceeds the cap is rejected before any
// payload read.
func TestReadFrame_OverCapStillRejected(t *testing.T) {
	t.Parallel()
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], TypeBinary)
	binary.BigEndian.PutUint32(hdr[4:8], MaxFrameSize+1)
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("too large")) {
		t.Fatalf("err = %v, want 'frame too large'", err)
	}
}

// --- item 6: over-long filename rejected on the writer side -----------------

func TestWriteFrame_OverLongFilenameRejected(t *testing.T) {
	t.Parallel()
	long := string(bytes.Repeat([]byte("a"), maxFilenameLen+1))
	var buf bytes.Buffer
	err := WriteFrame(&buf, &Frame{Type: TypeFile, Filename: long, Payload: []byte("x")})
	if err == nil {
		t.Fatal("expected WriteFrame to reject an over-long filename before the uint16 cast")
	}
	if buf.Len() != 0 {
		t.Fatalf("WriteFrame wrote %d bytes despite rejecting the filename", buf.Len())
	}

	// A name longer than 65535 bytes would have wrapped the uint16 length
	// field; confirm that is rejected too (and never truncated onto the wire).
	wrapping := string(bytes.Repeat([]byte("b"), 1<<16+10))
	buf.Reset()
	if err := WriteFrame(&buf, &Frame{Type: TypeFile, Filename: wrapping, Payload: []byte("x")}); err == nil {
		t.Fatal("expected WriteFrame to reject a name that would wrap the uint16 length")
	}

	// A name at the limit still works and round-trips.
	ok := string(bytes.Repeat([]byte("c"), maxFilenameLen))
	buf.Reset()
	if err := WriteFrame(&buf, &Frame{Type: TypeFile, Filename: ok, Payload: []byte("ok")}); err != nil {
		t.Fatalf("WriteFrame rejected a max-length name: %v", err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if got.Filename != ok {
		t.Fatalf("filename round-trip: got %q (len %d), want len %d", got.Filename, len(got.Filename), maxFilenameLen)
	}
}

// --- item 5: binary payloads round-trip losslessly through the inbox --------

func TestSaveInboxMessage_BinaryLossless(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp}) // IncludeBase64 off by default

	// Bytes that are NOT valid UTF-8 — would be mangled to U+FFFD if stored
	// as a JSON string.
	payload := []byte{0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x80, 0xC3, 0x28}
	if err := s.saveInboxMessage(&Frame{Type: TypeBinary, Payload: payload}, protocol.Addr{Node: 1}); err != nil {
		t.Fatalf("saveInboxMessage: %v", err)
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Fatalf("inbox files = %d, want 1", len(entries))
	}
	body, _ := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
	var msg map[string]any
	if err := json.Unmarshal(body, &msg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if msg["data_encoding"] != "base64" {
		t.Fatalf("data_encoding = %v, want base64 for binary payload", msg["data_encoding"])
	}
	b64, ok := msg["data_b64"].(string)
	if !ok {
		t.Fatalf("data_b64 missing/wrong type for binary payload: %v", msg["data_b64"])
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode data_b64: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("binary payload corrupted: got %x, want %x", decoded, payload)
	}
	// And it must NOT have been written as a lossy string field.
	if _, hasRaw := msg["data"]; hasRaw {
		t.Errorf("binary payload also stored as lossy 'data' string: %v", msg["data"])
	}
}

// --- item 3: inbox total-byte cap enforced on receipt ----------------------

func TestSaveInboxMessage_ByteCapEnforced(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Small cap so a couple of writes blow past it. Each message is the
	// payload + ~256 estimated JSON overhead, so cap at ~1 KiB.
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 1024})

	from := protocol.Addr{Node: 1}
	payload := bytes.Repeat([]byte("x"), 400) // valid UTF-8

	// First write fits.
	if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
		t.Fatalf("first write should fit: %v", err)
	}
	// Keep writing; the cap must eventually reject (after eviction can no
	// longer make room, which here happens because every file is ~same size
	// and the cap holds only ~1-2 of them).
	rejected := false
	for i := 0; i < 20; i++ {
		if err := s.saveInboxMessage(&Frame{Type: TypeText, Payload: payload}, from); err != nil {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("expected the inbox byte cap to reject a write once full")
	}
	// On-disk total must never have exceeded the cap by more than one message.
	total, _ := inboxTotalBytes(tmp)
	if total > 1024+int64(len(payload))+512 {
		t.Fatalf("inbox grew to %d bytes, well past the 1024 cap", total)
	}
}

// TestEffectiveInboxMaxBytes_Defaults checks the defaulting / disable logic.
func TestEffectiveInboxMaxBytes_Defaults(t *testing.T) {
	t.Parallel()
	if got := (&Service{cfg: ServiceConfig{}}).effectiveInboxMaxBytes(); got != DefaultInboxMaxBytes {
		t.Errorf("zero ⇒ %d, want default %d", got, DefaultInboxMaxBytes)
	}
	if got := (&Service{cfg: ServiceConfig{InboxMaxBytes: -1}}).effectiveInboxMaxBytes(); got != 0 {
		t.Errorf("negative ⇒ %d, want 0 (disabled)", got)
	}
	if got := (&Service{cfg: ServiceConfig{InboxMaxBytes: 99}}).effectiveInboxMaxBytes(); got != 99 {
		t.Errorf("explicit ⇒ %d, want 99", got)
	}
}

// --- item 4: received-files quota enforced ----------------------------------

func TestSaveReceivedFile_QuotaEnforced(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{ReceivedDir: tmp, ReceivedMaxBytes: 1000})

	// First 600-byte file fits.
	if err := s.saveReceivedFile(&Frame{Type: TypeFile, Filename: "a.bin", Payload: bytes.Repeat([]byte("a"), 600)}); err != nil {
		t.Fatalf("first file should fit: %v", err)
	}
	// Second 600-byte file would push past the 1000-byte quota.
	if err := s.saveReceivedFile(&Frame{Type: TypeFile, Filename: "b.bin", Payload: bytes.Repeat([]byte("b"), 600)}); err == nil {
		t.Fatal("expected the received-files quota to reject the second file")
	}
	total, _ := dirTotalBytes(tmp)
	if total > 1000 {
		t.Fatalf("received dir grew to %d bytes, past the 1000 quota", total)
	}
}

// TestStreamReceiver_QuotaRejectsOversizedInit proves the streamed path also
// honours the disk quota: an INIT declaring more than the quota is rejected
// before any chunk is written.
func TestStreamReceiver_QuotaRejectsOversizedInit(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	sr := NewStreamReceiverWithQuota(tmp, nil, nil, 500)
	defer sr.Close()

	var id [transferIDLen]byte
	id[0] = 0xAB
	var hash [32]byte
	// Declare a 10_000-byte transfer against a 500-byte quota.
	resp := sr.HandleFrame(encodeInit(id, 10_000, hash, StreamChunkSize, "big.bin"))
	if resp == nil {
		t.Fatal("expected a COMPLETE response rejecting the oversized INIT")
	}
	ok, msg := decodeComplete(resp.Payload[1+transferIDLen:])
	if ok {
		t.Fatalf("oversized INIT was accepted; msg=%q", msg)
	}
	if !bytes.Contains([]byte(msg), []byte("quota")) {
		t.Fatalf("rejection message = %q, want it to mention the quota", msg)
	}
	// No partial should have been left on disk for this transfer.
	total, _ := dirTotalBytes(tmp)
	if total != 0 {
		t.Fatalf("quota-rejected transfer left %d bytes on disk", total)
	}
}

// --- item 2: per-connection read deadline fires on a slowloris peer ---------

// deadlineStream models *driver.Conn's deadline behaviour: Read blocks until
// either bytes arrive on `in` or the read deadline elapses, in which case it
// returns os.ErrDeadlineExceeded. This is the surface the production transport
// exposes and the handler relies on.
type deadlineStream struct {
	mu        sync.Mutex
	in        chan []byte
	out       *bytes.Buffer
	buf       []byte
	deadline  time.Time
	closed    chan struct{}
	closeOnce sync.Once
}

func newDeadlineStream() *deadlineStream {
	return &deadlineStream{in: make(chan []byte, 16), out: &bytes.Buffer{}, closed: make(chan struct{})}
}

func (s *deadlineStream) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}
	s.mu.Lock()
	dl := s.deadline
	s.mu.Unlock()
	var timer <-chan time.Time
	if !dl.IsZero() {
		if !time.Now().Before(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		timer = t.C
	}
	select {
	case data, ok := <-s.in:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, data)
		if n < len(data) {
			s.buf = data[n:]
		}
		return n, nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-s.closed:
		return 0, io.EOF
	}
}

func (s *deadlineStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.Write(p)
}
func (s *deadlineStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}
func (s *deadlineStream) LocalAddr() coreapi.Addr  { return protocol.Addr{} }
func (s *deadlineStream) LocalPort() uint16        { return 1001 }
func (s *deadlineStream) RemoteAddr() coreapi.Addr { return protocol.Addr{Node: 0xBAD} }
func (s *deadlineStream) RemotePort() uint16       { return 5555 }
func (s *deadlineStream) SetDeadline(t time.Time) error {
	return s.SetReadDeadline(t)
}
func (s *deadlineStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}
func (s *deadlineStream) SetWriteDeadline(time.Time) error { return nil }

func TestHandleConn_ReadDeadlineFires(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	// Tiny idle timeout — a peer that connects and then never sends a frame
	// must be torn down.
	svc := NewService(ServiceConfig{InboxDir: tmp, ReceivedDir: tmp, IdleTimeout: 100 * time.Millisecond})
	svc.deps = coreapi.Deps{}

	stream := newDeadlineStream() // never feeds any bytes ⇒ slowloris
	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()

	select {
	case <-done:
		// handleConn returned because the read deadline fired — good.
	case <-time.After(3 * time.Second):
		stream.Close()
		t.Fatal("handleConn did not return: read deadline never fired on an idle (slowloris) connection")
	}
}

// TestHandleConn_NoDeadlineWhenDisabled ensures a negative IdleTimeout opts
// out cleanly (handler still tears down on EOF, not on a deadline).
func TestHandleConn_NoDeadlineWhenDisabled(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp, ReceivedDir: tmp, IdleTimeout: -1})
	svc.deps = coreapi.Deps{}

	stream := newDeadlineStream()
	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()
	// With the deadline disabled the handler should still be blocked after a
	// short wait (no premature teardown).
	select {
	case <-done:
		t.Fatal("handleConn returned despite the idle deadline being disabled and no EOF")
	case <-time.After(300 * time.Millisecond):
	}
	// Closing the stream EOFs the read loop and unblocks the handler.
	stream.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not return after Close")
	}
}
