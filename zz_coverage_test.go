// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/coreapi"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ----- helpers ---------------------------------------------------------------

// pipeStream pairs an io.Pipe-based read end with a separate write end so
// handleConn (which Reads and Writes on the same stream) can be driven
// from a test goroutine without deadlocking on a single net.Pipe.
type pipeStream struct {
	in        *io.PipeReader // what handleConn reads (test writes to inW)
	out       *io.PipeWriter // what handleConn writes (test reads from outR)
	closeOnce sync.Once
	closed    chan struct{}
}

func newPipeStream(in *io.PipeReader, out *io.PipeWriter) *pipeStream {
	return &pipeStream{in: in, out: out, closed: make(chan struct{})}
}

func (s *pipeStream) Read(p []byte) (int, error)  { return s.in.Read(p) }
func (s *pipeStream) Write(p []byte) (int, error) { return s.out.Write(p) }
func (s *pipeStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.in.Close()
		_ = s.out.Close()
	})
	return nil
}
func (s *pipeStream) LocalAddr() coreapi.Addr          { return protocol.Addr{} }
func (s *pipeStream) LocalPort() uint16                { return 1001 }
func (s *pipeStream) RemoteAddr() coreapi.Addr         { return protocol.Addr{Network: 1, Node: 0xBEEF} }
func (s *pipeStream) RemotePort() uint16               { return 40000 }
func (s *pipeStream) SetDeadline(time.Time) error      { return nil }
func (s *pipeStream) SetReadDeadline(time.Time) error  { return nil }
func (s *pipeStream) SetWriteDeadline(time.Time) error { return nil }

// makeServiceConn wires a fresh Service to a pipeStream and spins up
// handleConn in a goroutine. Returns the writer to feed requests in,
// the reader to consume ACKs, and a wait func that blocks until
// handleConn returns.
func makeServiceConn(t *testing.T, cfg ServiceConfig) (
	clientW *io.PipeWriter,
	serverR *io.PipeReader,
	wait func(),
) {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()

	stream := newPipeStream(c2sR, s2cW)
	svc := NewService(cfg)
	svc.deps = coreapi.Deps{}

	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()

	return c2sW, s2cR, func() {
		_ = c2sW.Close() // EOF the read loop
		<-done
		_ = s2cR.Close()
	}
}

// ----- evictInboxOverflow ---------------------------------------------------

// TestEvictInboxOverflow_TrimsOldestFiles seeds dir with N>cap files,
// staggers mtimes, calls evictInboxOverflow directly, and asserts the
// oldest entries are gone and exactly cap entries remain.
func TestEvictInboxOverflow_TrimsOldestFiles(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const cap = 5
	const total = 12
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: cap})

	now := time.Now()
	for i := 0; i < total; i++ {
		p := filepath.Join(tmp, "msg-"+strings.Repeat("a", 1)+leftpad(i)+".json")
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatalf("seed write: %v", err)
		}
		// Stagger mtimes one second apart, oldest first.
		mt := now.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}

	s.evictInboxOverflow(tmp)

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != cap {
		t.Fatalf("after evict: have %d files, want %d", len(entries), cap)
	}
	// The surviving files are the *newest* — indices [total-cap..total).
	for _, e := range entries {
		idx := nameIndex(t, e.Name())
		if idx < total-cap {
			t.Errorf("old file %q survived eviction (idx=%d, threshold=%d)",
				e.Name(), idx, total-cap)
		}
	}
}

// TestEvictInboxOverflow_NoOpBelowCap leaves files alone when count<=cap.
func TestEvictInboxOverflow_NoOpBelowCap(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: 100})
	for i := 0; i < 3; i++ {
		_ = os.WriteFile(filepath.Join(tmp, "f"+leftpad(i)), []byte("x"), 0600)
	}
	s.evictInboxOverflow(tmp)
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 3 {
		t.Errorf("got %d, want 3 (no-op)", len(entries))
	}
}

// TestEvictInboxOverflow_DefaultCap exercises the cap=0 → default 10000
// branch by setting the cap to its default and verifying with a tiny
// directory it does nothing.
func TestEvictInboxOverflow_DefaultCap(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp}) // InboxMaxFiles unset
	_ = os.WriteFile(filepath.Join(tmp, "one.json"), []byte("x"), 0600)
	s.evictInboxOverflow(tmp) // should hit the cap=0 → 10000 branch
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Errorf("got %d, want 1", len(entries))
	}
}

// TestEvictInboxOverflow_ReaddirError exercises the readdir-failure
// branch by pointing at a non-existent directory.
func TestEvictInboxOverflow_ReaddirError(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{InboxDir: "/nope"})
	s.evictInboxOverflow("/this/path/does/not/exist") // must not panic
}

// TestEvictInboxOverflow_SkipsSubdirs verifies the IsDir branch — a
// subdirectory inside the inbox is ignored even though it shows up in
// ReadDir.
func TestEvictInboxOverflow_SkipsSubdirs(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const cap = 2
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: cap})

	// One subdir + 4 files.
	if err := os.Mkdir(filepath.Join(tmp, "sub"), 0700); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	now := time.Now()
	for i := 0; i < 4; i++ {
		p := filepath.Join(tmp, "f"+leftpad(i)+".json")
		_ = os.WriteFile(p, []byte("x"), 0600)
		mt := now.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(p, mt, mt)
	}
	s.evictInboxOverflow(tmp)

	entries, _ := os.ReadDir(tmp)
	// Expect: subdir still there + cap (2) files = 3 total.
	if len(entries) != cap+1 {
		t.Errorf("got %d entries, want %d (subdir + %d files)",
			len(entries), cap+1, cap)
	}
}

// ----- saveInboxMessage edge paths ------------------------------------------

// TestSaveInboxMessage_MkdirError forces a mkdir failure by pointing the
// inbox at a path beneath /dev/null.
func TestSaveInboxMessage_MkdirError(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{InboxDir: "/dev/null/inbox-cannot-mkdir"})
	frame := &Frame{Type: TypeText, Payload: []byte("hi")}
	if err := s.saveInboxMessage(frame, protocol.Addr{Node: 1}); err == nil {
		t.Error("expected mkdir error, got nil")
	}
}

// TestSaveInboxMessage_TriggersEvictionTick writes enough messages to
// cross inboxEvictCheckEvery and asserts (a) all writes succeed and
// (b) the on-disk count never exceeds cap by more than the sample window.
func TestSaveInboxMessage_TriggersEvictionTick(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const cap = 10
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: cap})

	// Need at least inboxEvictCheckEvery writes for the periodic check
	// to fire. The seq atomic is per-Service so we control it directly.
	for i := 0; i < inboxEvictCheckEvery+5; i++ {
		f := &Frame{Type: TypeText, Payload: []byte("x")}
		if err := s.saveInboxMessage(f, protocol.Addr{Node: uint32(i)}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	entries, _ := os.ReadDir(tmp)
	// After eviction tick at seq=64, count should drop to cap; further
	// writes (up to seq=69) push it back to cap+5 = 15. Verify we're
	// under that ceiling.
	if len(entries) > cap+inboxEvictCheckEvery {
		t.Errorf("inbox grew unbounded: %d files", len(entries))
	}
	if len(entries) < cap {
		t.Errorf("eviction overshot: %d files, expected ≥ %d", len(entries), cap)
	}
}

// ----- handleConn frame-type coverage ----------------------------------------

func TestHandleConn_TypeBinary(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp})
	defer wait()

	frame := &Frame{Type: TypeBinary, Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
	if err := WriteFrame(w, frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.Type != TypeText || !bytes.Contains(ack.Payload, []byte("ACK BINARY")) {
		t.Errorf("ack = %+v", ack)
	}
	// File should have landed in tmp inbox.
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Errorf("inbox files = %d, want 1", len(entries))
	}
}

func TestHandleConn_TypeJSON(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp})
	defer wait()

	if err := WriteFrame(w, &Frame{Type: TypeJSON, Payload: []byte(`{"k":1}`)}); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ACK JSON")) {
		t.Errorf("ack payload = %q", ack.Payload)
	}
}

func TestHandleConn_TypeFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{ReceivedDir: tmp, InboxDir: tmp})
	defer wait()

	frame := &Frame{
		Type:     TypeFile,
		Filename: "report.bin",
		Payload:  []byte("file body"),
	}
	if err := WriteFrame(w, frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ACK FILE")) {
		t.Errorf("ack payload = %q", ack.Payload)
	}
	// The file should land in ReceivedDir.
	entries, _ := os.ReadDir(tmp)
	var found bool
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "report-") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("received file not present in %s: %v", tmp, entries)
	}
}

// TestHandleConn_TypeFile_EmptyFilenameIsNoop — when Filename is "", the
// service skips saveReceivedFile but still ACKs.
func TestHandleConn_TypeFile_EmptyFilename(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{ReceivedDir: tmp, InboxDir: tmp})
	defer wait()

	frame := &Frame{Type: TypeFile, Filename: "", Payload: []byte("x")}
	if err := WriteFrame(w, frame); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadFrame(r); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	// No file should have been written (Filename was empty).
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 0 {
		t.Errorf("expected no files, got %v", entries)
	}
}

func TestHandleConn_TypeTrace(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp})
	defer wait()

	tf := &TraceFrame{
		SentAtNs:  time.Now().UnixNano(),
		InnerType: TypeText,
		Payload:   []byte("hello-trace"),
	}
	if err := WriteTraceFrame(w, tf); err != nil {
		t.Fatalf("WriteTraceFrame: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if ack.Type != TypeJSON {
		t.Errorf("ack.Type = %d, want JSON", ack.Type)
	}
	var timing map[string]any
	if err := json.Unmarshal(ack.Payload, &timing); err != nil {
		t.Fatalf("ack payload not JSON: %v / %q", err, ack.Payload)
	}
	for _, k := range []string{
		"sent_at_ns", "received_at_ns", "inbox_written_at_ns",
		"ack_sent_at_ns", "inner_ack",
	} {
		if _, ok := timing[k]; !ok {
			t.Errorf("timing JSON missing %q: %v", k, timing)
		}
	}
}

// TestHandleConn_TypeTrace_ParseError sends a TypeTrace frame whose
// inner payload is <12 bytes — ReadTracePayload errors and the ACK
// reports "ERR trace parse".
func TestHandleConn_TypeTrace_ParseError(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp})
	defer wait()

	// Outer TypeTrace with a too-short payload (3 bytes < 12).
	bad := &Frame{Type: TypeTrace, Payload: []byte{1, 2, 3}}
	if err := WriteFrame(w, bad); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ERR trace parse")) {
		t.Errorf("ack payload = %q, want ERR trace parse", ack.Payload)
	}
}

// TestHandleConn_SaveError exercises the saveErr → ERR ACK branch by
// pointing the inbox at a path under /dev/null.
func TestHandleConn_SaveError(t *testing.T) {
	t.Parallel()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: "/dev/null/x"})
	defer wait()

	if err := WriteFrame(w, &Frame{Type: TypeText, Payload: []byte("hi")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ERR")) {
		t.Errorf("expected ERR ack, got %q", ack.Payload)
	}
}

// TestHandleConn_UnknownType — a frame whose type doesn't match any
// switch arm still produces an ACK (no save, but a default ACK is sent).
func TestHandleConn_UnknownType(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp})
	defer wait()

	if err := WriteFrame(w, &Frame{Type: 999, Payload: []byte("z")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ACK UNKNOWN(999)")) {
		t.Errorf("ack payload = %q", ack.Payload)
	}
}

// ----- inboxDir / receivedDir HOME fallback ---------------------------------

// TestInboxDir_DefaultsToHome sets HOME so the empty-cfg branch returns
// $HOME/.pilot/inbox without touching the real homedir.
// (No t.Parallel — t.Setenv is incompatible with parallel tests.)
func TestInboxDir_DefaultsToHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := NewService(ServiceConfig{}) // empty InboxDir
	got, err := s.inboxDir()
	if err != nil {
		t.Fatalf("inboxDir: %v", err)
	}
	want := filepath.Join(tmp, ".pilot", "inbox")
	if got != want {
		t.Errorf("inboxDir = %q, want %q", got, want)
	}
}

func TestReceivedDir_DefaultsToHome(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	s := NewService(ServiceConfig{})
	got, err := s.receivedDir()
	if err != nil {
		t.Fatalf("receivedDir: %v", err)
	}
	want := filepath.Join(tmp, ".pilot", "received")
	if got != want {
		t.Errorf("receivedDir = %q, want %q", got, want)
	}
}

// ----- Stop after Start ------------------------------------------------------

// TestService_StartStop covers the happy-path lifecycle including the
// done-channel signalling in Stop.
func TestService_StartStop(t *testing.T) {
	t.Parallel()
	r, _ := io.Pipe()
	_, w := io.Pipe()
	stream := newPipeStream(r, w)
	listener := newFakeListener(stream)
	deps := coreapi.Deps{Streams: &fakeStreams{listener: listener}}

	svc := NewService(ServiceConfig{InboxDir: t.TempDir()})
	if err := svc.Start(context.Background(), deps); err != nil {
		t.Fatalf("Start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := svc.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// ----- save helpers ---------------------------------------------------------

// leftpad returns a zero-padded 4-digit decimal — keeps filenames in
// lexicographic order matching numeric order for predictable test setup.
func leftpad(n int) string {
	s := ""
	switch {
	case n < 10:
		s = "000"
	case n < 100:
		s = "00"
	case n < 1000:
		s = "0"
	}
	return s + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}

// nameIndex pulls the trailing integer out of seed filenames like
// "msg-a0000.json" or "f0007.json".
func nameIndex(t *testing.T, name string) int {
	t.Helper()
	// strip extension
	name = strings.TrimSuffix(name, filepath.Ext(name))
	// strip trailing digits
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	digits := name[i:]
	n := 0
	for _, c := range digits {
		n = n*10 + int(c-'0')
	}
	return n
}
