// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// ---- saveReceivedFile error branches ---------------------------------------

// TestSaveReceivedFile_WriteFails forces the os.WriteFile branch to fail by
// pre-creating the destination as a *directory* with the same name pattern
// the service will generate. The current code uses a timestamp + seq counter
// so the dest path isn't predictable — instead, point ReceivedDir at a
// read-only directory and assert the write errors.
func TestSaveReceivedFile_WriteFails(t *testing.T) {
	t.Parallel()
	// Make a directory that we'll then chmod 0500 (read+exec, no write).
	// On macOS/Linux, os.WriteFile under it must fail with EACCES.
	tmp := t.TempDir()
	ro := filepath.Join(tmp, "ro")
	if err := os.Mkdir(ro, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(ro, 0500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		// Restore so t.TempDir cleanup can remove it.
		_ = os.Chmod(ro, 0700)
	})

	// If we're running as root (CI sometimes does), the chmod won't matter.
	// Skip in that case rather than emit a noisy failure.
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod-based EACCES test cannot assert")
	}

	s := NewService(ServiceConfig{ReceivedDir: ro})
	frame := &Frame{
		Type:     TypeFile,
		Filename: "victim.bin",
		Payload:  []byte("body"),
	}
	if err := s.saveReceivedFile(frame); err == nil {
		t.Error("expected write to fail under read-only dir")
	}
}

// TestSaveReceivedFile_EmitsEvent verifies the Events.Publish call site for
// the file.received topic (a path the round-1 happy-path test didn't hit
// because it set deps.Events to nil).
func TestSaveReceivedFile_EmitsEvent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	events := newCapturingEvents()
	s := NewService(ServiceConfig{ReceivedDir: tmp})
	s.deps = coreapi.Deps{Events: events}

	frame := &Frame{
		Type:     TypeFile,
		Filename: "data.bin",
		Payload:  []byte("xyz"),
	}
	if err := s.saveReceivedFile(frame); err != nil {
		t.Fatalf("saveReceivedFile: %v", err)
	}
	if len(events.published) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events.published))
	}
	if events.published[0].topic != "file.received" {
		t.Errorf("topic = %q, want file.received", events.published[0].topic)
	}
}

// TestSaveInboxMessage_EmitsEvent — corresponding message.received event
// branch in saveInboxMessage. Round 1 happy-path passed deps.Events = nil.
func TestSaveInboxMessage_EmitsEvent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	events := newCapturingEvents()
	s := NewService(ServiceConfig{InboxDir: tmp})
	s.deps = coreapi.Deps{Events: events}

	frame := &Frame{Type: TypeText, Payload: []byte("ping")}
	if err := s.saveInboxMessage(frame, protocol.Addr{Node: 7}); err != nil {
		t.Fatalf("saveInboxMessage: %v", err)
	}
	if len(events.published) != 1 || events.published[0].topic != "message.received" {
		t.Errorf("expected one message.received event, got %+v", events.published)
	}
}

// ---- WriteFrame error branches --------------------------------------------

// TestWriteFrame_HeaderWriteError forces the first w.Write (header) to fail.
// failingWriter returns an error on the very first call.
func TestWriteFrame_HeaderWriteError(t *testing.T) {
	t.Parallel()
	fw := &failingWriter{failAfter: 0} // fail immediately
	err := WriteFrame(fw, &Frame{Type: TypeText, Payload: []byte("x")})
	if err == nil {
		t.Error("expected header-write error")
	}
}

// TestWriteFrame_PayloadWriteError forces the SECOND w.Write to fail (the
// payload), exercising the path where the header lands but the body errors.
func TestWriteFrame_PayloadWriteError(t *testing.T) {
	t.Parallel()
	fw := &failingWriter{failAfter: 1} // first write OK, second fails
	err := WriteFrame(fw, &Frame{Type: TypeText, Payload: []byte("payload")})
	if err == nil {
		t.Error("expected payload-write error")
	}
}

// ---- handleConn write-error branch ----------------------------------------

// TestHandleConn_AckWriteFailureExits — handleConn aborts when WriteFrame on
// the ACK fails (e.g. remote closed the socket mid-conversation). We feed a
// valid TypeText frame in, then close the read side of the response pipe so
// the server's ACK write errors. handleConn must return without panicking.
func TestHandleConn_AckWriteFailureExits(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp})

	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	stream := &abortableStream{r: c2sR, w: s2cW, closed: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()

	// Send one valid frame so handleConn enters the ACK path.
	if err := WriteFrame(c2sW, &Frame{Type: TypeText, Payload: []byte("hi")}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	// Slam the read side of the response pipe shut — the server's pending
	// ACK write will now error. CloseWithError propagates io.ErrClosedPipe.
	_ = s2cR.CloseWithError(errors.New("client gone"))

	select {
	case <-done:
		// expected: handleConn exits after the failed ACK write
	case <-time.After(2 * time.Second):
		t.Fatal("handleConn did not exit after ACK write failure")
	}
	_ = c2sW.Close()
}

// ---- Stop() ctx-cancel branch ---------------------------------------------

// TestService_Stop_CtxCancelled exercises the `case <-ctx.Done()` branch in
// Stop(). We start a service whose acceptLoop is parked on a listener that
// never returns, then call Stop with an already-cancelled context. Stop
// must return ctx.Err() instead of blocking on s.done.
func TestService_Stop_CtxCancelled(t *testing.T) {
	t.Parallel()
	// A listener whose Accept blocks forever (no Close() unblock).
	hangLn := &hangingListener{block: make(chan struct{})}
	deps := coreapi.Deps{Streams: &hangingStreams{ln: hangLn}}

	svc := NewService(ServiceConfig{InboxDir: t.TempDir()})
	if err := svc.Start(context.Background(), deps); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Cancel BEFORE Stop is invoked so the select hits ctx.Done() first.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := svc.Stop(ctx)
	if err == nil {
		t.Error("expected ctx.Err() from Stop with cancelled ctx")
	}
	// Cleanup: unblock the listener so the goroutine can exit before
	// the test process tears down.
	close(hangLn.block)
}

// ---- evictInboxOverflow edge cases / PILOT-183 -----------------------------

// TestEvictInboxOverflow_PILOT183_SubdirMixedWithFiles documents the
// current (buggy) behaviour: when the inbox dir contains a mix of regular
// files and subdirectories, the early-return "len(entries) <= cap" check
// uses the *raw* entry count (files + subdirs). If a single subdir pushes
// entries past cap but the file count is exactly cap, eviction is skipped
// — even when the real file count then climbs *past* cap on the next save.
//
// The reverse: if entries > cap due to subdirs alone (no files over cap),
// we still enter the loop. We assert the loop's *second* guard
// (`len(files) <= cap`) correctly short-circuits so no real file is wrongly
// evicted just because a subdirectory inflated the entry count.
//
// REMOVE THIS COMMENT WHEN PILOT-183 LANDS: the fix will move the
// IsDir() filter ABOVE the first early-return so both checks operate on
// the same population.
func TestEvictInboxOverflow_PILOT183_SubdirMixedWithFiles(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const cap = 3
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: cap})

	// 2 subdirs + 3 regular files. entries = 5, files = 3.
	// First early-return (entries <= cap) is FALSE → proceeds.
	// Loop filters out 2 dirs → files = 3.
	// Second guard (len(files) <= cap) is TRUE → returns without evicting.
	for _, sub := range []string{"sub1", "sub2"} {
		if err := os.Mkdir(filepath.Join(tmp, sub), 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		p := filepath.Join(tmp, "msg-"+strings.Repeat("z", 1)+itoa(i)+".json")
		if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		mt := now.Add(time.Duration(i) * time.Second)
		_ = os.Chtimes(p, mt, mt)
	}

	s.evictInboxOverflow(tmp)

	// Expect ALL 5 entries to still be there (no false eviction).
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 5 {
		t.Errorf("after evict: %d entries, want 5 (2 subdirs + 3 files preserved)",
			len(entries))
	}
}

// TestEvictInboxOverflow_PILOT183_SubdirInflatesEntries documents the
// inverse: with cap=3 and 3 real files + 1 subdir, entries=4 → the first
// early-return is FALSE → loop runs, files=3, second guard returns →
// no eviction. Files are preserved.
func TestEvictInboxOverflow_PILOT183_SubdirInflatesEntries(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	const cap = 3
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxFiles: cap})

	if err := os.Mkdir(filepath.Join(tmp, "child"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < 3; i++ {
		p := filepath.Join(tmp, "f"+itoa(i)+".json")
		_ = os.WriteFile(p, []byte("x"), 0600)
	}

	s.evictInboxOverflow(tmp)

	entries, _ := os.ReadDir(tmp)
	if len(entries) != 4 {
		t.Errorf("got %d entries, want 4 (child dir + 3 files)", len(entries))
	}
}

// ---- handleConn TypeTrace + IncludeBase64 path ----------------------------

// TestHandleConn_TypeText_IncludeBase64 exercises the IncludeBase64=true
// branch via the saveInboxMessage call.
func TestHandleConn_TypeText_IncludeBase64(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp, IncludeBase64: true})

	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	stream := &abortableStream{r: c2sR, w: s2cW, closed: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()

	if err := WriteFrame(c2sW, &Frame{Type: TypeJSON, Payload: []byte(`{"a":1}`)}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	ack, err := ReadFrame(s2cR)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !bytes.Contains(ack.Payload, []byte("ACK JSON")) {
		t.Errorf("ack = %q", ack.Payload)
	}
	// Read the saved JSON and confirm data_b64 is present.
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Fatalf("inbox files = %d, want 1", len(entries))
	}
	body, err := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(body, []byte(`"data_b64"`)) {
		t.Errorf("expected data_b64 in saved JSON, got %s", body)
	}

	_ = c2sW.Close()
	_ = s2cR.Close()
	<-done
}

// ---- helpers ---------------------------------------------------------------

// failingWriter is an io.Writer that returns an error after `failAfter`
// successful writes (zero ⇒ first write fails).
type failingWriter struct {
	failAfter int
	count     int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.count >= w.failAfter {
		return 0, errors.New("simulated write failure")
	}
	w.count++
	return len(p), nil
}

// abortableStream is a coreapi.Stream that wraps two io.Pipe halves and
// lets the test slam the response side shut. Distinct from pipeStream in
// zz_coverage_test.go because we expose the underlying writer for forced
// errors.
type abortableStream struct {
	r         *io.PipeReader
	w         *io.PipeWriter
	closed    chan struct{}
	closeOnce sync.Once
}

func (s *abortableStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *abortableStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *abortableStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.r.Close()
		_ = s.w.Close()
	})
	return nil
}
func (s *abortableStream) LocalAddr() coreapi.Addr          { return protocol.Addr{} }
func (s *abortableStream) LocalPort() uint16                { return 1001 }
func (s *abortableStream) RemoteAddr() coreapi.Addr         { return protocol.Addr{Node: 0xCAFE} }
func (s *abortableStream) RemotePort() uint16               { return 33000 }
func (s *abortableStream) SetDeadline(time.Time) error      { return nil }
func (s *abortableStream) SetReadDeadline(time.Time) error  { return nil }
func (s *abortableStream) SetWriteDeadline(time.Time) error { return nil }

// hangingListener.Accept blocks until block is closed. Used to force
// acceptLoop to never return so Stop's ctx-cancel branch fires.
type hangingListener struct {
	block chan struct{}
}

func (l *hangingListener) Accept() (coreapi.Stream, error) {
	<-l.block
	return nil, errors.New("hanging listener: unblocked")
}
func (l *hangingListener) Close() error       { return nil }
func (l *hangingListener) Addr() coreapi.Addr { return protocol.Addr{} }
func (l *hangingListener) Port() uint16       { return 1001 }

type hangingStreams struct {
	ln coreapi.Listener
}

func (s *hangingStreams) Listen(port uint16) (coreapi.Listener, error) {
	return s.ln, nil
}
func (s *hangingStreams) Dial(context.Context, coreapi.Addr, uint16) (coreapi.Stream, error) {
	return nil, errors.New("not implemented")
}
func (s *hangingStreams) SendDatagram(context.Context, coreapi.Addr, uint16, []byte) error {
	return errors.New("not implemented")
}

// capturingEvents records published events for assertion.
type capturingEvents struct {
	mu        sync.Mutex
	published []publishedEvent
}

type publishedEvent struct {
	topic   string
	payload map[string]any
}

func newCapturingEvents() *capturingEvents { return &capturingEvents{} }

func (e *capturingEvents) Publish(topic string, data map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.published = append(e.published, publishedEvent{topic: topic, payload: data})
}

// Subscribe is required by coreapi.EventBus but unused in these tests —
// return a closed channel + no-op unsubscribe so the contract is honoured.
func (e *capturingEvents) Subscribe(pattern string) (<-chan coreapi.Event, func()) {
	ch := make(chan coreapi.Event)
	close(ch)
	return ch, func() {}
}

// ---- PILOT-276: inbox byte-budget cap ----------------------------------

// TestSaveInboxMessage_ByteBudgetEnforced verifies that when InboxMaxBytes is
// set, saveInboxMessage rejects writes that would exceed the budget.
func TestSaveInboxMessage_ByteBudgetEnforced(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 512})

	// First message (small) must succeed.
	frame := &Frame{Type: TypeText, Payload: []byte("hello")}
	if err := s.saveInboxMessage(frame, protocol.Addr{Node: 1}); err != nil {
		t.Fatalf("first save under budget must succeed: %v", err)
	}

	// Second message — the inbox JSON overhead + data should push over 512.
	// Force the test by writing a payload that fills the rest of the budget.
	// After the first save, let's check how many files exist.
	entries, _ := os.ReadDir(tmp)
	t.Logf("entries after first save: %d", len(entries))

	// Save enough messages to exceed 512 bytes total.
	for i := 0; i < 20; i++ {
		frame := &Frame{Type: TypeText, Payload: []byte(strings.Repeat("x", 50))}
		err := s.saveInboxMessage(frame, protocol.Addr{Node: 2})
		if err != nil {
			t.Logf("saveInboxMessage #%d failed as expected: %v", i+2, err)
			return // success — budget enforced
		}
	}
	t.Error("expected saveInboxMessage to eventually reject when over byte budget")
}

// TestSaveInboxMessage_NoByteBudget_Unbounded documents that with
// InboxMaxBytes unset (zero), old behaviour is preserved — writes are
// never rejected on byte count.
func TestSaveInboxMessage_NoByteBudget_Unbounded(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp}) // InboxMaxBytes=0 (unset)

	for i := 0; i < 5; i++ {
		frame := &Frame{Type: TypeText, Payload: []byte(strings.Repeat("y", 200))}
		if err := s.saveInboxMessage(frame, protocol.Addr{Node: 3}); err != nil {
			t.Fatalf("save #%d with no byte budget must not reject: %v", i+1, err)
		}
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 5 {
		t.Errorf("got %d files, want 5", len(entries))
	}
}

// TestEvictInboxOverflow_ByteBasedEvictsOldest verifies that when
// InboxMaxBytes is set, evictInboxOverflow uses total bytes (not file
// count) to decide what to delete.
func TestEvictInboxOverflow_ByteBasedEvictsOldest(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{InboxDir: tmp, InboxMaxBytes: 200})

	now := time.Now()
	// Write 3 files totalling > 200 bytes. Oldest should get evicted.
	files := []struct {
		name    string
		content string
		age     time.Duration
	}{
		{"old.json", strings.Repeat("a", 100), -10 * time.Second},
		{"mid.json", strings.Repeat("b", 80), -5 * time.Second},
		{"new.json", strings.Repeat("c", 60), -1 * time.Second},
	}
	for _, f := range files {
		p := filepath.Join(tmp, f.name)
		if err := os.WriteFile(p, []byte(f.content), 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		mt := now.Add(f.age)
		_ = os.Chtimes(p, mt, mt)
	}

	s.evictInboxOverflow(tmp)

	entries, _ := os.ReadDir(tmp)
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	t.Logf("remaining entries: %v", names)

	// old.json (oldest, 100 bytes) may have been evicted to get under 200.
	// At a minimum, the total remaining bytes must not exceed 200.
	var total int64
	for _, e := range entries {
		info, _ := e.Info()
		total += info.Size()
	}
	if total > 200 {
		t.Errorf("total bytes after eviction = %d, want <= 200", total)
	}
}

// Ensure capturingEvents satisfies coreapi.EventBus at compile time.
var _ coreapi.EventBus = (*capturingEvents)(nil)

// keep binary.BigEndian referenced — used inside frame helpers in
// zz_client_test.go but the import gets flagged unused here otherwise.
var _ = binary.BigEndian
