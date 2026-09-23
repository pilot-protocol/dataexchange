// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/protocol"
)

// addrPipeStream is a pipeStream whose remote (sender) address is chosen by
// the test, so several connections can come from the same or different
// peers.
type addrPipeStream struct {
	*pipeStream
	remote protocol.Addr
}

func (s *addrPipeStream) RemoteAddr() coreapi.Addr { return s.remote }

// clientEnd is the sender's side of a service connection.
type clientEnd struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (c clientEnd) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c clientEnd) Write(p []byte) (int, error) { return c.w.Write(p) }

// openServiceConn runs svc.handleConn for one connection from remote and
// returns the sender's end. The connection is torn down at test cleanup.
func openServiceConn(t *testing.T, svc *Service, remote protocol.Addr) clientEnd {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	stream := &addrPipeStream{pipeStream: newPipeStream(c2sR, s2cW), remote: remote}
	done := make(chan struct{})
	go func() {
		svc.handleConn(context.Background(), stream)
		close(done)
	}()
	t.Cleanup(func() {
		_ = c2sW.Close()
		<-done
		_ = s2cR.Close()
	})
	return clientEnd{r: s2cR, w: c2sW}
}

// inboxRecords returns the inbox JSON records in dir, oldest file first.
func inboxRecords(t *testing.T, dir string) []map[string]any {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	// Names are <TYPE>-<timestamp>-<seq>.json; order by the sequence number.
	seqOf := func(name string) string { return name[strings.LastIndex(name, "-")+1:] }
	sort.Slice(names, func(i, j int) bool { return seqOf(names[i]) < seqOf(names[j]) })
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var rec map[string]any
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		out = append(out, rec)
	}
	return out
}

var (
	peerA = protocol.Addr{Network: 1, Node: 0xA}
	peerB = protocol.Addr{Network: 1, Node: 0xB}
)

func mustSend(t *testing.T, conn io.ReadWriter, f *Frame) *SendResult {
	t.Helper()
	res, err := sendAndAwaitAck(conn, f)
	if err != nil {
		t.Fatalf("send %+v: %v", f, err)
	}
	return res
}

func TestService_TaggedMessageRecordsCorrelation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	events := newCapturingEvents()
	svc := NewService(ServiceConfig{InboxDir: tmp})
	svc.deps = coreapi.Deps{Events: events}
	conn := openServiceConn(t, svc, peerA)

	res := mustSend(t, conn, &Frame{Type: TypeText, Payload: []byte("weather?"), MessageID: "req-1"})
	if !res.Tagged || res.Duplicate || string(res.Ack.Payload) != "ACK TEXT 8 bytes" {
		t.Fatalf("request result = %+v ack=%q", res, res.Ack.Payload)
	}
	res = mustSend(t, conn, &Frame{Type: TypeJSON, Payload: []byte(`{"t":21}`), ReplyTo: "req-1"})
	if !res.Tagged || string(res.Ack.Payload) != "ACK JSON 8 bytes" {
		t.Fatalf("reply result = %+v ack=%q", res, res.Ack.Payload)
	}

	recs := inboxRecords(t, tmp)
	if len(recs) != 2 {
		t.Fatalf("inbox records = %d, want 2", len(recs))
	}
	if recs[0]["message_id"] != "req-1" || recs[0]["data"] != "weather?" {
		t.Fatalf("request record = %v", recs[0])
	}
	if _, has := recs[0]["reply_to"]; has {
		t.Fatalf("request record has a reply_to: %v", recs[0])
	}
	if recs[1]["reply_to"] != "req-1" || recs[1]["type"] != "JSON" {
		t.Fatalf("reply record = %v", recs[1])
	}
	if _, has := recs[1]["message_id"]; has {
		t.Fatalf("reply record has a message_id: %v", recs[1])
	}

	events.mu.Lock()
	defer events.mu.Unlock()
	var got []map[string]any
	for _, e := range events.published {
		if e.topic == "message.received" {
			got = append(got, e.payload)
		}
	}
	if len(got) != 2 || got[0]["message_id"] != "req-1" || got[1]["reply_to"] != "req-1" {
		t.Fatalf("message.received events = %v", got)
	}
}

// TestService_UntaggedRecordUnchanged: an old sender's frame produces exactly
// the fields it always did.
func TestService_UntaggedRecordUnchanged(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	conn := openServiceConn(t, NewService(ServiceConfig{InboxDir: tmp}), peerA)
	if _, err := conn.Write(rawFrame(TypeText, []byte("legacy"))); err != nil {
		t.Fatal(err)
	}
	ack, err := ReadFrame(conn)
	if err != nil || string(ack.Payload) != "ACK TEXT 6 bytes" {
		t.Fatalf("ack=%v err=%v", ack, err)
	}
	recs := inboxRecords(t, tmp)
	if len(recs) != 1 {
		t.Fatalf("records = %d", len(recs))
	}
	keys := make([]string, 0, len(recs[0]))
	for k := range recs[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got := strings.Join(keys, ","); got != "bytes,data,data_encoding,from,received_at,type" {
		t.Fatalf("untagged record keys = %s", got)
	}
}

func TestService_DuplicateTaggedDeliveryStoredOnce(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp})
	frame := &Frame{Type: TypeText, Payload: []byte("same bytes"), MessageID: "m-42"}

	first := mustSend(t, openServiceConn(t, svc, peerA), frame)
	if first.Duplicate {
		t.Fatal("first delivery reported as duplicate")
	}
	// Re-sends on one connection (a retry), and on another connection (a
	// relay path next to a direct one), from the same peer.
	retryConn := openServiceConn(t, svc, peerA)
	for i, conn := range []io.ReadWriter{retryConn, retryConn, openServiceConn(t, svc, peerA)} {
		res := mustSend(t, conn, frame)
		if !res.Duplicate || string(res.Ack.Payload) != "ACK TEXT 10 bytes (duplicate)" {
			t.Fatalf("re-delivery %d: result=%+v ack=%q", i, res, res.Ack.Payload)
		}
	}
	if n := len(inboxRecords(t, tmp)); n != 1 {
		t.Fatalf("inbox records = %d, want 1", n)
	}

	// The same bytes and ID from a different peer are a different message.
	if res := mustSend(t, openServiceConn(t, svc, peerB), frame); res.Duplicate {
		t.Fatal("another peer's message was suppressed")
	}
	// Same ID, different payload: not an identical delivery.
	if res := mustSend(t, retryConn, &Frame{Type: TypeText, Payload: []byte("other bytes"), MessageID: "m-42"}); res.Duplicate {
		t.Fatal("a different payload under the same ID was suppressed")
	}
	// Same payload, different type: not identical either.
	if res := mustSend(t, retryConn, &Frame{Type: TypeJSON, Payload: []byte("same bytes"), MessageID: "m-42"}); res.Duplicate {
		t.Fatal("a different frame type was suppressed")
	}
	if n := len(inboxRecords(t, tmp)); n != 4 {
		t.Fatalf("inbox records = %d, want 4", n)
	}
}

// TestService_UntaggedDuplicatesStoredByDefault: without a MessageID and
// without DedupeContentWindow, identical frames are all stored (old
// behaviour).
func TestService_UntaggedDuplicatesStoredByDefault(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	conn := openServiceConn(t, NewService(ServiceConfig{InboxDir: tmp}), peerA)
	for i := 0; i < 3; i++ {
		if res := mustSend(t, conn, &Frame{Type: TypeText, Payload: []byte("ok")}); res.Duplicate {
			t.Fatalf("send %d suppressed", i)
		}
	}
	if n := len(inboxRecords(t, tmp)); n != 3 {
		t.Fatalf("inbox records = %d, want 3", n)
	}
}

func TestService_ContentDedupeWindow(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp, DedupeContentWindow: 2 * time.Second})
	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	svc.dedupeByContent.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	advance := func(d time.Duration) { clockMu.Lock(); now = now.Add(d); clockMu.Unlock() }
	conn := openServiceConn(t, svc, peerA)

	// The list-agents pattern: one reply delivered twice within a second.
	reply := &Frame{Type: TypeJSON, Payload: []byte(`{"items":[1]}`)}
	mustSend(t, conn, reply)
	advance(700 * time.Millisecond)
	if res := mustSend(t, conn, reply); !res.Duplicate {
		t.Fatal("identical untagged frame inside the window was stored again")
	}
	// A ReplyTo-only frame is content-deduplicated too, keyed with its ReplyTo.
	correlated := &Frame{Type: TypeJSON, Payload: []byte(`{"items":[1]}`), ReplyTo: "req-9"}
	if res := mustSend(t, conn, correlated); res.Duplicate {
		t.Fatal("a reply to a different request was suppressed")
	}
	if res := mustSend(t, conn, correlated); !res.Duplicate {
		t.Fatal("identical ReplyTo-only frame inside the window was stored again")
	}
	// After the window, the same bytes are a new message.
	advance(3 * time.Second)
	if res := mustSend(t, conn, reply); res.Duplicate {
		t.Fatal("identical frame after the window was suppressed")
	}
	if n := len(inboxRecords(t, tmp)); n != 3 {
		t.Fatalf("inbox records = %d, want 3", n)
	}
}

func TestService_DedupeWindowNegativeDisables(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp, DedupeWindow: -1})
	if svc.dedupeByID != nil || svc.dedupeByContent != nil {
		t.Fatal("dedupe caches created while disabled")
	}
	conn := openServiceConn(t, svc, peerA)
	frame := &Frame{Type: TypeText, Payload: []byte("x"), MessageID: "m"}
	mustSend(t, conn, frame)
	if res := mustSend(t, conn, frame); res.Duplicate {
		t.Fatal("dedupe ran although DedupeWindow < 0")
	}
	if n := len(inboxRecords(t, tmp)); n != 2 {
		t.Fatalf("inbox records = %d, want 2", n)
	}
}

// TestService_ConcurrentIdenticalDeliveriesStoreOnce reproduces a reply that
// arrives over several paths at the same instant (the sweep saw list-agents
// duplicates 83 ns apart): exactly one copy may be stored.
func TestService_ConcurrentIdenticalDeliveriesStoreOnce(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{InboxDir: tmp})
	frame := &Frame{Type: TypeText, Payload: []byte("answer"), MessageID: NewMessageID()}

	const paths = 8
	conns := make([]clientEnd, paths)
	for i := range conns {
		conns[i] = openServiceConn(t, svc, peerA)
	}
	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		duplicates int
		errs       []error
	)
	start := make(chan struct{})
	for _, conn := range conns {
		wg.Add(1)
		go func(conn clientEnd) {
			defer wg.Done()
			<-start
			res, err := sendAndAwaitAck(conn, frame)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if res.Duplicate {
				duplicates++
			}
		}(conn)
	}
	close(start)
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("concurrent sends failed: %v", errs)
	}
	if duplicates != paths-1 {
		t.Fatalf("duplicates = %d, want %d", duplicates, paths-1)
	}
	if n := len(inboxRecords(t, tmp)); n != 1 {
		t.Fatalf("inbox records = %d, want exactly 1", n)
	}
}

// TestService_FailedDeliveryIsNotRemembered: a delivery that was not stored
// must not make its retry look like a duplicate.
func TestService_FailedDeliveryIsNotRemembered(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	inbox := filepath.Join(tmp, "inbox")
	// A regular file where the inbox directory should be: MkdirAll fails.
	if err := os.WriteFile(inbox, []byte("blocker"), 0600); err != nil {
		t.Fatal(err)
	}
	svc := NewService(ServiceConfig{InboxDir: inbox})
	conn := openServiceConn(t, svc, peerA)
	frame := &Frame{Type: TypeText, Payload: []byte("retry me"), MessageID: "r-1"}

	res, err := sendAndAwaitAck(conn, frame)
	if !errors.Is(err, ErrRejected) || res == nil || res.Duplicate {
		t.Fatalf("first attempt: res=%+v err=%v, want a rejection", res, err)
	}
	if err := os.Remove(inbox); err != nil {
		t.Fatal(err)
	}
	res = mustSend(t, conn, frame)
	if res.Duplicate {
		t.Fatal("the retry of a failed delivery was treated as a duplicate")
	}
	if n := len(inboxRecords(t, inbox)); n != 1 {
		t.Fatalf("inbox records = %d, want 1", n)
	}
}

func TestService_TaggedGovernedFrameKeepsCorrelation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	governed, verifier := newGovernedTestFrame(t, &Frame{Type: TypeText, Payload: []byte("approved")}, decision.Allow, nil)
	svc := NewService(ServiceConfig{InboxDir: tmp, RequireGoverned: true, GovernedVerifier: verifier})
	conn := openServiceConn(t, svc, peerA)

	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		t.Fatal(err)
	}
	envelope.MessageID, envelope.ReplyTo = "gov-1", "req-7"
	res := mustSend(t, conn, envelope)
	if !res.Tagged || string(res.Ack.Payload) != "ACK TEXT 8 bytes" {
		t.Fatalf("result=%+v ack=%q", res, res.Ack.Payload)
	}
	recs := inboxRecords(t, tmp)
	if len(recs) != 1 || recs[0]["message_id"] != "gov-1" || recs[0]["reply_to"] != "req-7" || recs[0]["data"] != "approved" {
		t.Fatalf("records = %v", recs)
	}
	// An identical re-delivery is acknowledged as a duplicate instead of
	// tripping the governed replay guard with an error.
	res = mustSend(t, conn, envelope)
	if !res.Duplicate || string(res.Ack.Payload) != "ACK TEXT 8 bytes (duplicate)" {
		t.Fatalf("re-delivery result=%+v ack=%q", res, res.Ack.Payload)
	}
	if n := len(inboxRecords(t, tmp)); n != 1 {
		t.Fatalf("inbox records = %d, want 1", n)
	}
}

func TestService_TaggedTraceFrameKeepsCorrelation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	conn := openServiceConn(t, NewService(ServiceConfig{InboxDir: tmp}), peerA)
	payload := make([]byte, 12+2)
	binary.BigEndian.PutUint32(payload[0:4], TypeText)
	binary.BigEndian.PutUint64(payload[4:12], uint64(time.Now().UnixNano()))
	copy(payload[12:], "hi")
	res := mustSend(t, conn, &Frame{Type: TypeTrace, Payload: payload, MessageID: "trace-1"})
	if res.Ack.Type != TypeJSON {
		t.Fatalf("trace ack type = %d", res.Ack.Type)
	}
	recs := inboxRecords(t, tmp)
	if len(recs) != 1 || recs[0]["message_id"] != "trace-1" || recs[0]["data"] != "hi" {
		t.Fatalf("records = %v", recs)
	}
}

func TestService_TaggedFileEventCarriesCorrelation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	events := newCapturingEvents()
	svc := NewService(ServiceConfig{ReceivedDir: tmp, InboxDir: t.TempDir()})
	svc.deps = coreapi.Deps{Events: events}
	conn := openServiceConn(t, svc, peerA)
	mustSend(t, conn, &Frame{Type: TypeFile, Filename: "r.txt", Payload: []byte("data"), MessageID: "f-1", ReplyTo: "req-2"})
	if res := mustSend(t, conn, &Frame{Type: TypeFile, Filename: "r.txt", Payload: []byte("data"), MessageID: "f-1", ReplyTo: "req-2"}); !res.Duplicate {
		t.Fatal("identical tagged file re-delivery was stored again")
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Fatalf("received files = %d, want 1", len(entries))
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	found := false
	for _, e := range events.published {
		if e.topic == "file.received" {
			found = e.payload["message_id"] == "f-1" && e.payload["reply_to"] == "req-2"
		}
	}
	if !found {
		t.Fatalf("file.received event lacks correlation: %v", events.published)
	}
}

// oldReceiver emulates a dataexchange receiver that predates TypeTagged: it
// reads raw frames and answers exactly as the pre-TypeTagged service did.
func oldReceiver(t *testing.T, governed bool) (clientEnd, func() []uint32, func() [][]byte) {
	t.Helper()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	var (
		mu       sync.Mutex
		types    []uint32
		payloads [][]byte
	)
	go func() {
		defer s2cW.Close()
		for {
			var hdr [8]byte
			if _, err := io.ReadFull(c2sR, hdr[:]); err != nil {
				return
			}
			ftype := binary.BigEndian.Uint32(hdr[0:4])
			payload := make([]byte, binary.BigEndian.Uint32(hdr[4:8]))
			if _, err := io.ReadFull(c2sR, payload); err != nil {
				return
			}
			mu.Lock()
			types = append(types, ftype)
			payloads = append(payloads, payload)
			mu.Unlock()
			name, known := map[uint32]string{TypeText: "TEXT", TypeJSON: "JSON", TypeBinary: "BINARY"}[ftype]
			if !known {
				name = fmt.Sprintf("UNKNOWN(%d)", ftype)
			}
			ack := fmt.Sprintf("ACK %s %d bytes", name, len(payload))
			switch {
			case governed && ftype == TypeTagged:
				// A RequireGoverned receiver rejects any non-governed type
				// before looking at it.
				ack = fmt.Sprintf("ERR %s save failed: unsigned legacy frame rejected by governed receiver", name)
			case !known:
				ack = fmt.Sprintf("ERR %s save failed: unsupported frame type %d", name, ftype)
			}
			if err := WriteFrame(s2cW, &Frame{Type: TypeText, Payload: []byte(ack)}); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = c2sW.Close(); _ = s2cR.Close() })
	seenTypes := func() []uint32 { mu.Lock(); defer mu.Unlock(); return append([]uint32(nil), types...) }
	seenPayloads := func() [][]byte { mu.Lock(); defer mu.Unlock(); return append([][]byte(nil), payloads...) }
	return clientEnd{r: s2cR, w: c2sW}, seenTypes, seenPayloads
}

// TestSend_FallsBackForOldReceiver: a sender using MessageID still reaches a
// receiver that predates TypeTagged; the message arrives once, untagged.
func TestSend_FallsBackForOldReceiver(t *testing.T) {
	t.Parallel()
	for _, governed := range []bool{false, true} {
		conn, types, payloads := oldReceiver(t, governed)
		res, err := sendAndAwaitAck(conn, &Frame{Type: TypeText, Payload: []byte("hello"), MessageID: "m-1", ReplyTo: "r-0"})
		if err != nil {
			t.Fatalf("governed=%v: send: %v", governed, err)
		}
		if res.Tagged || res.Duplicate || string(res.Ack.Payload) != "ACK TEXT 5 bytes" {
			t.Fatalf("governed=%v: result=%+v ack=%q", governed, res, res.Ack.Payload)
		}
		if got := types(); len(got) != 2 || got[0] != TypeTagged || got[1] != TypeText {
			t.Fatalf("governed=%v: old receiver saw types %v, want [TAGGED TEXT]", governed, got)
		}
		if got := payloads(); string(got[1]) != "hello" {
			t.Fatalf("governed=%v: fallback payload = %q", governed, got[1])
		}
	}
}

// TestSend_UntaggedFrameNeverRetried: a frame without metadata is sent once,
// even when the receiver rejects it.
func TestSend_UntaggedFrameNeverRetried(t *testing.T) {
	t.Parallel()
	conn, types, _ := oldReceiver(t, false)
	res, err := sendAndAwaitAck(conn, &Frame{Type: 99, Payload: []byte("x")})
	if !errors.Is(err, ErrRejected) || res == nil {
		t.Fatalf("res=%+v err=%v, want ErrRejected", res, err)
	}
	if got := types(); len(got) != 1 {
		t.Fatalf("receiver saw %d frames, want 1", len(got))
	}
}

// TestSend_NewReceiverRejectionIsNotRetried: a current receiver that rejects
// a tagged frame (here: unsigned under RequireGoverned) must not trigger the
// old-receiver fallback.
func TestSend_NewReceiverRejectionIsNotRetried(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, verifier := newGovernedTestFrame(t, &Frame{Type: TypeText, Payload: []byte("x")}, decision.Allow, nil)
	conn := openServiceConn(t, NewService(ServiceConfig{InboxDir: tmp, RequireGoverned: true, GovernedVerifier: verifier}), peerA)
	res, err := sendAndAwaitAck(conn, &Frame{Type: TypeText, Payload: []byte("unsigned"), MessageID: "m-1"})
	if !errors.Is(err, ErrRejected) || res == nil || !res.Tagged {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if !strings.HasPrefix(string(res.Ack.Payload), "ERR TEXT save failed: unsigned legacy frame rejected") {
		t.Fatalf("ack = %q", res.Ack.Payload)
	}
	if n := len(inboxRecords(t, tmp)); n != 0 {
		t.Fatalf("inbox records = %d, want 0", n)
	}
}

func TestSend_NilFrame(t *testing.T) {
	t.Parallel()
	if _, err := sendAndAwaitAck(clientEnd{}, nil); err == nil {
		t.Fatal("nil frame accepted")
	}
}

// ---- deliveryDedupe unit tests ------------------------------------------

func testKey(b byte) dedupeKey { var k dedupeKey; k[0] = b; return k }

func TestDeliveryDedupe_WaiterTakesOverFailedDelivery(t *testing.T) {
	t.Parallel()
	d := newDeliveryDedupe(time.Minute, 16)
	first, _, ok := d.claim(context.Background(), testKey(1))
	if !ok || first.cache == nil {
		t.Fatal("first claim was not granted")
	}
	type outcome struct {
		claim dedupeClaim
		dup   string
	}
	waiter := make(chan outcome, 1)
	go func() {
		c, dup, _ := d.claim(context.Background(), testKey(1))
		waiter <- outcome{c, dup}
	}()
	select {
	case <-waiter:
		t.Fatal("second claim did not wait for the in-flight delivery")
	case <-time.After(50 * time.Millisecond):
	}
	first.finish(false, "")
	got := <-waiter
	if got.claim.cache == nil {
		t.Fatalf("after the first delivery failed the waiter got duplicate %q instead of the claim", got.dup)
	}
	got.claim.finish(true, "ACK TEXT 1 bytes")

	// Now remembered: the next claim is a duplicate carrying the first ACK.
	c, dup, ok := d.claim(context.Background(), testKey(1))
	if !ok || c.cache != nil || dup != "ACK TEXT 1 bytes" {
		t.Fatalf("claim after store = %+v %q %v", c, dup, ok)
	}
}

func TestDeliveryDedupe_WaiterSeesStoredDelivery(t *testing.T) {
	t.Parallel()
	d := newDeliveryDedupe(time.Minute, 16)
	first, _, _ := d.claim(context.Background(), testKey(2))
	result := make(chan string, 1)
	go func() {
		_, dup, _ := d.claim(context.Background(), testKey(2))
		result <- dup
	}()
	time.Sleep(20 * time.Millisecond)
	first.finish(true, "ACK JSON 3 bytes")
	if got := <-result; got != "ACK JSON 3 bytes" {
		t.Fatalf("waiter duplicate ack = %q", got)
	}
}

func TestDeliveryDedupe_WaiterHonoursContext(t *testing.T) {
	t.Parallel()
	d := newDeliveryDedupe(time.Minute, 16)
	first, _, _ := d.claim(context.Background(), testKey(3))
	defer first.finish(false, "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, _, ok := d.claim(ctx, testKey(3)); ok {
		t.Fatal("claim returned ok after its context ended")
	}
}

func TestDeliveryDedupe_ExpiryAndCapacity(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000, 0)
	d := newDeliveryDedupe(10*time.Second, 2)
	d.now = func() time.Time { return now }
	store := func(k byte) {
		c, _, _ := d.claim(context.Background(), testKey(k))
		if c.cache == nil {
			t.Fatalf("key %d unexpectedly remembered", k)
		}
		c.finish(true, "ACK")
	}
	remembered := func(k byte) bool {
		c, _, _ := d.claim(context.Background(), testKey(k))
		if c.cache != nil {
			c.finish(false, "") // not remembered: release the probe
			return false
		}
		return true
	}

	store(1)
	store(2)
	if !remembered(1) || !remembered(2) {
		t.Fatal("stored keys not remembered")
	}
	store(3) // over capacity: the oldest (1) is forgotten early
	if remembered(1) || !remembered(3) {
		t.Fatal("capacity eviction did not drop the oldest entry")
	}
	now = now.Add(11 * time.Second) // past the window
	if remembered(2) || remembered(3) {
		t.Fatal("entries outlived the window")
	}
	if n := d.len(); n != 0 {
		t.Fatalf("cache holds %d entries after expiry", n)
	}
	// A zero claim is inert.
	var zero dedupeClaim
	zero.finish(true, "ignored")
}

// TestDeliveryDedupe_CompactsOrder keeps the FIFO bounded across many
// expiries.
func TestDeliveryDedupe_CompactsOrder(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000, 0)
	d := newDeliveryDedupe(time.Second, 1<<20)
	d.now = func() time.Time { return now }
	for i := 0; i < 5000; i++ {
		var k dedupeKey
		binary.BigEndian.PutUint32(k[:4], uint32(i))
		c, _, _ := d.claim(context.Background(), k)
		c.finish(true, "ACK")
		now = now.Add(10 * time.Millisecond) // ~100 live at a time
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if live := len(d.order) - d.head; live > 200 {
		t.Fatalf("%d live entries, want about 100", live)
	}
	if len(d.order) > 1000 {
		t.Fatalf("order slice grew to %d; compaction is not running", len(d.order))
	}
}

func TestDeliveryKeyFor_FieldBoundaries(t *testing.T) {
	t.Parallel()
	a := deliveryKeyFor(peerA, &Frame{Type: TypeText, MessageID: "ab", ReplyTo: "c", Payload: []byte("x")})
	b := deliveryKeyFor(peerA, &Frame{Type: TypeText, MessageID: "a", ReplyTo: "bc", Payload: []byte("x")})
	if a == b {
		t.Fatal("shifting bytes between MessageID and ReplyTo produced the same key")
	}
	c := deliveryKeyFor(peerA, &Frame{Type: TypeFile, Filename: "n", Payload: []byte("x")})
	d := deliveryKeyFor(peerA, &Frame{Type: TypeFile, Filename: "", Payload: []byte("nx")})
	if c == d {
		t.Fatal("shifting bytes between filename and payload produced the same key")
	}
}

func TestEffectiveDedupeWindow_Defaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want time.Duration }{
		{0, DefaultDedupeWindow},
		{-1, 0},
		{3 * time.Second, 3 * time.Second},
	} {
		if got := (&Service{cfg: ServiceConfig{DedupeWindow: tc.in}}).effectiveDedupeWindow(); got != tc.want {
			t.Errorf("DedupeWindow %v ⇒ %v, want %v", tc.in, got, tc.want)
		}
	}
}
