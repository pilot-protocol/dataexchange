// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"io"
	"os"
	"testing"
	"time"
)

// TestTypeName_AutoAnswer covers the new frame type's human-readable name.
func TestTypeName_AutoAnswer(t *testing.T) {
	t.Parallel()
	if got := TypeName(TypeAutoAnswer); got != "AUTOANSWER" {
		t.Fatalf("TypeName(TypeAutoAnswer) = %q, want AUTOANSWER", got)
	}
}

// TestClient_SendAutoAnswer asserts the client writes a TypeAutoAnswer frame.
func TestClient_SendAutoAnswer(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	if err := c.SendAutoAnswer(`/data {"x":1}`); err != nil {
		t.Fatalf("SendAutoAnswer: %v", err)
	}
	f, err := ReadFrame(newByteReader(waitForCompleteFrame(t, d)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeAutoAnswer {
		t.Errorf("Type = %d, want TypeAutoAnswer", f.Type)
	}
	if string(f.Payload) != `/data {"x":1}` {
		t.Errorf("Payload = %q", f.Payload)
	}
	_ = c.Close()
}

// TestClient_SetReadDeadline asserts the passthrough is wired and non-erroring.
func TestClient_SetReadDeadline(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_ = c.Close()
}

// TestService_AutoAnswer_ReplyOnConnection is the core integration test: a
// TypeAutoAnswer request to an --auto-answer service is NOT saved to the inbox,
// gets an ACK+REPLY ack, and the ReplyHook's reply is written back as a TEXT
// frame on the same connection.
func TestService_AutoAnswer_ReplyOnConnection(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	var hookSawType uint32
	var hookSawPayload string
	cfg := ServiceConfig{
		InboxDir:   tmp,
		AutoAnswer: true,
		ReplyHook: func(reqType uint32, payload []byte) (uint32, []byte, bool) {
			hookSawType = reqType
			hookSawPayload = string(payload)
			return TypeJSON, []byte(`{"source":"list-agents","tiers":{}}`), true
		},
	}
	clientW, serverR, wait := makeServiceConn(t, cfg)

	if err := WriteFrame(clientW, &Frame{Type: TypeAutoAnswer, Payload: []byte(`/data {"q":1}`)}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	ack, err := ReadFrame(serverR)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if got := string(ack.Payload); got[:9] != "ACK+REPLY" {
		t.Fatalf("ack = %q, want ACK+REPLY prefix", got)
	}
	reply, err := ReadFrame(serverR)
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	// The reply is delivered as a TEXT frame regardless of the hook's declared
	// type, so a plain reply-aware sender reads it as a normal message.
	if reply.Type != TypeText {
		t.Errorf("reply.Type = %d, want TypeText", reply.Type)
	}
	if string(reply.Payload) != `{"source":"list-agents","tiers":{}}` {
		t.Errorf("reply payload = %q", reply.Payload)
	}
	if hookSawType != TypeAutoAnswer || hookSawPayload != `/data {"q":1}` {
		t.Errorf("hook saw type=%d payload=%q", hookSawType, hookSawPayload)
	}
	wait() // closes the client half → graceful close completes

	// AutoAnswer requests must NOT be saved to the inbox (answered on-connection,
	// so the responder never double-handles them).
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 0 {
		t.Errorf("inbox has %d files, want 0 (AutoAnswer must skip the inbox)", len(entries))
	}
}

// TestService_AutoAnswer_PlainTextUnaffected proves an --auto-answer node serves
// a CURRENT sender (plain TEXT) exactly as before: saved to inbox, plain ACK, no
// reply-on-connection. This is the shielding guarantee.
func TestService_AutoAnswer_PlainTextUnaffected(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	hookCalled := false
	cfg := ServiceConfig{
		InboxDir:   tmp,
		AutoAnswer: true,
		ReplyHook: func(uint32, []byte) (uint32, []byte, bool) {
			hookCalled = true
			return TypeText, []byte("should not happen"), true
		},
	}
	clientW, serverR, wait := makeServiceConn(t, cfg)

	if err := WriteFrame(clientW, &Frame{Type: TypeText, Payload: []byte("hello")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	ack, err := ReadFrame(serverR)
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if got := string(ack.Payload); len(got) >= 9 && got[:9] == "ACK+REPLY" {
		t.Errorf("plain TEXT got ACK+REPLY ack (%q) — should be a plain ACK", got)
	}
	wait()

	if hookCalled {
		t.Error("ReplyHook fired for a plain TEXT frame — auto-answer must only run for TypeAutoAnswer")
	}
	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Errorf("inbox has %d files, want 1 (plain TEXT must be saved as today)", len(entries))
	}
}

// TestService_AutoAnswer_FallbackWhenDisabled proves a TypeAutoAnswer frame
// reaching a node that does NOT auto-answer falls back to a normal inbox save
// (so it still gets a dial-back reply) instead of being lost.
func TestService_AutoAnswer_FallbackWhenDisabled(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := ServiceConfig{InboxDir: tmp /* AutoAnswer: false */}
	clientW, serverR, wait := makeServiceConn(t, cfg)

	if err := WriteFrame(clientW, &Frame{Type: TypeAutoAnswer, Payload: []byte("/data {}")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadFrame(serverR); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	wait()

	entries, _ := os.ReadDir(tmp)
	if len(entries) != 1 {
		t.Errorf("inbox has %d files, want 1 (AutoAnswer frame must fall back to inbox on a non-AA node)", len(entries))
	}
}

// TestService_AutoAnswer_NoReplyWhenHookDeclines: when the dispatch declines
// (e.g. classification dropped the message), no reply frame is written and the
// connection closes after the ack.
func TestService_AutoAnswer_NoReplyWhenHookDeclines(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := ServiceConfig{
		InboxDir:   tmp,
		AutoAnswer: true,
		ReplyHook: func(uint32, []byte) (uint32, []byte, bool) {
			return 0, nil, false // declined (loop-prevention drop)
		},
	}
	clientW, serverR, wait := makeServiceConn(t, cfg)

	if err := WriteFrame(clientW, &Frame{Type: TypeAutoAnswer, Payload: []byte("prose, not a command")}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := ReadFrame(serverR); err != nil {
		t.Fatalf("read ack: %v", err)
	}
	// No reply frame: the next read sees EOF because handleConn returned.
	if _, err := ReadFrame(serverR); err != io.EOF && err == nil {
		t.Errorf("expected EOF / no reply after a declined hook, got err=%v", err)
	}
	wait()
}
