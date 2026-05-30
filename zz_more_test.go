// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"strings"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// TestTypeName covers every branch of the human-readable type mapping.
func TestTypeName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   uint32
		want string
	}{
		{TypeText, "TEXT"},
		{TypeBinary, "BINARY"},
		{TypeJSON, "JSON"},
		{TypeFile, "FILE"},
		{TypeTrace, "TRACE"},
		{999, "UNKNOWN(999)"},
	}
	for _, tc := range cases {
		if got := TypeName(tc.in); got != tc.want {
			t.Errorf("TypeName(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestWriteTraceFrame_Roundtrip covers WriteTraceFrame + ReadTracePayload.
func TestWriteTraceFrame_Roundtrip(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	tf := &TraceFrame{
		SentAtNs:  1234567890,
		InnerType: TypeText,
		Payload:   []byte("hello-trace"),
	}
	if err := WriteTraceFrame(&buf, tf); err != nil {
		t.Fatalf("WriteTraceFrame: %v", err)
	}

	// Decode the outer TypeTrace frame.
	outer, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if outer.Type != TypeTrace {
		t.Fatalf("outer.Type = %d, want TypeTrace", outer.Type)
	}

	// Decode the inner TraceFrame.
	got, err := ReadTracePayload(outer)
	if err != nil {
		t.Fatalf("ReadTracePayload: %v", err)
	}
	if got.SentAtNs != tf.SentAtNs {
		t.Errorf("SentAtNs = %d, want %d", got.SentAtNs, tf.SentAtNs)
	}
	if got.InnerType != tf.InnerType {
		t.Errorf("InnerType = %d, want %d", got.InnerType, tf.InnerType)
	}
	if !bytes.Equal(got.Payload, tf.Payload) {
		t.Errorf("Payload mismatch")
	}
}

// TestReadTracePayload_WrongType exercises the error branch.
func TestReadTracePayload_WrongType(t *testing.T) {
	t.Parallel()
	f := &Frame{Type: TypeText, Payload: make([]byte, 20)}
	if _, err := ReadTracePayload(f); err == nil {
		t.Error("expected error on non-Trace frame")
	}
}

// TestReadTracePayload_Short exercises the too-short payload branch.
func TestReadTracePayload_Short(t *testing.T) {
	t.Parallel()
	f := &Frame{Type: TypeTrace, Payload: []byte{1, 2, 3}}
	if _, err := ReadTracePayload(f); err == nil {
		t.Error("expected error on short Trace payload")
	}
}

// TestReadFrame_EOF tests the header-EOF branch.
func TestReadFrame_EOF(t *testing.T) {
	t.Parallel()
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want EOF", err)
	}
}

// TestReadFrame_TruncatedPayload tests the payload-EOF branch.
func TestReadFrame_TruncatedPayload(t *testing.T) {
	t.Parallel()
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], TypeText)
	binary.BigEndian.PutUint32(hdr[4:], 100) // claim 100-byte payload
	// Provide only 10 bytes of body.
	buf := bytes.NewReader(append(hdr[:], make([]byte, 10)...))
	if _, err := ReadFrame(buf); err == nil {
		t.Error("expected error on truncated payload")
	}
}

// TestReadFrame_FileWithoutFilename exercises the TypeFile branch
// where the name length is zero (legitimate but no filename).
func TestReadFrame_FileWithoutFilename(t *testing.T) {
	t.Parallel()
	// 2-byte zero name length + content.
	payload := append([]byte{0, 0}, []byte("content")...)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], TypeFile)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	buf := bytes.NewReader(append(hdr[:], payload...))

	f, err := ReadFrame(buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Filename != "" {
		t.Errorf("Filename = %q, want empty", f.Filename)
	}
	if !bytes.Equal(f.Payload, []byte("content")) {
		t.Errorf("Payload = %q", f.Payload)
	}
}

// TestReadFrame_FileDotName rejects single-dot filenames.
func TestReadFrame_FileDotName(t *testing.T) {
	t.Parallel()
	name := "."
	payload := make([]byte, 2+len(name))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(name)))
	copy(payload[2:], name)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[:4], TypeFile)
	binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
	if _, err := ReadFrame(bytes.NewReader(append(hdr[:], payload...))); err == nil {
		t.Error("expected error for dot-only filename")
	}
}

// TestNewService_Defaults exercises the constructor and the
// receivedDir / inboxDir helpers with explicit cfg values.
func TestNewService_DirsExplicit(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	cfg := ServiceConfig{
		ReceivedDir: filepath.Join(tmp, "rx"),
		InboxDir:    filepath.Join(tmp, "in"),
	}
	s := NewService(cfg)
	if s == nil {
		t.Fatal("NewService returned nil")
	}
	if s.Name() != "dataexchange" {
		t.Errorf("Name = %q", s.Name())
	}
	if s.Order() != 110 {
		t.Errorf("Order = %d, want 110", s.Order())
	}

	got, err := s.receivedDir()
	if err != nil || got != cfg.ReceivedDir {
		t.Errorf("receivedDir = (%q, %v), want %q", got, err, cfg.ReceivedDir)
	}
	got, err = s.inboxDir()
	if err != nil || got != cfg.InboxDir {
		t.Errorf("inboxDir = (%q, %v), want %q", got, err, cfg.InboxDir)
	}
}

// TestService_StopWithoutStart confirms Stop on a never-started Service
// is safe (cancel/listener/done all nil).
func TestService_StopWithoutStart(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{})
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("Stop without Start: %v", err)
	}
}

// TestService_SaveReceivedFile_WritesToDisk drives the file persistence
// path. Uses an explicit ReceivedDir to avoid touching $HOME/.pilot.
func TestService_SaveReceivedFile_WritesToDisk(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	s := NewService(ServiceConfig{ReceivedDir: tmp})
	s.deps = coreapi.Deps{} // Events nil — saveReceivedFile guards on it

	frame := &Frame{
		Type:     TypeFile,
		Filename: "hello.txt",
		Payload:  []byte("hi there"),
	}
	if err := s.saveReceivedFile(frame); err != nil {
		t.Fatalf("saveReceivedFile: %v", err)
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("got %d files, want 1: %v", len(entries), entries)
	}
	if !strings.HasPrefix(entries[0].Name(), "hello-") {
		t.Errorf("filename = %q, want hello-*.txt", entries[0].Name())
	}
}

// TestService_SaveInboxMessage_WritesJSON drives the message-persist
// path with both IncludeBase64 disabled and enabled.
func TestService_SaveInboxMessage_WritesJSON(t *testing.T) {
	t.Parallel()
	for _, b64 := range []bool{false, true} {
		t.Run("b64="+map[bool]string{false: "off", true: "on"}[b64], func(t *testing.T) {
			tmp := t.TempDir()
			s := NewService(ServiceConfig{InboxDir: tmp, IncludeBase64: b64})

			frame := &Frame{Type: TypeText, Payload: []byte("hello")}
			from := protocol.Addr{Network: 1, Node: 0xCAFE}
			if err := s.saveInboxMessage(frame, from); err != nil {
				t.Fatalf("saveInboxMessage: %v", err)
			}
			entries, err := os.ReadDir(tmp)
			if err != nil || len(entries) != 1 {
				t.Fatalf("ReadDir = %v (err=%v)", entries, err)
			}
			body, err := os.ReadFile(filepath.Join(tmp, entries[0].Name()))
			if err != nil {
				t.Fatalf("ReadFile: %v", err)
			}
			var msg map[string]any
			if err := json.Unmarshal(body, &msg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if msg["type"] != "TEXT" {
				t.Errorf("type = %v, want TEXT", msg["type"])
			}
			if b64 {
				// When IncludeBase64 is true, data_b64 is the canonical field;
				// data must NOT be present to avoid 2× payload blowup.
				if _, hasRaw := msg["data"]; hasRaw {
					t.Errorf("data = %v, want absent when IncludeBase64=true", msg["data"])
				}
				b64Val, hasB64 := msg["data_b64"]
				if !hasB64 {
					t.Error("data_b64 missing when IncludeBase64=true")
				} else if b64Val != base64.StdEncoding.EncodeToString([]byte("hello")) {
					t.Errorf("data_b64 = %v, want %q", b64Val, base64.StdEncoding.EncodeToString([]byte("hello")))
				}
			} else {
				if msg["data"] != "hello" {
					t.Errorf("data = %v, want hello", msg["data"])
				}
				if _, hasB64 := msg["data_b64"]; hasB64 {
					t.Error("data_b64 present when IncludeBase64=false")
				}
			}
		})
	}
}

// TestService_SaveReceivedFile_BadDir exercises the mkdir-error branch.
// On macOS/Linux, writing under /dev/null fails reliably.
func TestService_SaveReceivedFile_BadDir(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{ReceivedDir: "/dev/null/cannot-mkdir"})
	frame := &Frame{Type: TypeFile, Filename: "x", Payload: []byte("y")}
	if err := s.saveReceivedFile(frame); err == nil {
		t.Error("expected error writing under /dev/null")
	}
}
