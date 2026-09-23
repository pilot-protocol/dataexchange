// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// rawFrame builds wire bytes by hand, bypassing WriteFrame's validation.
func rawFrame(ftype uint32, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], ftype)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(payload)))
	copy(out[8:], payload)
	return out
}

// rawTaggedPayload builds a TypeTagged payload from a literal header.
func rawTaggedPayload(header string, innerType uint32, inner []byte) []byte {
	out := make([]byte, 2+len(header)+4+len(inner))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(header)))
	copy(out[2:], header)
	binary.BigEndian.PutUint32(out[2+len(header):], innerType)
	copy(out[2+len(header)+4:], inner)
	return out
}

// TestWriteFrame_UntaggedWireFormatUnchanged pins the bytes of a frame
// without correlation metadata: older peers must see exactly the original
// format.
func TestWriteFrame_UntaggedWireFormatUnchanged(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: TypeText, Payload: []byte("hi")}); err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0, 0, 0, 2, 'h', 'i'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("untagged text frame = %v, want %v", buf.Bytes(), want)
	}

	buf.Reset()
	if err := WriteFrame(&buf, &Frame{Type: TypeFile, Filename: "a", Payload: []byte("z")}); err != nil {
		t.Fatal(err)
	}
	want = []byte{0, 0, 0, 4, 0, 0, 0, 4, 0, 1, 'a', 'z'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("untagged file frame = %v, want %v", buf.Bytes(), want)
	}
}

func TestTaggedFrame_RoundTrip(t *testing.T) {
	t.Parallel()
	id := NewMessageID()
	for _, tc := range []Frame{
		{Type: TypeText, Payload: []byte("what is the weather"), MessageID: id},
		{Type: TypeJSON, Payload: []byte(`{"q":1}`), ReplyTo: id},
		{Type: TypeBinary, Payload: []byte{0, 0xFF, 7}, MessageID: "reply-1", ReplyTo: id},
		{Type: TypeFile, Filename: "report.csv", Payload: []byte("a,b"), MessageID: id},
		{Type: TypeText, Payload: []byte{}, MessageID: id},
	} {
		tc := tc
		var buf bytes.Buffer
		if err := WriteFrame(&buf, &tc); err != nil {
			t.Fatalf("WriteFrame(%+v): %v", tc, err)
		}
		if got := binary.BigEndian.Uint32(buf.Bytes()[0:4]); got != TypeTagged {
			t.Fatalf("on-wire type = %d, want TypeTagged", got)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got.Type != tc.Type || !bytes.Equal(got.Payload, tc.Payload) || got.Filename != tc.Filename ||
			got.MessageID != tc.MessageID || got.ReplyTo != tc.ReplyTo {
			t.Fatalf("round trip = %+v, want %+v", got, tc)
		}
	}
}

func TestTaggedFrame_WriteRejectsInvalidIDs(t *testing.T) {
	t.Parallel()
	for _, f := range []Frame{
		{Type: TypeText, MessageID: strings.Repeat("a", MaxMessageIDLen+1)},
		{Type: TypeText, MessageID: "has space"},
		{Type: TypeText, ReplyTo: "quote\""},
		{Type: TypeText, ReplyTo: "slash/../x"},
		{Type: TypeText, MessageID: "ünïcode"},
		{Type: TypeTagged, MessageID: "nested"},
		{Type: TypeFile, Filename: strings.Repeat("n", maxFilenameLen+1), MessageID: "ok"},
	} {
		f := f
		var buf bytes.Buffer
		if err := WriteFrame(&buf, &f); err == nil {
			t.Errorf("WriteFrame(%+v) accepted an invalid frame", f)
		}
		if buf.Len() != 0 {
			t.Errorf("WriteFrame(%+v) wrote %d bytes before failing", f, buf.Len())
		}
	}
	// The longest valid ID is accepted.
	var buf bytes.Buffer
	if err := WriteFrame(&buf, &Frame{Type: TypeText, MessageID: strings.Repeat("A", MaxMessageIDLen)}); err != nil {
		t.Fatalf("max-length ID rejected: %v", err)
	}
}

func TestTaggedFrame_ReadRejectsMalformed(t *testing.T) {
	t.Parallel()
	cases := map[string][]byte{
		"empty payload":        {},
		"one byte":             {0},
		"zero header length":   rawTaggedPayload("", TypeText, []byte("x")),
		"truncated inner type": append([]byte{0, 2}, []byte("{}")...),
		"header past end":      {0, 50, '{', '}'},
		"not json":             rawTaggedPayload("nope", TypeText, []byte("x")),
		"wrong json type":      rawTaggedPayload(`{"message_id":7}`, TypeText, []byte("x")),
		"invalid id chars":     rawTaggedPayload(`{"message_id":"a b"}`, TypeText, []byte("x")),
		"id too long":          rawTaggedPayload(`{"reply_to":"`+strings.Repeat("r", MaxMessageIDLen+1)+`"}`, TypeText, []byte("x")),
		"nested tagged":        rawTaggedPayload(`{"message_id":"a"}`, TypeTagged, rawTaggedPayload(`{}`, TypeText, nil)),
		"traversal filename":   rawTaggedPayload(`{"message_id":"a"}`, TypeFile, append([]byte{0, 4}, []byte("../x")...)),
	}
	huge := make([]byte, 2+maxTaggedHeaderLen+1+4)
	binary.BigEndian.PutUint16(huge[0:2], maxTaggedHeaderLen+1)
	cases["header too long"] = huge

	for name, payload := range cases {
		if _, err := ReadFrame(bytes.NewReader(rawFrame(TypeTagged, payload))); err == nil {
			t.Errorf("%s: ReadFrame accepted a malformed tagged frame", name)
		}
	}
}

// TestTaggedFrame_ReadIgnoresUnknownHeaderKeys: later versions may add header
// fields; this version must still deliver the frame.
func TestTaggedFrame_ReadIgnoresUnknownHeaderKeys(t *testing.T) {
	t.Parallel()
	payload := rawTaggedPayload(`{"message_id":"m-1","trace_parent":"00-abc","priority":3}`, TypeJSON, []byte(`{"a":1}`))
	f, err := ReadFrame(bytes.NewReader(rawFrame(TypeTagged, payload)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeJSON || f.MessageID != "m-1" || f.ReplyTo != "" || string(f.Payload) != `{"a":1}` {
		t.Fatalf("frame = %+v", f)
	}
	// An empty header object is a tagged frame without metadata.
	f, err = ReadFrame(bytes.NewReader(rawFrame(TypeTagged, rawTaggedPayload(`{}`, TypeText, []byte("x")))))
	if err != nil || f.Type != TypeText || f.MessageID != "" || string(f.Payload) != "x" {
		t.Fatalf("empty header: frame=%+v err=%v", f, err)
	}
}

func TestNewMessageID(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		id := NewMessageID()
		if len(id) != 32 || !ValidMessageID(id) {
			t.Fatalf("NewMessageID() = %q, want 32 valid hex characters", id)
		}
		if seen[id] {
			t.Fatalf("NewMessageID repeated %q", id)
		}
		seen[id] = true
	}
}

func TestValidMessageID(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{
		"":                                     false,
		"abc":                                  true,
		"01J9Z8X5Q3R4T6Y7U8I9O0P1A2":           true, // ULID
		"123e4567-e89b-12d3-a456-426614174000": true, // UUID
		"req:42.retry_1":                       true,
		"a b":                                  false,
		"a\nb":                                 false,
		"a/b":                                  false,
		strings.Repeat("x", MaxMessageIDLen):   true,
		strings.Repeat("x", MaxMessageIDLen+1): false,
	} {
		if got := ValidMessageID(id); got != want {
			t.Errorf("ValidMessageID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestTypeName_Tagged(t *testing.T) {
	t.Parallel()
	if got := TypeName(TypeTagged); got != "TAGGED" {
		t.Fatalf("TypeName(TypeTagged) = %q", got)
	}
}

func FuzzTaggedFrameRoundTrip(f *testing.F) {
	f.Add(uint32(TypeText), []byte("hello"), "id-1", "")
	f.Add(uint32(TypeJSON), []byte(`{}`), "", "reply")
	f.Add(uint32(TypeBinary), []byte{0, 1, 2}, "a", "b")
	f.Fuzz(func(t *testing.T, ftype uint32, payload []byte, messageID, replyTo string) {
		if ftype == TypeTagged || ftype == TypeFile {
			return // not a caller-level frame type / filename covered elsewhere
		}
		frame := &Frame{Type: ftype, Payload: payload, MessageID: messageID, ReplyTo: replyTo}
		var buf bytes.Buffer
		if err := WriteFrame(&buf, frame); err != nil {
			if (messageID == "" || ValidMessageID(messageID)) && (replyTo == "" || ValidMessageID(replyTo)) {
				t.Fatalf("WriteFrame rejected valid metadata %q/%q: %v", messageID, replyTo, err)
			}
			return
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		if got.Type != ftype || !bytes.Equal(got.Payload, payload) || got.MessageID != messageID || got.ReplyTo != replyTo {
			t.Fatalf("round trip mismatch: %+v", got)
		}
	})
}

func FuzzTaggedFrameRead(f *testing.F) {
	f.Add(rawTaggedPayload(`{"message_id":"a"}`, TypeText, []byte("x")))
	f.Add([]byte{0, 0})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	f.Fuzz(func(t *testing.T, payload []byte) {
		// Must not panic; a nil error must come with a non-tagged frame
		// whose metadata is valid.
		got, err := ReadFrame(bytes.NewReader(rawFrame(TypeTagged, payload)))
		if err != nil {
			return
		}
		if got.Type == TypeTagged {
			t.Fatal("ReadFrame returned a nested TypeTagged frame")
		}
		if (got.MessageID != "" && !ValidMessageID(got.MessageID)) || (got.ReplyTo != "" && !ValidMessageID(got.ReplyTo)) {
			t.Fatalf("ReadFrame accepted invalid metadata %q/%q", got.MessageID, got.ReplyTo)
		}
	})
}

// TestClient_Send_TaggedThroughDriver drives Client.Send over the real
// driver: the tagged frame goes out as TypeTagged and the ACK comes back.
func TestClient_Send_TaggedThroughDriver(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	type outcome struct {
		res *SendResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := c.Send(&Frame{Type: TypeText, Payload: []byte("q"), MessageID: "abc", ReplyTo: "xyz"})
		done <- outcome{res, err}
	}()

	body := waitForCompleteFrame(t, d)
	if got := binary.BigEndian.Uint32(body[0:4]); got != TypeTagged {
		t.Fatalf("on-wire type = %d, want TypeTagged", got)
	}
	sent, err := ReadFrame(newByteReader(body))
	if err != nil {
		t.Fatalf("decode sent frame: %v", err)
	}
	if sent.Type != TypeText || string(sent.Payload) != "q" || sent.MessageID != "abc" || sent.ReplyTo != "xyz" {
		t.Fatalf("sent frame = %+v", sent)
	}

	ack := frameBytes(t, &Frame{Type: TypeText, Payload: []byte("ACK TEXT 1 bytes")})
	push := make([]byte, 1+4+len(ack))
	push[0] = wireCmdRecv
	binary.BigEndian.PutUint32(push[1:5], 0x42)
	copy(push[5:], ack)
	d.push(t, push)

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("Send: %v", got.err)
		}
		if !got.res.Tagged || got.res.Duplicate || string(got.res.Ack.Payload) != "ACK TEXT 1 bytes" {
			t.Fatalf("result = %+v", got.res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not return after the ACK")
	}
	_ = c.Close()
}

// TestMaxTaggedOverhead: the documented worst-case header overhead is what
// two maximal IDs actually cost on the wire.
func TestMaxTaggedOverhead(t *testing.T) {
	t.Parallel()
	id := strings.Repeat("x", MaxMessageIDLen)
	payload, err := taggedWirePayload(&Frame{Type: TypeText, MessageID: id, ReplyTo: id})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != MaxTaggedOverhead || MaxTaggedOverhead != 293 {
		t.Fatalf("maximal tagged overhead = %d bytes, MaxTaggedOverhead = %d, want both 293", len(payload), MaxTaggedOverhead)
	}
}

// countingWriter counts bytes written and discards them.
type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += len(p); return len(p), nil }

// TestWriteFrame_TaggedFrameOverMaxFrameSize is part of review finding
// DX-REV-3: the tagged wrapper must not push a frame past MaxFrameSize,
// where the receiver would drop the connection. WriteFrame refuses such a
// frame before writing anything, and accepts one that fits exactly.
func TestWriteFrame_TaggedFrameOverMaxFrameSize(t *testing.T) {
	t.Parallel()
	overhead, err := taggedWirePayload(&Frame{Type: TypeBinary, MessageID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	// Untouched zero pages: this does not commit MaxFrameSize bytes of RAM
	// until a write copies them.
	big := make([]byte, MaxFrameSize)

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"untagged size at the cap", int(MaxFrameSize)},
		{"one byte over once tagged", int(MaxFrameSize) - len(overhead) + 1},
	} {
		var w countingWriter
		err := WriteFrame(&w, &Frame{Type: TypeBinary, Payload: big[:tc.n], MessageID: "m"})
		if !errors.Is(err, ErrTaggedFrameTooLarge) {
			t.Fatalf("%s: err = %v, want ErrTaggedFrameTooLarge", tc.name, err)
		}
		if w.n != 0 {
			t.Fatalf("%s: %d bytes written before the error, want 0", tc.name, w.n)
		}
	}

	var w countingWriter
	if err := WriteFrame(&w, &Frame{Type: TypeBinary, Payload: big[:int(MaxFrameSize)-len(overhead)], MessageID: "m"}); err != nil {
		t.Fatalf("tagged frame that fits exactly: %v", err)
	}
	if w.n != 8+int(MaxFrameSize) {
		t.Fatalf("exact fit wrote %d bytes, want %d", w.n, 8+int(MaxFrameSize))
	}
}

// TestSend_TaggedFrameTooLargeSentUntagged: Client.Send delivers a frame
// that fits only untagged, untagged, and reports Tagged == false.
func TestSend_TaggedFrameTooLargeSentUntagged(t *testing.T) {
	t.Parallel()
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	t.Cleanup(func() { _ = c2sW.Close(); _ = s2cR.Close() })
	type seen struct {
		ftype  uint32
		length uint32
	}
	frames := make(chan seen, 4)
	go func() {
		// A receiver that checks the outer length like ReadFrame does but
		// discards the payload, so the test does not buffer 64 MiB.
		defer s2cW.Close()
		for {
			var hdr [8]byte
			if _, err := io.ReadFull(c2sR, hdr[:]); err != nil {
				return
			}
			ftype, length := binary.BigEndian.Uint32(hdr[0:4]), binary.BigEndian.Uint32(hdr[4:8])
			frames <- seen{ftype, length}
			if length > MaxFrameSize {
				// "frame too large": the receiver drops the connection,
				// which fails the sender's pending write.
				_ = c2sR.CloseWithError(errors.New("receiver dropped the connection: frame too large"))
				return
			}
			if _, err := io.CopyN(io.Discard, c2sR, int64(length)); err != nil {
				return
			}
			ack := fmt.Sprintf("ACK %s %d bytes", TypeName(ftype), length)
			if err := WriteFrame(s2cW, &Frame{Type: TypeText, Payload: []byte(ack)}); err != nil {
				return
			}
		}
	}()

	payload := make([]byte, MaxFrameSize)
	conn := struct {
		io.Reader
		io.Writer
	}{s2cR, c2sW}
	res, err := sendAndAwaitAck(conn, &Frame{Type: TypeBinary, Payload: payload, MessageID: NewMessageID()})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	want := fmt.Sprintf("ACK BINARY %d bytes", MaxFrameSize)
	if res.Tagged || string(res.Ack.Payload) != want {
		t.Fatalf("result = %+v ack = %q, want untagged %q", res, res.Ack.Payload, want)
	}
	if got := <-frames; got.ftype != TypeBinary || got.length != MaxFrameSize {
		t.Fatalf("receiver saw type %d length %d, want one untagged BINARY frame of %d bytes", got.ftype, got.length, MaxFrameSize)
	}
	select {
	case extra := <-frames:
		t.Fatalf("receiver saw a second frame %+v", extra)
	default:
	}
}
