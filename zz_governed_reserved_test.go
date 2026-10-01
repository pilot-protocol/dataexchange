// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pilot-protocol/common/coreapi"
)

// TestService_ReservedGovernedTypesAreRefused: frame types 8 and 9 are no
// longer implemented but stay reserved, because senders built before the
// removal can still emit them. The receiver must answer each with the same
// error reply as any unsupported type, store and publish nothing, not
// remember the frame as a delivery, and keep serving the connection.
func TestService_ReservedGovernedTypesAreRefused(t *testing.T) {
	t.Parallel()
	if TypeGoverned != 8 || TypeGovernedFileStream != 9 {
		t.Fatalf("reserved types renumbered: TypeGoverned=%d TypeGovernedFileStream=%d", TypeGoverned, TypeGovernedFileStream)
	}
	// The shape of an envelope as an older sender encodes it.
	envelope := []byte(`{"version":1,"type":1,"payload":"YXBwcm92ZWQ=","intent":{},"decision":{}}`)
	for _, tc := range []struct {
		name    string
		frame   *Frame
		wantAck string
	}{
		{"governed", &Frame{Type: TypeGoverned, Payload: envelope}, "ERR GOVERNED save failed: unsupported frame type 8"},
		{"governed file", &Frame{Type: TypeGoverned, Filename: "report.txt", Payload: envelope}, "ERR GOVERNED save failed: unsupported frame type 8"},
		{"governed tagged", &Frame{Type: TypeGoverned, Payload: envelope, MessageID: "gov-1", ReplyTo: "req-7"}, "ERR GOVERNED save failed: unsupported frame type 8"},
		{"governed garbage", &Frame{Type: TypeGoverned, Payload: []byte{0xff, 0x00, 0x7b}}, "ERR GOVERNED save failed: unsupported frame type 8"},
		{"governed filestream", &Frame{Type: TypeGovernedFileStream, Payload: envelope}, "ERR GOVERNED_FILESTREAM save failed: unsupported frame type 9"},
		{"governed filestream tagged", &Frame{Type: TypeGovernedFileStream, Payload: envelope, MessageID: "gov-2"}, "ERR GOVERNED_FILESTREAM save failed: unsupported frame type 9"},
		{"governed filestream garbage", &Frame{Type: TypeGovernedFileStream, Payload: []byte{0xff, 0x00, 0x7b}}, "ERR GOVERNED_FILESTREAM save failed: unsupported frame type 9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tmp := t.TempDir()
			inbox, received := filepath.Join(tmp, "inbox"), filepath.Join(tmp, "received")
			events := newCapturingEvents()
			svc := NewService(ServiceConfig{InboxDir: inbox, ReceivedDir: received, DedupeContentWindow: DefaultDedupeWindow})
			svc.deps = coreapi.Deps{Events: events}
			conn := openServiceConn(t, svc, peerA)

			// Twice: the second attempt must be refused again rather than
			// acknowledged as a duplicate of a stored delivery.
			for attempt := 1; attempt <= 2; attempt++ {
				res, err := sendAndAwaitAck(conn, tc.frame)
				if !errors.Is(err, ErrRejected) || res == nil {
					t.Fatalf("attempt %d: res=%+v err=%v, want ErrRejected", attempt, res, err)
				}
				if res.Ack.Type != TypeText || string(res.Ack.Payload) != tc.wantAck {
					t.Fatalf("attempt %d: ack = %d %q, want %q", attempt, res.Ack.Type, res.Ack.Payload, tc.wantAck)
				}
				if tagged := tc.frame.MessageID != ""; res.Tagged != tagged {
					t.Fatalf("attempt %d: Tagged = %v, want %v (a refusal must not trigger the untagged re-send)", attempt, res.Tagged, tagged)
				}
				if res.Duplicate {
					t.Fatalf("attempt %d: refused frame reported as a duplicate", attempt)
				}
			}
			for _, dir := range []string{inbox, received} {
				if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
					t.Fatalf("%s holds %d entries after a refused frame, want none", dir, len(entries))
				} else if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			events.mu.Lock()
			published := len(events.published)
			events.mu.Unlock()
			if published != 0 {
				t.Fatalf("a refused frame published %d events, want 0", published)
			}

			// The connection is still in service for ordinary frames.
			res := mustSend(t, conn, &Frame{Type: TypeText, Payload: []byte("after")})
			if string(res.Ack.Payload) != "ACK TEXT 5 bytes" {
				t.Fatalf("ack after refusal = %q", res.Ack.Payload)
			}
			if recs := inboxRecords(t, inbox); len(recs) != 1 || recs[0]["data"] != "after" {
				t.Fatalf("inbox after refusal = %v", recs)
			}
		})
	}
}

// TestReservedGovernedTypesKeepTheirNames pins the wire numbers and names so
// they are not handed to a new frame type, and checks they are not treated
// as storable deliveries by the duplicate-suppression layer.
func TestReservedGovernedTypesKeepTheirNames(t *testing.T) {
	t.Parallel()
	for typ, name := range map[uint32]string{8: "GOVERNED", 9: "GOVERNED_FILESTREAM"} {
		if got := TypeName(typ); got != name {
			t.Errorf("TypeName(%d) = %q, want %q", typ, got, name)
		}
		if dedupeEligible(typ) {
			t.Errorf("reserved type %d is dedupe-eligible", typ)
		}
	}
}
