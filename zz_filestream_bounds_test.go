// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"crypto/sha256"
	"os"
	"testing"
)

// A chunk that runs past the size declared at INIT must be refused at
// the point it arrives, so the partial file stays inside the size the
// receiver agreed to hold.
func TestStreamChunkBeyondDeclaredSizeIsRefused(t *testing.T) {
	dir := t.TempDir()
	sr := NewStreamReceiver(dir, nil, nil)
	defer sr.Close()

	const declared = 1024
	data := makePayload(declared)
	id := transferIDOf([]byte("oversize-transfer"))
	sum := sha256.Sum256(data)

	if resp := sr.HandleFrame(encodeInit(id, declared, sum, StreamChunkSize, "big.bin")); resp == nil {
		t.Fatal("INIT produced no reply")
	}

	// A chunk twice the declared size, at offset 0.
	resp := sr.HandleFrame(encodeChunk(id, 0, makePayload(2*declared)))
	if resp == nil {
		t.Fatal("oversized chunk produced no reply")
	}
	kind, _, body, parsed := decodeStreamHeaderForTest(resp)
	if !parsed || kind != streamKindComplete {
		t.Fatalf("oversized chunk reply kind = %#x (parsed=%v), want a failed complete", kind, parsed)
	}
	if accepted, msg := decodeComplete(body); accepted {
		t.Fatalf("oversized chunk was accepted (%q)", msg)
	}

	// A chunk that starts inside the file but overruns the tail is
	// refused on the same grounds.
	resp = sr.HandleFrame(encodeChunk(id, declared-16, makePayload(64)))
	kind, _, body, parsed = decodeStreamHeaderForTest(resp)
	if !parsed || kind != streamKindComplete {
		t.Fatalf("overrunning tail chunk reply kind = %#x (parsed=%v), want a failed complete", kind, parsed)
	}
	if accepted, msg := decodeComplete(body); accepted {
		t.Fatalf("overrunning tail chunk was accepted (%q)", msg)
	}

	// Nothing past the declared size reached the disk.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Size() > declared {
			t.Fatalf("%s is %d bytes, declared size was %d", e.Name(), info.Size(), declared)
		}
	}
}

// decodeStreamHeaderForTest peels the stream control header off a
// TypeFileStream frame: [kind][transfer id][body].
func decodeStreamHeaderForTest(f *Frame) (kind byte, id [transferIDLen]byte, body []byte, ok bool) {
	if f == nil || f.Type != TypeFileStream || len(f.Payload) < 1+transferIDLen {
		return 0, id, nil, false
	}
	kind = f.Payload[0]
	copy(id[:], f.Payload[1:1+transferIDLen])
	return kind, id, f.Payload[1+transferIDLen:], true
}
