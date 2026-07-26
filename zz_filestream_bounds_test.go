// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"crypto/sha256"
	"io/fs"
	"path/filepath"
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

	// Nothing past the declared size reached the disk. The receiver keeps
	// its .partial fragments in a subdirectory, so walk the tree and look
	// at regular files only — a directory's own reported size varies by
	// filesystem and says nothing about the transfer.
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > declared {
			t.Fatalf("%s is %d bytes, declared size was %d", path, info.Size(), declared)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
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
