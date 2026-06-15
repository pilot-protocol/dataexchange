// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// runStreamReceiver drives a StreamReceiver over conn until conn closes.
func runStreamReceiver(conn net.Conn, dir string, done chan<- error) {
	sr := NewStreamReceiver(dir, nil, nil)
	defer sr.Close()
	for {
		f, err := ReadFrame(conn)
		if err != nil {
			done <- err
			return
		}
		if f.Type != TypeFileStream {
			continue
		}
		if resp := sr.HandleFrame(f); resp != nil {
			if werr := WriteFrame(conn, resp); werr != nil {
				done <- werr
				return
			}
		}
	}
}

func makePayload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*131 + 7) & 0xff)
	}
	return b
}

func transferIDOf(data []byte) [transferIDLen]byte {
	sum := sha256.Sum256(data)
	var id [transferIDLen]byte
	copy(id[:], sum[:transferIDLen])
	return id
}

func TestFileStream_HappyPath(t *testing.T) {
	dir := t.TempDir()
	// Span several chunks plus a partial tail.
	data := makePayload(3*StreamChunkSize + 12345)
	wantSum := sha256.Sum256(data)

	cli, srv := net.Pipe()
	done := make(chan error, 1)
	go runStreamReceiver(srv, dir, done)

	res, err := streamSend(cli, "hello.bin", bytes.NewReader(data), int64(len(data)), 10*time.Second)
	if err != nil {
		t.Fatalf("streamSend: %v", err)
	}
	_ = cli.Close()
	<-done

	if !res.OK {
		t.Fatalf("transfer not OK: %s", res.Message)
	}
	if res.BytesResumed != 0 {
		t.Errorf("BytesResumed = %d, want 0", res.BytesResumed)
	}
	if res.BytesSent != int64(len(data)) {
		t.Errorf("BytesSent = %d, want %d", res.BytesSent, len(data))
	}
	if res.Sha256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("Sha256 = %s, want %s", res.Sha256, hex.EncodeToString(wantSum[:]))
	}

	// Exactly one file in dir (besides the .partial dir), content matches.
	assertSingleReceivedFile(t, dir, data)
}

func TestFileStream_Resume(t *testing.T) {
	dir := t.TempDir()
	data := makePayload(2*StreamChunkSize + 555)
	resumeAt := StreamChunkSize + 100 // mid-second-chunk

	// Pre-seed a .partial holding the first resumeAt bytes, as if a prior
	// transfer was killed. transfer_id is content-derived, so the receiver
	// will recognize it on INIT.
	id := transferIDOf(data)
	partialDir := filepath.Join(dir, ".partial")
	if err := os.MkdirAll(partialDir, 0700); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(partialDir, hex.EncodeToString(id[:]))
	if err := os.WriteFile(partial, data[:resumeAt], 0600); err != nil {
		t.Fatal(err)
	}

	cli, srv := net.Pipe()
	done := make(chan error, 1)
	go runStreamReceiver(srv, dir, done)

	res, err := streamSend(cli, "resumed.bin", bytes.NewReader(data), int64(len(data)), 10*time.Second)
	if err != nil {
		t.Fatalf("streamSend: %v", err)
	}
	_ = cli.Close()
	<-done

	if !res.OK {
		t.Fatalf("transfer not OK: %s", res.Message)
	}
	if res.BytesResumed != int64(resumeAt) {
		t.Errorf("BytesResumed = %d, want %d", res.BytesResumed, resumeAt)
	}
	if res.BytesSent != int64(len(data)-resumeAt) {
		t.Errorf("BytesSent = %d, want %d (should not re-send resumed bytes)", res.BytesSent, len(data)-resumeAt)
	}
	assertSingleReceivedFile(t, dir, data)
}

func TestFileStream_CorruptResumeRejected(t *testing.T) {
	// A .partial whose bytes do NOT match the declared content must be
	// caught by the full-hash verification at DONE.
	dir := t.TempDir()
	data := makePayload(StreamChunkSize + 10)
	resumeAt := 500
	id := transferIDOf(data)
	partialDir := filepath.Join(dir, ".partial")
	if err := os.MkdirAll(partialDir, 0700); err != nil {
		t.Fatal(err)
	}
	corrupt := make([]byte, resumeAt) // zeros, not data[:resumeAt]
	partial := filepath.Join(partialDir, hex.EncodeToString(id[:]))
	if err := os.WriteFile(partial, corrupt, 0600); err != nil {
		t.Fatal(err)
	}

	cli, srv := net.Pipe()
	done := make(chan error, 1)
	go runStreamReceiver(srv, dir, done)

	res, err := streamSend(cli, "corrupt.bin", bytes.NewReader(data), int64(len(data)), 10*time.Second)
	_ = cli.Close()
	<-done
	if err != nil {
		// A protocol-level error is acceptable here too.
		return
	}
	if res.OK {
		t.Fatalf("expected corrupt resume to be rejected, but transfer reported OK")
	}
}

func TestFileStream_CodecRoundTrip(t *testing.T) {
	id := transferIDOf([]byte("abc"))
	var hash [32]byte
	copy(hash[:], makePayload(32))

	init := encodeInit(id, 1<<40, hash, StreamChunkSize, "a/b/c.bin")
	k, gotID, body, ok := decodeStreamFrame(init)
	if !ok || k != streamKindInit || gotID != id {
		t.Fatalf("decode init header: ok=%v kind=%d", ok, k)
	}
	size, gotHash, cs, name, ok := decodeInit(body)
	if !ok || size != 1<<40 || gotHash != hash || cs != StreamChunkSize || name != "a/b/c.bin" {
		t.Fatalf("decodeInit mismatch: size=%d cs=%d name=%q", size, cs, name)
	}

	ck := encodeChunk(id, 4096, []byte("payload"))
	_, _, cbody, _ := decodeStreamFrame(ck)
	off, cdata, ok := decodeChunk(cbody)
	if !ok || off != 4096 || string(cdata) != "payload" {
		t.Fatalf("decodeChunk mismatch: off=%d data=%q", off, cdata)
	}

	cf := encodeComplete(id, false, "boom")
	_, _, fbody, _ := decodeStreamFrame(cf)
	cok, msg := decodeComplete(fbody)
	if cok || msg != "boom" {
		t.Fatalf("decodeComplete mismatch: ok=%v msg=%q", cok, msg)
	}
}

func assertSingleReceivedFile(t *testing.T, dir string, want []byte) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue // skip .partial
		}
		files = append(files, e.Name())
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 received file, got %d: %v", len(files), files)
	}
	got, err := os.ReadFile(filepath.Join(dir, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("received content mismatch: got %d bytes, want %d", len(got), len(want))
	}
	// .partial must be cleaned up on success.
	if _, err := os.Stat(filepath.Join(dir, ".partial")); err == nil {
		if rem, _ := os.ReadDir(filepath.Join(dir, ".partial")); len(rem) != 0 {
			t.Errorf(".partial not cleaned: %d files remain", len(rem))
		}
	}
	_ = io.Discard
}
