// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func partialFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, ".partial"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read .partial: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The .partial is named after the content hash, so several transfers of the
// same content at once used to share one file: all but the first failed at
// the final rename. Each now completes and leaves its own copy.
func TestFileStream_SameContentConcurrently(t *testing.T) {
	dir := t.TempDir()
	data := makePayload(3*StreamChunkSize + 4321)
	var seq atomic.Int64
	name := func(base string) string { return fmt.Sprintf("%d-%s", seq.Add(1), base) }

	const senders = 4
	var wg sync.WaitGroup
	results := make([]*StreamResult, senders)
	errs := make([]error, senders)
	for i := 0; i < senders; i++ {
		cli, srv := net.Pipe()
		go func() {
			sr := NewStreamReceiver(dir, name, nil)
			defer sr.Close()
			for {
				f, err := ReadFrame(srv)
				if err != nil {
					return
				}
				if resp := sr.HandleFrame(f); resp != nil {
					if WriteFrame(srv, resp) != nil {
						return
					}
				}
			}
		}()
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer cli.Close()
			results[i], errs[i] = streamSend(cli, "same.bin", bytes.NewReader(data), int64(len(data)), 10*time.Second)
		}(i)
	}
	wg.Wait()

	for i := range results {
		if errs[i] != nil {
			t.Fatalf("sender %d: %v", i, errs[i])
		}
		if !results[i].OK {
			t.Errorf("sender %d refused: %s", i, results[i].Message)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files++
		got, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("%s does not match the sent content", e.Name())
		}
	}
	if files != senders {
		t.Errorf("received %d files, want %d", files, senders)
	}
	// The receivers close when their pipes do; give that a moment.
	deadline := time.Now().Add(2 * time.Second)
	for len(partialFiles(t, dir)) > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if left := partialFiles(t, dir); len(left) > 0 {
		t.Errorf("partial files left behind: %v", left)
	}
}

// A transfer that cannot fit on the disk is refused before any byte lands,
// rather than failing part-way with the disk full.
func TestFileStream_RefusedWhenDiskCannotHoldIt(t *testing.T) {
	dir := t.TempDir()
	data := makePayload(2 * StreamChunkSize)
	prev := freeDiskBytes
	freeDiskBytes = func(string) (uint64, bool) { return uint64(len(data)) + diskReserveBytes - 1, true }
	defer func() { freeDiskBytes = prev }()

	cli, srv := net.Pipe()
	done := make(chan error, 1)
	go runStreamReceiver(srv, dir, done)
	res, err := streamSend(cli, "big.bin", bytes.NewReader(data), int64(len(data)), 5*time.Second)
	_ = cli.Close()
	<-done

	if err == nil && res != nil && res.OK {
		t.Fatal("transfer accepted with too little free space")
	}
	msg := fmt.Sprint(err)
	if res != nil {
		msg += " " + res.Message
	}
	if !strings.Contains(msg, "receiver disk full") {
		t.Errorf("refusal does not say why: %q", msg)
	}
	if left := partialFiles(t, dir); len(left) > 0 {
		t.Errorf("refused transfer left partial files: %v", left)
	}

	// With room to spare the same transfer goes through.
	freeDiskBytes = func(string) (uint64, bool) { return uint64(len(data)) + diskReserveBytes, true }
	cli, srv = net.Pipe()
	go runStreamReceiver(srv, dir, done)
	res, err = streamSend(cli, "big.bin", bytes.NewReader(data), int64(len(data)), 5*time.Second)
	_ = cli.Close()
	<-done
	if err != nil || !res.OK {
		t.Fatalf("transfer with enough space failed: %v %+v", err, res)
	}
}

// When a write fails because the disk is full, the .partial goes: keeping it
// holds the disk full for a resume that cannot succeed.
func TestFileStream_DiskFullMidTransferRemovesPartial(t *testing.T) {
	dir := t.TempDir()
	data := makePayload(StreamChunkSize)
	id := transferIDOf(data)
	sr := NewStreamReceiver(dir, nil, nil)
	defer sr.Close()

	cli, srv := net.Pipe()
	go func() {
		for {
			f, err := ReadFrame(srv)
			if err != nil {
				return
			}
			if f.Type == TypeFileStream && len(f.Payload) > 0 && f.Payload[0] == streamKindInit {
				_ = WriteFrame(srv, sr.HandleFrame(f))
				return
			}
		}
	}()
	go func() { _, _ = streamSend(cli, "f.bin", bytes.NewReader(data), int64(len(data)), time.Second) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(partialFiles(t, dir)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(partialFiles(t, dir)) != 1 {
		t.Fatalf("expected one partial after INIT, have %v", partialFiles(t, dir))
	}

	sr.abandonIfDiskFull(id, fmt.Errorf("write at 0: %w", os.ErrPermission))
	if len(partialFiles(t, dir)) != 1 {
		t.Fatal("a non-disk-full error must keep the partial for resume")
	}
	sr.abandonIfDiskFull(id, fmt.Errorf("write at 0: %w", syscall.ENOSPC))
	if left := partialFiles(t, dir); len(left) != 0 {
		t.Errorf("partial kept after disk-full: %v", left)
	}
	_ = cli.Close()
	_ = srv.Close()
}

type writeCounter struct {
	bytes.Buffer
	writes int
}

func (c *writeCounter) Write(p []byte) (int, error) {
	c.writes++
	return c.Buffer.Write(p)
}

// A small frame must reach the stream in one write: header and payload as
// two writes stalls on Nagle and the peer's delayed ACK.
func TestWriteFrame_SmallFrameIsOneWrite(t *testing.T) {
	for _, tc := range []struct {
		size, writes int
	}{{0, 1}, {200, 1}, {singleWriteMax, 1}, {singleWriteMax + 1, 2}} {
		var w writeCounter
		in := &Frame{Type: TypeBinary, Payload: makePayload(tc.size)}
		if err := WriteFrame(&w, in); err != nil {
			t.Fatal(err)
		}
		if w.writes != tc.writes {
			t.Errorf("%d-byte payload: %d writes, want %d", tc.size, w.writes, tc.writes)
		}
		out, err := ReadFrame(&w.Buffer)
		if err != nil {
			t.Fatalf("%d-byte payload: read back: %v", tc.size, err)
		}
		if out.Type != in.Type || !bytes.Equal(out.Payload, in.Payload) {
			t.Errorf("%d-byte payload did not round-trip", tc.size)
		}
	}
}

// A sender that stalls and retries reconnects while this receiver still
// holds the stalled connection open (until its idle timeout, minutes later).
// The retry must resume the .partial where the stalled transfer stopped —
// not start over in a private copy, which also left the stale .partial to
// count against the quota and could get the retry refused outright — and
// the stalled transfer must not write to the file again.
func TestFileStream_RetryTakesOverAStalledTransfer(t *testing.T) {
	prev := staleClaimAfter
	staleClaimAfter = 50 * time.Millisecond
	defer func() { staleClaimAfter = prev }()

	dir := t.TempDir()
	data := makePayload(3 * StreamChunkSize)
	hash := sha256.Sum256(data)
	var id [transferIDLen]byte
	copy(id[:], hash[:])

	send := func(sr *StreamReceiver, f *Frame) (kind byte, body []byte) {
		t.Helper()
		resp := sr.HandleFrame(f)
		if resp == nil {
			t.Fatal("no response")
		}
		kind, _, body, ok := decodeStreamFrame(resp)
		if !ok {
			t.Fatal("malformed response")
		}
		return kind, body
	}
	chunk := func(i int) *Frame {
		return encodeChunk(id, uint64(i*StreamChunkSize), data[i*StreamChunkSize:(i+1)*StreamChunkSize])
	}

	stalled := NewStreamReceiver(dir, nil, nil)
	defer stalled.Close()
	if kind, _ := send(stalled, encodeInit(id, uint64(len(data)), hash, StreamChunkSize, "f.bin")); kind != streamKindInitAck {
		t.Fatalf("first INIT answered with kind %#x", kind)
	}
	if kind, _ := send(stalled, chunk(0)); kind != streamKindAck {
		t.Fatalf("first chunk answered with kind %#x", kind)
	}
	time.Sleep(2 * staleClaimAfter) // the sender stalls, then retries

	retry := NewStreamReceiver(dir, nil, nil)
	defer retry.Close()
	kind, body := send(retry, encodeInit(id, uint64(len(data)), hash, StreamChunkSize, "f.bin"))
	if kind != streamKindInitAck {
		t.Fatalf("retry INIT answered with kind %#x", kind)
	}
	if off, _ := decodeOffset(body); off != StreamChunkSize {
		t.Fatalf("retry resumes at %d, want %d: it did not take over the stalled transfer's .partial", off, StreamChunkSize)
	}

	// The stalled connection wakes up and tries to carry on: refused.
	kind, body = send(stalled, chunk(1))
	if kind != streamKindComplete {
		t.Fatalf("stalled transfer's chunk answered with kind %#x, want a refusal", kind)
	}
	if ok, msg := decodeComplete(body); ok || !strings.Contains(msg, "taken it over") {
		t.Fatalf("stalled transfer's chunk: ok=%v %q", ok, msg)
	}

	for i := 1; i < 3; i++ {
		if kind, _ := send(retry, chunk(i)); kind != streamKindAck {
			t.Fatalf("retry chunk %d answered with kind %#x", i, kind)
		}
	}
	kind, body = send(retry, encodeStreamFrame(streamKindDone, id, nil))
	if ok, msg := decodeComplete(body); kind != streamKindComplete || !ok {
		t.Fatalf("retry DONE: kind %#x ok=%v %q", kind, ok, msg)
	}
	entries, _ := os.ReadDir(dir)
	files := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files++
		got, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if !bytes.Equal(got, data) {
			t.Fatalf("%s does not match what was sent", e.Name())
		}
	}
	if files != 1 {
		t.Fatalf("%d files received, want 1", files)
	}
	stalled.Close()
	retry.Close()
	if left := partialFiles(t, dir); len(left) > 0 {
		t.Fatalf("partial files left behind: %v", left)
	}
}
