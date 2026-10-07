// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// These tests drive StreamReceivers directly, one per connection, around the
// claim on a transfer's content-addressed .partial: which transfer may write
// it, and when a retry may take it over from one that has gone quiet.

// shortenStaleClaim makes a claim go stale after d for the rest of the test.
func shortenStaleClaim(t *testing.T, d time.Duration) {
	t.Helper()
	prev := staleClaimAfter
	staleClaimAfter = d
	t.Cleanup(func() { staleClaimAfter = prev })
}

// setFreeDisk makes the receiver see free bytes of disk for the rest of the
// test.
func setFreeDisk(t *testing.T, free uint64) {
	t.Helper()
	prev := freeDiskBytes
	freeDiskBytes = func(string) (uint64, bool) { return free, true }
	t.Cleanup(func() { freeDiskBytes = prev })
}

// sequencedNames gives every received file its own name: the default one is
// timestamped to the millisecond, so two transfers finishing together would
// share it.
func sequencedNames() func(string) string {
	var seq atomic.Int64
	return func(base string) string { return fmt.Sprintf("%d-%s", seq.Add(1), base) }
}

// streamFile is a file sent in whole StreamChunkSize chunks.
type streamFile struct {
	data []byte
	id   [transferIDLen]byte
	hash [32]byte
}

func newStreamFile(chunks int) streamFile {
	data := makePayload(chunks * StreamChunkSize)
	return streamFile{data: data, id: transferIDOf(data), hash: sha256.Sum256(data)}
}

func (f streamFile) init() *Frame { return f.initSized(uint64(len(f.data))) }

func (f streamFile) initSized(size uint64) *Frame {
	return encodeInit(f.id, size, f.hash, StreamChunkSize, "f.bin")
}

func (f streamFile) chunk(i int) *Frame {
	return encodeChunk(f.id, uint64(i*StreamChunkSize), f.data[i*StreamChunkSize:(i+1)*StreamChunkSize])
}

func (f streamFile) done() *Frame { return encodeStreamFrame(streamKindDone, f.id, nil) }

// exchange hands sr one frame and decodes its answer.
func exchange(t *testing.T, sr *StreamReceiver, f *Frame) (kind byte, body []byte) {
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

// expectResume sends an INIT and checks it is accepted at offset want.
func expectResume(t *testing.T, sr *StreamReceiver, f *Frame, want uint64) {
	t.Helper()
	kind, body := exchange(t, sr, f)
	if kind != streamKindInitAck {
		_, msg := decodeComplete(body)
		t.Fatalf("INIT answered with kind %#x: %q", kind, msg)
	}
	if off, _ := decodeOffset(body); off != want {
		t.Fatalf("INIT resumes at %d, want %d", off, want)
	}
}

// expectAck sends a chunk and checks it is written.
func expectAck(t *testing.T, sr *StreamReceiver, f *Frame) {
	t.Helper()
	if kind, body := exchange(t, sr, f); kind != streamKindAck {
		_, msg := decodeComplete(body)
		t.Fatalf("chunk answered with kind %#x: %q", kind, msg)
	}
}

// expectRefused sends f and checks it is refused for the reason want.
func expectRefused(t *testing.T, sr *StreamReceiver, f *Frame, want string) {
	t.Helper()
	kind, body := exchange(t, sr, f)
	ok, msg := decodeComplete(body)
	if kind != streamKindComplete || ok {
		t.Fatalf("answered with kind %#x ok=%v, want a refusal", kind, ok)
	}
	if !strings.Contains(msg, want) {
		t.Fatalf("refusal %q does not say %q", msg, want)
	}
}

// expectCompleted sends DONE and checks the file is accepted.
func expectCompleted(t *testing.T, sr *StreamReceiver, f streamFile) {
	t.Helper()
	kind, body := exchange(t, sr, f.done())
	if ok, msg := decodeComplete(body); kind != streamKindComplete || !ok {
		t.Fatalf("DONE answered with kind %#x ok=%v %q", kind, ok, msg)
	}
}

// expectCopies checks dir holds n received files, each with data.
func expectCopies(t *testing.T, dir string, data []byte, n int) {
	t.Helper()
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
			t.Errorf("%s does not match what was sent", e.Name())
		}
	}
	if files != n {
		t.Fatalf("%d files received, want %d", files, n)
	}
}

// openTransferFile returns the descriptor sr holds for transfer id.
func openTransferFile(t *testing.T, sr *StreamReceiver, id [transferIDLen]byte) *os.File {
	t.Helper()
	sr.mu.Lock()
	defer sr.mu.Unlock()
	tr := sr.transfers[id]
	if tr == nil {
		t.Fatal("no transfer")
	}
	return tr.file
}

// A stalled transfer whose .partial a retry has taken over is refused its
// DONE, and lets go of the file: it used to keep the descriptor open until
// its connection closed.
func TestFileStream_StalledDoneIsRefused(t *testing.T) {
	shortenStaleClaim(t, 50*time.Millisecond)
	dir := t.TempDir()
	f := newStreamFile(2)

	stalled := NewStreamReceiver(dir, nil, nil)
	defer stalled.Close()
	expectResume(t, stalled, f.init(), 0)
	expectAck(t, stalled, f.chunk(0))
	expectAck(t, stalled, f.chunk(1))
	time.Sleep(2 * staleClaimAfter) // the sender stalls before DONE, then retries

	retry := NewStreamReceiver(dir, nil, nil)
	defer retry.Close()
	expectResume(t, retry, f.init(), uint64(len(f.data)))

	file := openTransferFile(t, stalled, f.id)
	expectRefused(t, stalled, f.done(), "taken it over")
	if err := file.Close(); !errors.Is(err, os.ErrClosed) {
		t.Error("the refused transfer's .partial is still open")
	}

	expectCompleted(t, retry, f)
	expectCopies(t, dir, f.data, 1)
}

// DONE takes a while — fsync, a hash over the whole file, onPrepare — and a
// retry can take the .partial over meanwhile. The transfer that lost it must
// not then rename the file the retry is finishing.
func TestFileStream_TakeoverDuringDoneStopsTheRename(t *testing.T) {
	shortenStaleClaim(t, 50*time.Millisecond)
	dir := t.TempDir()
	f := newStreamFile(2)

	retry := NewStreamReceiver(dir, nil, nil)
	defer retry.Close()
	onPrepare := func([transferIDLen]byte, string, string, int64) error {
		time.Sleep(2 * staleClaimAfter)
		expectResume(t, retry, f.init(), uint64(len(f.data)))
		return nil
	}
	stalled := NewStreamReceiverWithQuotaAndPrepareAndCommit(dir, nil, nil, onPrepare, nil, 0)
	defer stalled.Close()
	expectResume(t, stalled, f.init(), 0)
	expectAck(t, stalled, f.chunk(0))
	expectAck(t, stalled, f.chunk(1))
	expectRefused(t, stalled, f.done(), "taken it over")

	expectCompleted(t, retry, f)
	expectCopies(t, dir, f.data, 1)
}

// A second INIT on a connection whose transfer a retry has since taken over
// must leave the retry's file alone — not open it as its own, truncate it or
// delete it — and must not leave the transfer stuck refusing every chunk.
func TestFileStream_ReInitOnSupersededConnection(t *testing.T) {
	// stall starts f on one connection, writes its first written chunks, and
	// has a retry on another connection take the .partial over.
	stall := func(t *testing.T, dir string, f streamFile, written int) (stalled, retry *StreamReceiver) {
		t.Helper()
		shortenStaleClaim(t, 50*time.Millisecond)
		names := sequencedNames()
		stalled = NewStreamReceiver(dir, names, nil)
		t.Cleanup(stalled.Close)
		expectResume(t, stalled, f.init(), 0)
		for i := 0; i < written; i++ {
			expectAck(t, stalled, f.chunk(i))
		}
		time.Sleep(2 * staleClaimAfter)
		retry = NewStreamReceiver(dir, names, nil)
		t.Cleanup(retry.Close)
		expectResume(t, retry, f.init(), uint64(written*StreamChunkSize))
		return stalled, retry
	}

	t.Run("same file", func(t *testing.T) {
		dir := t.TempDir()
		f := newStreamFile(3)
		stalled, retry := stall(t, dir, f, 1)
		expectAck(t, retry, f.chunk(1))

		// The stalled sender starts over on the connection it still has.
		// The retry is writing the .partial, so this gets a private one.
		expectResume(t, stalled, f.init(), 0)
		for i := 0; i < 3; i++ {
			expectAck(t, stalled, f.chunk(i))
		}
		expectCompleted(t, stalled, f)

		expectAck(t, retry, f.chunk(2))
		expectCompleted(t, retry, f)
		expectCopies(t, dir, f.data, 2)
		stalled.Close()
		retry.Close()
		if left := partialFiles(t, dir); len(left) > 0 {
			t.Fatalf("partial files left behind: %v", left)
		}
	})

	t.Run("declares less than the file holds", func(t *testing.T) {
		dir := t.TempDir()
		f := newStreamFile(3)
		stalled, retry := stall(t, dir, f, 1)
		expectAck(t, retry, f.chunk(1))

		// A .partial longer than the declared size is truncated.
		stalled.HandleFrame(f.initSized(StreamChunkSize))

		expectAck(t, retry, f.chunk(2))
		expectCompleted(t, retry, f)
		expectCopies(t, dir, f.data, 1)
	})

	t.Run("refused by the disk check", func(t *testing.T) {
		dir := t.TempDir()
		f := newStreamFile(2)
		stalled, retry := stall(t, dir, f, 0)

		// A refusal used to delete an empty .partial on its way out.
		setFreeDisk(t, 0)
		expectRefused(t, stalled, f.init(), "disk full")

		expectAck(t, retry, f.chunk(0))
		expectAck(t, retry, f.chunk(1))
		expectCompleted(t, retry, f)
		expectCopies(t, dir, f.data, 1)
	})
}

// An INIT that is refused must not take a .partial over from a transfer that
// has merely gone quiet. Anyone who knows the transfer id could otherwise
// strip a quiet transfer of its file by declaring an absurd size.
func TestFileStream_RefusedInitDoesNotTakeOver(t *testing.T) {
	for _, tc := range []struct {
		name   string
		refuse func(t *testing.T, dir string, f streamFile)
	}{
		{"quota", func(t *testing.T, dir string, f streamFile) {
			intruder := NewStreamReceiverWithQuota(dir, nil, nil, 1<<20)
			defer intruder.Close()
			expectRefused(t, intruder, f.initSized(1<<40), "quota exceeded")
		}},
		{"quota, a size past the int64 range", func(t *testing.T, dir string, f streamFile) {
			// Where free space cannot be read, the quota is the only gate.
			prev := freeDiskBytes
			freeDiskBytes = func(string) (uint64, bool) { return 0, false }
			t.Cleanup(func() { freeDiskBytes = prev })
			intruder := NewStreamReceiverWithQuota(dir, nil, nil, 1<<20)
			defer intruder.Close()
			expectRefused(t, intruder, f.initSized(1<<63), "quota exceeded")
		}},
		{"disk space", func(t *testing.T, dir string, f streamFile) {
			setFreeDisk(t, 1<<30)
			intruder := NewStreamReceiver(dir, nil, nil)
			defer intruder.Close()
			expectRefused(t, intruder, f.initSized(1<<40), "disk full")
		}},
		{"too many transfers", func(t *testing.T, dir string, f streamFile) {
			intruder := NewStreamReceiver(dir, nil, nil)
			defer intruder.Close()
			for i := 0; i < maxConcurrentTransfers; i++ {
				other := f.id
				other[0], other[1] = ^other[0], byte(i)
				expectResume(t, intruder, encodeInit(other, 1, f.hash, StreamChunkSize, "x"), 0)
			}
			expectRefused(t, intruder, f.init(), "too many concurrent transfers")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortenStaleClaim(t, 50*time.Millisecond)
			dir := t.TempDir()
			f := newStreamFile(2)

			holder := NewStreamReceiver(dir, nil, nil)
			defer holder.Close()
			expectResume(t, holder, f.init(), 0)
			expectAck(t, holder, f.chunk(0))
			time.Sleep(2 * staleClaimAfter)

			tc.refuse(t, dir, f)

			expectAck(t, holder, f.chunk(1))
			expectCompleted(t, holder, f)
			expectCopies(t, dir, f.data, 1)
		})
	}
}

// What makes a claim stale is how long its holder has gone without writing,
// not how old the claim is.
func TestFileStream_LiveHolderIsNotTakenOver(t *testing.T) {
	shortenStaleClaim(t, 100*time.Millisecond)
	dir := t.TempDir()
	f := newStreamFile(2)
	names := sequencedNames()

	holder := NewStreamReceiver(dir, names, nil)
	defer holder.Close()
	expectResume(t, holder, f.init(), 0)
	time.Sleep(2 * staleClaimAfter)
	expectAck(t, holder, f.chunk(0))

	// The same content on another connection: a private file, from 0.
	other := NewStreamReceiver(dir, names, nil)
	defer other.Close()
	expectResume(t, other, f.init(), 0)

	expectAck(t, holder, f.chunk(1))
	expectCompleted(t, holder, f)
	expectAck(t, other, f.chunk(0))
	expectAck(t, other, f.chunk(1))
	expectCompleted(t, other, f)
	expectCopies(t, dir, f.data, 2)
}

// A sender waits up to streamStepTimeout for each ACK, so a live transfer can
// be quiet that long. Its claim must not go stale sooner: losing the file
// fails a transfer that was still going.
func TestFileStream_StaleClaimOutlastsSenderStepTimeout(t *testing.T) {
	if staleClaimAfter <= streamStepTimeout {
		t.Fatalf("a claim goes stale after %s, but a live sender waits up to %s for an ACK",
			staleClaimAfter, streamStepTimeout)
	}
}

// A transfer abandoned for a full disk deletes its .partial only while it
// still holds it: once a retry has taken the file over, the file is the
// retry's.
func TestFileStream_DiskFullLeavesATakenOverFileAlone(t *testing.T) {
	shortenStaleClaim(t, 50*time.Millisecond)
	dir := t.TempDir()
	f := newStreamFile(2)

	stalled := NewStreamReceiver(dir, nil, nil)
	defer stalled.Close()
	expectResume(t, stalled, f.init(), 0)
	expectAck(t, stalled, f.chunk(0))
	time.Sleep(2 * staleClaimAfter)

	retry := NewStreamReceiver(dir, nil, nil)
	defer retry.Close()
	expectResume(t, retry, f.init(), StreamChunkSize)

	stalled.abandonIfDiskFull(f.id, &os.PathError{Op: "write", Path: "f", Err: syscall.ENOSPC})

	expectAck(t, retry, f.chunk(1))
	expectCompleted(t, retry, f)
	expectCopies(t, dir, f.data, 1)
}
