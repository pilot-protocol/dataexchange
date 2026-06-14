// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// ServiceConfig configures the daemon-side dataexchange handler. Both
// paths default to ~/.pilot/{received,inbox} when empty.
type ServiceConfig struct {
	ReceivedDir string
	InboxDir    string
	// IncludeBase64 adds a lossless `data_b64` field to inbox JSON
	// alongside `data`. Off by default — only enable when binary
	// payloads (e.g. zlib-compressed envelopes) need to round-trip
	// without UTF-8 mangling.
	IncludeBase64 bool
	// InboxMaxFiles caps the number of inbox files retained on disk.
	// On exceeding the cap, oldest files (by mtime) are evicted FIFO.
	// Zero or negative ⇒ default 10000. Without this cap, a
	// misbehaving peer or sustained inbound load fills the operator's
	// disk indefinitely.
	InboxMaxFiles int
	// InboxMaxBytes caps the total on-disk bytes used by the inbox.
	// When > 0, saveInboxMessage checks the accumulated size before
	// every write and evictExpandOverflow uses bytes instead of file
	// count. Zero ⇒ no byte cap (backward-compatible).
	InboxMaxBytes int64
}

// inboxEvictCheckEvery: only run the eviction-scan once every N saves
// — full readdir + sort is O(n log n), so we don't want it on every
// write. The cap is a soft cap; transient overshoot of up to this
// many files between checks is acceptable.
const inboxEvictCheckEvery = 64

// Service is the L11 plugin adapter. Daemon (L7) holds it only as
// coreapi.Service; cmd/daemon/main.go (L12) constructs it.
type Service struct {
	cfg      ServiceConfig
	listener coreapi.Listener
	deps     coreapi.Deps
	cancel   context.CancelFunc
	done     chan struct{}
	seq      atomic.Uint64
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg}
}

func (s *Service) Name() string { return "dataexchange" }

// Order: 110 — after handshake (~70) and the trust subsystem (~50).
func (s *Service) Order() int { return 110 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	s.deps = deps
	ln, err := deps.Streams.Listen(protocol.PortDataExchange)
	if err != nil {
		return fmt.Errorf("dataexchange: listen on port %d: %w", protocol.PortDataExchange, err)
	}
	s.listener = ln

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.acceptLoop(runCtx)
	slog.Info("dataexchange service listening", "port", protocol.PortDataExchange)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.done == nil {
		return nil
	}
	select {
	case <-s.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (s *Service) acceptLoop(ctx context.Context) {
	defer close(s.done)
	// L11 panic boundary: a panic in Accept must not kill the plugin.
	// TODO(03-INVARIANTS.md §8): per-plugin supervisor.
	defer coreapi.RecoverPlugin("dataexchange", "acceptLoop", s.deps.Events, nil)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Service) handleConn(ctx context.Context, conn coreapi.Stream) {
	// L11 panic boundary: tear down THIS conn only.
	defer coreapi.RecoverPlugin("dataexchange", "handleConn", s.deps.Events, nil)
	defer conn.Close()
	for {
		frame, err := ReadFrame(conn)
		// Capture right after the IO read so receiver-side timestamps are as
		// close to the wire as possible.
		frameReceivedAtNs := time.Now().UnixNano()
		if err != nil {
			return
		}
		slog.Debug("dataexchange frame received",
			"type", TypeName(frame.Type),
			"bytes", len(frame.Payload),
			"remote", conn.RemoteAddr())

		var saveErr error
		var ackFrame *Frame
		switch frame.Type {
		case TypeFile:
			if frame.Filename != "" {
				saveErr = s.saveReceivedFile(frame)
			}
		case TypeText, TypeJSON, TypeBinary:
			saveErr = s.saveInboxMessage(frame, conn.RemoteAddr())
		case TypeTrace:
			tf, tferr := ReadTracePayload(frame)
			if tferr != nil {
				ackFrame = &Frame{
					Type:    TypeText,
					Payload: []byte(fmt.Sprintf("ERR trace parse: %v", tferr)),
				}
			} else {
				innerFrame := &Frame{Type: tf.InnerType, Payload: tf.Payload}
				innerSaveErr := s.saveInboxMessage(innerFrame, conn.RemoteAddr())
				inboxWrittenAtNs := time.Now().UnixNano()
				innerAck := fmt.Sprintf("ACK %s %d bytes", TypeName(tf.InnerType), len(tf.Payload))
				if innerSaveErr != nil {
					innerAck = fmt.Sprintf("ERR %s save failed: %v", TypeName(tf.InnerType), innerSaveErr)
				}
				ackSentAtNs := time.Now().UnixNano()
				timingJSON, _ := json.Marshal(map[string]interface{}{
					"sent_at_ns":          tf.SentAtNs,
					"received_at_ns":      frameReceivedAtNs,
					"inbox_written_at_ns": inboxWrittenAtNs,
					"ack_sent_at_ns":      ackSentAtNs,
					"inner_ack":           innerAck,
				})
				ackFrame = &Frame{Type: TypeJSON, Payload: timingJSON}
			}
		}

		if ackFrame == nil {
			ackMsg := fmt.Sprintf("ACK %s %d bytes", TypeName(frame.Type), len(frame.Payload))
			if saveErr != nil {
				ackMsg = fmt.Sprintf("ERR %s save failed: %v", TypeName(frame.Type), saveErr)
			}
			ackFrame = &Frame{Type: TypeText, Payload: []byte(ackMsg)}
		}
		if err := WriteFrame(conn, ackFrame); err != nil {
			if s.deps.Events != nil {
				s.deps.Events.Publish("dataexchange.ack_failed", map[string]any{
					"remote":     conn.RemoteAddr(),
					"frame_type": TypeName(frame.Type),
					"error":      err.Error(),
				})
			}
			return
		}
	}
}

// receivedDir returns the configured received-file directory or the
// default ~/.pilot/received.
func (s *Service) receivedDir() (string, error) {
	if s.cfg.ReceivedDir != "" {
		return s.cfg.ReceivedDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".pilot", "received"), nil
}

// inboxDir returns the configured inbox directory or the default
// ~/.pilot/inbox.
func (s *Service) inboxDir() (string, error) {
	if s.cfg.InboxDir != "" {
		return s.cfg.InboxDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, ".pilot", "inbox"), nil
}

func (s *Service) saveReceivedFile(frame *Frame) error {
	dir, err := s.receivedDir()
	if err != nil {
		slog.Warn("save received file: cannot determine dir", "err", err)
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("save received file: mkdir failed", "err", err)
		return fmt.Errorf("mkdir: %w", err)
	}

	safeName := filepath.Base(frame.Filename)
	ts := time.Now().Format("20060102-150405.000")
	seq := s.seq.Add(1)
	ext := filepath.Ext(safeName)
	base := safeName[:len(safeName)-len(ext)]
	destName := fmt.Sprintf("%s-%s-%06d%s", base, ts, seq, ext)
	destPath := filepath.Join(dir, destName)

	if err := os.WriteFile(destPath, frame.Payload, 0600); err != nil {
		_ = os.Remove(destPath)
		slog.Warn("save received file: write failed", "path", destPath, "err", err)
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("file saved", "path", destPath, "bytes", len(frame.Payload))
	if s.deps.Events != nil {
		s.deps.Events.Publish("file.received", map[string]any{
			"filename": safeName, "size": len(frame.Payload), "path": destPath,
		})
	}
	return nil
}

func (s *Service) saveInboxMessage(frame *Frame, from protocol.Addr) error {
	dir, err := s.inboxDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Byte-budget check: if InboxMaxBytes is set, confirm there is room
	// BEFORE writing. Evict if over, then re-check.
	if s.cfg.InboxMaxBytes > 0 {
		current, _ := inboxTotalBytes(dir)
		// Estimate the JSON overhead: type, from, data, bytes, received_at,
		// and possibly data_b64.
		estimated := int64(len(frame.Payload)) + 256
		if current+estimated > s.cfg.InboxMaxBytes {
			s.evictInboxOverflowByBytes(dir)
			after, _ := inboxTotalBytes(dir)
			if after+estimated > s.cfg.InboxMaxBytes {
				slog.Warn("inbox byte budget exceeded after eviction",
					"current_bytes", after,
					"max_bytes", s.cfg.InboxMaxBytes,
					"frame_bytes", len(frame.Payload))
				if s.deps.Events != nil {
					s.deps.Events.Publish("inbox.full", map[string]any{
						"from":        from.String(),
						"type":        TypeName(frame.Type),
						"frame_bytes": len(frame.Payload),
						"max_bytes":   s.cfg.InboxMaxBytes,
					})
				}
				return fmt.Errorf("inbox byte budget exceeded: %d + %d > %d",
					after, estimated, s.cfg.InboxMaxBytes)
			}
		}
	}

	ts := time.Now()
	msg := map[string]interface{}{
		"type":        TypeName(frame.Type),
		"from":        from.String(),
		"bytes":       len(frame.Payload),
		"received_at": ts.Format(time.RFC3339Nano),
	}
	if s.cfg.IncludeBase64 {
		msg["data_b64"] = base64.StdEncoding.EncodeToString(frame.Payload)
	} else {
		msg["data"] = string(frame.Payload)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	seq := s.seq.Add(1)
	filename := fmt.Sprintf("%s-%s-%06d.json", TypeName(frame.Type), ts.Format("20060102-150405.000"), seq)
	destPath := filepath.Join(dir, filename)
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	slog.Info("inbox message saved", "path", destPath, "type", TypeName(frame.Type), "bytes", len(frame.Payload))
	if s.deps.Events != nil {
		s.deps.Events.Publish("message.received", map[string]any{
			"type": TypeName(frame.Type), "from": from.String(),
			"size": len(frame.Payload),
		})
	}
	// Periodic eviction so a misbehaving peer (or sustained inbound
	// load) cannot fill the operator's disk. We sample every
	// inboxEvictCheckEvery writes — the cap is soft.
	if seq%inboxEvictCheckEvery == 0 {
		s.evictInboxOverflow(dir)
	}
	return nil
}

// evictInboxOverflow trims the inbox to at most cfg.InboxMaxFiles by
// deleting the oldest files (by mtime). When InboxMaxBytes > 0, the
// eviction target is total bytes rather than file count. Best-effort:
// I/O errors are logged and the loop continues. Called periodically
// from saveInboxMessage.
func (s *Service) evictInboxOverflow(dir string) {
	// Byte-based eviction when InboxMaxBytes is configured.
	if s.cfg.InboxMaxBytes > 0 {
		s.evictInboxOverflowByBytes(dir)
		return
	}
	maxFiles := s.cfg.InboxMaxFiles
	if maxFiles <= 0 {
		maxFiles = 10000
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Debug("inbox evict: readdir", "dir", dir, "err", err)
		return
	}
	if len(entries) <= maxFiles {
		return
	}
	type aged struct {
		name string
		mod  time.Time
	}
	files := make([]aged, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, aged{name: e.Name(), mod: info.ModTime()})
	}
	if len(files) <= maxFiles {
		return
	}
	// Oldest first.
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	toEvict := len(files) - maxFiles
	for i := 0; i < toEvict; i++ {
		_ = os.Remove(filepath.Join(dir, files[i].name))
	}
	slog.Info("inbox eviction", "dir", dir, "evicted", toEvict, "remaining", maxFiles)
}

// evictInboxOverflowByBytes trims total inbox size to InboxMaxBytes.
func (s *Service) evictInboxOverflowByBytes(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Debug("inbox evict: readdir", "dir", dir, "err", err)
		return
	}
	type aged struct {
		name string
		mod  time.Time
		size int64
	}
	files := make([]aged, 0, len(entries))
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		sz := info.Size()
		files = append(files, aged{name: e.Name(), mod: info.ModTime(), size: sz})
		total += sz
	}
	if total <= s.cfg.InboxMaxBytes {
		return
	}
	// Oldest first.
	sort.Slice(files, func(i, j int) bool { return files[i].mod.Before(files[j].mod) })
	evicted := 0
	for i := 0; i < len(files) && total > s.cfg.InboxMaxBytes; i++ {
		p := filepath.Join(dir, files[i].name)
		if err := os.Remove(p); err != nil {
			continue
		}
		total -= files[i].size
		evicted++
	}
	slog.Info("inbox eviction (bytes)", "dir", dir, "evicted", evicted, "total_bytes_after", total, "max_bytes", s.cfg.InboxMaxBytes)
}

// inboxTotalBytes sums the on-disk size of all regular files in dir.
func inboxTotalBytes(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}
