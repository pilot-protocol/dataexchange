// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
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
	// InboxMaxBytes caps the total on-disk bytes used by the inbox. Every
	// write is checked against a running total; when a message would not
	// fit, the oldest messages are evicted until the inbox plus the new
	// message is at or below 90% of the cap. A single message larger than the
	// cap is rejected without evicting anything. Zero ⇒ DefaultInboxMaxBytes;
	// a negative value disables the byte cap entirely (escape hatch).
	InboxMaxBytes int64
	// ReceivedMaxBytes caps the total on-disk bytes used by the received-
	// files directory (completed TypeFile / TypeFileStream files plus any
	// retained .partial fragments). Enforced before every write so a peer
	// cannot fill the disk. Zero ⇒ DefaultReceivedMaxBytes; a negative
	// value disables the quota entirely (escape hatch).
	ReceivedMaxBytes int64
	// IdleTimeout bounds how long a single connection may sit without
	// delivering the next frame. Reset before every read, so a slowloris
	// peer that opens a connection and dribbles (or stalls) is dropped
	// instead of pinning the goroutine and its buffers indefinitely.
	// Zero ⇒ DefaultIdleTimeout; a negative value disables the deadline.
	IdleTimeout time.Duration
	// RequireGoverned rejects legacy frames unless they carry a signed
	// governed envelope verified by GovernedVerifier. Enable this only after
	// sender rollout; the default preserves compatibility with older peers.
	RequireGoverned         bool
	GovernedVerifier        GovernedFrameVerifier
	GovernedStreamVerifier  GovernedStreamVerifier
	RequireGovernedReceipts bool
	GovernedReceiptRecorder GovernedReceiptRecorder
	// GovernedContentInspector runs only at this receiver, after signed
	// governed verification and before a message/file is released. It receives
	// a reader, not an exported payload copy, so central authority services do
	// not need application plaintext for DLP.
	GovernedContentInspector         decision.DisclosureContentInspector
	RequireGovernedContentInspection bool
	// GovernedTransferQuota bounds admitted transfers for each verified
	// Intent.AgentID. It never uses an untrusted peer address as the subject.
	// Quota is charged at governed-frame verification (or stream INIT) and does
	// not silently apply to legacy traffic.
	GovernedTransferQuota *decision.TransferQuotaLimiter
	// GovernedRetentionPolicies maps signed V2 disclosure retention classes to
	// durable local expiry work. When non-empty, governed deliveries without a
	// configured V2 retention class are rejected before persistence.
	GovernedRetentionPolicies []GovernedRetentionPolicy
	RetentionStateDir         string
	RetentionSweepInterval    time.Duration
}

// Defensible defaults applied when the corresponding ServiceConfig field
// is left at its zero value. A negative field value disables the limit.
const (
	// DefaultInboxMaxBytes caps inbox JSON at 256 MiB total.
	DefaultInboxMaxBytes int64 = 256 << 20
	// DefaultReceivedMaxBytes caps received files + partials at 2 GiB total.
	DefaultReceivedMaxBytes int64 = 2 << 30
	// DefaultIdleTimeout drops a connection idle for 2 minutes between frames.
	DefaultIdleTimeout = 2 * time.Minute
)

// readDeadliner is the optional deadline surface a Stream may expose. The
// production transport (*driver.Conn) implements it; test pipes generally do
// not, so we type-assert and skip the deadline when it is unavailable.
type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// effectiveInboxMaxBytes resolves the configured inbox byte cap: zero ⇒
// default, negative ⇒ disabled (returns 0).
func (s *Service) effectiveInboxMaxBytes() int64 {
	switch {
	case s.cfg.InboxMaxBytes < 0:
		return 0
	case s.cfg.InboxMaxBytes == 0:
		return DefaultInboxMaxBytes
	default:
		return s.cfg.InboxMaxBytes
	}
}

// effectiveReceivedMaxBytes resolves the received-files quota: zero ⇒
// default, negative ⇒ disabled (returns 0).
func (s *Service) effectiveReceivedMaxBytes() int64 {
	switch {
	case s.cfg.ReceivedMaxBytes < 0:
		return 0
	case s.cfg.ReceivedMaxBytes == 0:
		return DefaultReceivedMaxBytes
	default:
		return s.cfg.ReceivedMaxBytes
	}
}

// effectiveIdleTimeout resolves the per-connection idle deadline: zero ⇒
// default, negative ⇒ disabled (returns 0).
func (s *Service) effectiveIdleTimeout() time.Duration {
	switch {
	case s.cfg.IdleTimeout < 0:
		return 0
	case s.cfg.IdleTimeout == 0:
		return DefaultIdleTimeout
	default:
		return s.cfg.IdleTimeout
	}
}

// inboxEvictCheckEvery: only run the eviction-scan once every N saves
// — full readdir + sort is O(n log n), so we don't want it on every
// write. The file-count cap is a soft cap; transient overshoot of up to
// this many files between checks is acceptable. The byte cap is enforced on
// every write from a running total (see inbox_budget.go); this pass also
// re-seeds that total from disk.
const inboxEvictCheckEvery = 64

// Service is the L11 plugin adapter. Daemon (L7) holds it only as
// coreapi.Service; cmd/daemon/main.go (L12) constructs it.
type Service struct {
	cfg       ServiceConfig
	listener  coreapi.Listener
	deps      coreapi.Deps
	cancel    context.CancelFunc
	done      chan struct{}
	seq       atomic.Uint64
	retention *governedRetentionManager
	replay    *governedReplayGuard
	inbox     inboxBudget
}

// persistedDelivery separates a disk write from its visible notification so a
// governed receipt can be durably appended before the receiver acknowledges
// or publishes the delivery event. A failed receipt causes the staged file to
// be removed rather than leaving an unreceipted enterprise side effect.
type persistedDelivery struct {
	rollback func() error
	commit   func()
}

func NewService(cfg ServiceConfig) *Service {
	return &Service{cfg: cfg, replay: newGovernedReplayGuard()}
}

func (s *Service) Name() string { return "dataexchange" }

// Order: 110 — after handshake (~70) and the trust subsystem (~50).
func (s *Service) Order() int { return 110 }

func (s *Service) Start(ctx context.Context, deps coreapi.Deps) error {
	if err := s.validateGovernedConfig(); err != nil {
		return err
	}
	s.deps = deps
	if err := s.initializeGovernedRetention(); err != nil {
		return err
	}
	ln, err := deps.Streams.Listen(protocol.PortDataExchange)
	if err != nil {
		return fmt.Errorf("dataexchange: listen on port %d: %w", protocol.PortDataExchange, err)
	}
	s.listener = ln

	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.acceptLoop(runCtx)
	if s.retention != nil {
		go s.retention.run(runCtx.Done(), s.cfg.RetentionSweepInterval)
	}
	slog.Info("dataexchange service listening", "port", protocol.PortDataExchange)
	return nil
}

func (s *Service) validateGovernedConfig() error {
	if s.cfg.RequireGovernedReceipts && (!s.cfg.RequireGoverned || s.cfg.GovernedReceiptRecorder == nil) {
		return fmt.Errorf("dataexchange: governed receipts require a governed receiver and receipt recorder")
	}
	if s.cfg.RequireGovernedContentInspection && (!s.cfg.RequireGoverned || s.cfg.GovernedContentInspector == nil) {
		return fmt.Errorf("dataexchange: required content inspection needs a governed receiver and local inspector")
	}
	if s.cfg.GovernedTransferQuota != nil && !s.cfg.RequireGoverned {
		return fmt.Errorf("dataexchange: governed transfer quota requires a governed receiver")
	}
	if len(s.cfg.GovernedRetentionPolicies) > 0 && !s.cfg.RequireGoverned {
		return fmt.Errorf("dataexchange: governed retention requires a governed receiver")
	}
	return nil
}

func (s *Service) initializeGovernedRetention() error {
	if len(s.cfg.GovernedRetentionPolicies) == 0 {
		s.retention = nil
		return nil
	}
	inbox, err := s.inboxDir()
	if err != nil {
		return fmt.Errorf("dataexchange: retention inbox directory: %w", err)
	}
	received, err := s.receivedDir()
	if err != nil {
		return fmt.Errorf("dataexchange: retention received directory: %w", err)
	}
	stateDir := s.cfg.RetentionStateDir
	if stateDir == "" {
		stateDir = filepath.Join(filepath.Dir(inbox), "retention")
	}
	manager, err := newGovernedRetentionManager(stateDir, map[string]string{"inbox": inbox, "received": received}, s.cfg.GovernedRetentionPolicies, nil)
	if err != nil {
		return err
	}
	if err := manager.Sweep(); err != nil {
		return err
	}
	s.retention = manager
	return nil
}

func (s *Service) requireGovernedRetention(disclosure *decision.DisclosureBinding) error {
	if s.retention == nil {
		return nil
	}
	if disclosure == nil || disclosure.Version != decision.DisclosureBindingRetentionVersion || disclosure.RetentionClass == "" {
		return fmt.Errorf("dataexchange: governed retention requires a V2 disclosure retention class")
	}
	if _, exists := s.retention.policies[disclosure.RetentionClass]; !exists {
		return fmt.Errorf("dataexchange: disclosure retention class is not configured")
	}
	return nil
}

func (s *Service) prepareGovernedRetention(disclosure *decision.DisclosureBinding, path string) (retentionTicket, error) {
	if s.retention == nil {
		return retentionTicket{}, nil
	}
	return s.retention.prepare(disclosure, path)
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
	// Prefer a context error that already existed when Stop was called. A
	// completed accept loop must not make cancellation semantics depend on
	// which ready channel select happens to choose.
	if err := ctx.Err(); err != nil {
		return err
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

	// Lazily-constructed TypeFileStream receiver, scoped to this connection.
	// Final filenames and the file.received event match saveReceivedFile so
	// the two transfer paths are indistinguishable to consumers.
	var sr *StreamReceiver
	governedStreams := make(map[[transferIDLen]byte]GovernedStreamInit)
	streamRetention := make(map[[transferIDLen]byte]retentionTicket)
	defer func() {
		for _, ticket := range streamRetention {
			_ = ticket.rollback()
		}
		if sr != nil {
			sr.Close()
		}
	}()
	streamNameSuffix := func(base string) string {
		ts := time.Now().Format("20060102-150405.000")
		seq := s.seq.Add(1)
		ext := filepath.Ext(base)
		stem := base[:len(base)-len(ext)]
		return fmt.Sprintf("%s-%s-%06d%s", stem, ts, seq, ext)
	}
	streamOnSaved := func(name, path string, size int64) {
		slog.Info("file saved (stream)", "path", path, "bytes", size)
		if s.deps.Events != nil {
			s.deps.Events.Publish("file.received", map[string]any{
				"filename": name, "size": int(size), "path": path,
			})
		}
	}
	streamOnPrepare := func(id [transferIDLen]byte, _ string, path string, _ int64) error {
		governed, governedTransfer := governedStreams[id]
		if s.cfg.RequireGoverned && !governedTransfer {
			return fmt.Errorf("stream completion is not bound to a governed INIT")
		}
		if !governedTransfer {
			return nil
		}
		ticket, err := s.prepareGovernedRetention(governed.Disclosure, path)
		if err != nil {
			return err
		}
		streamRetention[id] = ticket
		return nil
	}
	streamOnCommit := func(id [transferIDLen]byte, name, path string, _ int64) error {
		governed, governedTransfer := governedStreams[id]
		if s.cfg.RequireGoverned && !governedTransfer {
			return fmt.Errorf("stream completion is not bound to a governed INIT")
		}
		if !governedTransfer {
			return nil
		}
		defer delete(governedStreams, id)
		retention := streamRetention[id]
		defer delete(streamRetention, id)
		committed := false
		defer func() {
			if !committed {
				_ = retention.rollback()
			}
		}()
		if err := s.inspectGovernedStreamFile(ctx, governed, path, name); err != nil {
			return err
		}
		if s.cfg.GovernedReceiptRecorder == nil {
			if s.cfg.RequireGovernedReceipts {
				return fmt.Errorf("governed receipt recorder is not configured")
			}
			committed = true
			return nil
		}
		if err := recordGovernedReceipt(ctx, s.cfg.GovernedReceiptRecorder, governed.Intent, governed.Decision, governed.Disclosure); err != nil {
			return fmt.Errorf("record governed stream receipt: %w", err)
		}
		committed = true
		return nil
	}

	idle := s.effectiveIdleTimeout()
	dl, canDeadline := conn.(readDeadliner)
	for {
		// Reset the idle/read deadline before every frame so a slowloris
		// peer that opens a connection and then dribbles or stalls is torn
		// down instead of holding the goroutine and its buffers forever.
		if canDeadline && idle > 0 {
			_ = dl.SetReadDeadline(time.Now().Add(idle))
		}
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

		var (
			saveErr  error
			ackFrame *Frame
			governed *GovernedFrame
			streamed *GovernedStreamInit
			delivery persistedDelivery
		)
		if frame.Type == TypeGoverned {
			decoded, governErr := DecodeGovernedFrame(frame)
			if governErr != nil {
				saveErr = governErr
			} else if s.cfg.GovernedVerifier == nil {
				saveErr = fmt.Errorf("governed frame received but no verifier is configured")
			} else if governErr = s.cfg.GovernedVerifier.VerifyGovernedFrame(ctx, conn.RemoteAddr(), decoded); governErr != nil {
				saveErr = governErr
			} else {
				governed = &decoded
				frame = governed.DataFrame()
			}
		} else if frame.Type == TypeGovernedFileStream {
			decoded, governErr := DecodeGovernedStreamInit(frame)
			if governErr != nil {
				saveErr = governErr
			} else if s.cfg.GovernedStreamVerifier == nil {
				saveErr = fmt.Errorf("governed stream received but no verifier is configured")
			} else if governErr = s.cfg.GovernedStreamVerifier.VerifyGovernedStreamInit(ctx, conn.RemoteAddr(), decoded); governErr != nil {
				saveErr = governErr
			} else {
				streamed = &decoded
				frame = streamed.InitFrame()
			}
		} else if s.cfg.RequireGoverned && frame.Type != TypeFileStream {
			saveErr = fmt.Errorf("unsigned legacy frame rejected by governed receiver")
		}
		if saveErr == nil {
			if governed != nil {
				saveErr = s.admitGovernedTransfer(governed.Intent, uint64(len(governed.Payload)))
			} else if streamed != nil {
				declaredBytes, declaredErr := streamed.DeclaredBytes()
				if declaredErr != nil {
					saveErr = declaredErr
				} else {
					saveErr = s.admitGovernedTransfer(streamed.Intent, declaredBytes)
				}
			}
		}
		if saveErr == nil {
			if governed != nil {
				saveErr = s.requireGovernedRetention(governed.Disclosure)
			} else if streamed != nil {
				saveErr = s.requireGovernedRetention(streamed.Disclosure)
			}
		}
		if saveErr == nil {
			if governed != nil && frame.Type != TypeFileStream {
				saveErr = s.inspectGovernedFrame(ctx, *governed)
			}
		}
		if saveErr == nil {
			switch frame.Type {
			case TypeFileStream:
				// Chunked/resumable transfer. The receiver emits its own
				// control responses (INIT-ACK / ACK / COMPLETE), so skip the
				// generic per-frame ACK below.
				if sr == nil {
					dir, derr := s.receivedDir()
					if derr != nil {
						_ = WriteFrame(conn, &Frame{Type: TypeText, Payload: []byte("ERR received dir: " + derr.Error())})
						return
					}
					if mderr := os.MkdirAll(dir, 0700); mderr != nil {
						_ = WriteFrame(conn, &Frame{Type: TypeText, Payload: []byte("ERR mkdir: " + mderr.Error())})
						return
					}
					sr = NewStreamReceiverWithQuotaAndPrepareAndCommit(dir, streamNameSuffix, streamOnSaved, streamOnPrepare, streamOnCommit, s.effectiveReceivedMaxBytes())
				}
				kind, id, _, validStreamFrame := decodeStreamFrame(frame)
				if !validStreamFrame {
					_ = WriteFrame(conn, encodeComplete(id, false, "malformed stream frame"))
					continue
				}
				if s.cfg.RequireGoverned {
					if streamed == nil {
						if kind == streamKindInit || !streamBound(governedStreams, id) {
							_ = WriteFrame(conn, encodeComplete(id, false, "unsigned stream frame rejected by governed receiver"))
							continue
						}
					} else if kind != streamKindInit {
						_ = WriteFrame(conn, encodeComplete(id, false, "governed stream envelope must carry INIT"))
						continue
					}
				}
				if resp := sr.HandleFrame(frame); resp != nil {
					responseKind, _, responseBody, responseValid := decodeStreamFrame(resp)
					if streamed != nil && responseValid && responseKind == streamKindInitAck {
						governedStreams[id] = *streamed
					}
					if responseValid && responseKind == streamKindComplete {
						completeOK, _ := decodeComplete(responseBody)
						if completeOK {
							delete(governedStreams, id)
						}
					}
					if werr := WriteFrame(conn, resp); werr != nil {
						return
					}
				}
				if kind == streamKindAbort {
					delete(governedStreams, id)
				}
				continue
			case TypeFile:
				if frame.Filename != "" {
					if governed != nil {
						delivery, saveErr = s.prepareReceivedFile(frame, governed.Disclosure)
					} else {
						saveErr = s.saveReceivedFile(frame)
					}
				}
			case TypeText, TypeJSON, TypeBinary:
				if governed != nil {
					delivery, saveErr = s.prepareInboxMessage(frame, conn.RemoteAddr(), governed.Disclosure)
				} else {
					saveErr = s.saveInboxMessage(frame, conn.RemoteAddr())
				}
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
			default:
				saveErr = fmt.Errorf("unsupported frame type %d", frame.Type)
			}
		}
		if saveErr == nil && governed != nil && delivery.commit != nil {
			if s.cfg.GovernedReceiptRecorder == nil {
				if s.cfg.RequireGovernedReceipts {
					saveErr = fmt.Errorf("governed receipt recorder is not configured")
				}
			} else if receiptErr := recordGovernedReceipt(ctx, s.cfg.GovernedReceiptRecorder, governed.Intent, governed.Decision, governed.Disclosure); receiptErr != nil {
				if delivery.rollback != nil {
					if rollbackErr := delivery.rollback(); rollbackErr != nil {
						receiptErr = fmt.Errorf("%w; remove unreceipted delivery: %v", receiptErr, rollbackErr)
					}
				}
				saveErr = fmt.Errorf("record governed delivery receipt: %w", receiptErr)
			}
		}
		if saveErr == nil && delivery.commit != nil {
			delivery.commit()
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

func (s *Service) admitGovernedTransfer(intent decision.Intent, bytes uint64) error {
	if s.replay != nil {
		if err := s.replay.admit(intent); err != nil {
			slog.Warn("governed transfer replay rejected", "agent_id", intent.AgentID, "intent_id", intent.ID, "error", err)
			return err
		}
	}
	if s.cfg.GovernedTransferQuota == nil {
		return nil
	}
	if err := s.cfg.GovernedTransferQuota.Allow(intent.AgentID, bytes); err != nil {
		slog.Warn("governed transfer quota rejected", "agent_id", intent.AgentID, "bytes", bytes, "error", err)
		return fmt.Errorf("governed transfer quota rejected")
	}
	return nil
}

func streamBound(streams map[[transferIDLen]byte]GovernedStreamInit, id [transferIDLen]byte) bool {
	_, exists := streams[id]
	return exists
}

func (s *Service) inspectGovernedFrame(ctx context.Context, governed GovernedFrame) error {
	if s.cfg.GovernedContentInspector == nil {
		return nil
	}
	contentType := contentTypeForFrame(governed.Type, governed.Disclosure)
	if err := s.cfg.GovernedContentInspector.InspectDisclosureContent(ctx, governed.Intent, governed.Disclosure, contentType, governed.Filename, bytes.NewReader(governed.Payload)); err != nil {
		slog.Warn("governed content inspection rejected", "action", governed.Intent.Action, "resource", governed.Intent.Resource, "error", err)
		return fmt.Errorf("governed content inspection rejected")
	}
	return nil
}

func (s *Service) inspectGovernedStreamFile(ctx context.Context, governed GovernedStreamInit, path string, filename string) error {
	if s.cfg.GovernedContentInspector == nil {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("governed content inspection rejected")
	}
	defer file.Close()
	contentType := contentTypeForFrame(TypeFile, governed.Disclosure)
	// Stream the verified on-disk body directly. A scanner that cannot process
	// the whole file must return an error; truncating the reader would create a
	// bypass for sensitive content placed after an arbitrary byte boundary.
	if err := s.cfg.GovernedContentInspector.InspectDisclosureContent(ctx, governed.Intent, governed.Disclosure, contentType, filename, file); err != nil {
		slog.Warn("governed stream content inspection rejected", "action", governed.Intent.Action, "resource", governed.Intent.Resource, "error", err)
		return fmt.Errorf("governed content inspection rejected")
	}
	return nil
}

func contentTypeForFrame(frameType uint32, disclosure *decision.DisclosureBinding) string {
	if disclosure != nil {
		return disclosure.ContentType
	}
	switch frameType {
	case TypeText:
		return "text/plain"
	case TypeJSON:
		return "application/json"
	default:
		return "application/octet-stream"
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
	delivery, err := s.prepareReceivedFile(frame, nil)
	if err != nil {
		return err
	}
	delivery.commit()
	return nil
}

func (s *Service) prepareReceivedFile(frame *Frame, disclosure *decision.DisclosureBinding) (persistedDelivery, error) {
	dir, err := s.receivedDir()
	if err != nil {
		slog.Warn("save received file: cannot determine dir", "err", err)
		return persistedDelivery{}, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		slog.Warn("save received file: mkdir failed", "err", err)
		return persistedDelivery{}, fmt.Errorf("mkdir: %w", err)
	}

	// Disk quota: reject the file up front if storing it would push the
	// received directory (completed files + retained .partial fragments)
	// past the quota, so a peer cannot fill the disk one file at a time.
	if quota := s.effectiveReceivedMaxBytes(); quota > 0 {
		current, _ := dirTotalBytes(dir)
		if current+int64(len(frame.Payload)) > quota {
			slog.Warn("received-files quota exceeded",
				"current_bytes", current, "max_bytes", quota,
				"frame_bytes", len(frame.Payload))
			if s.deps.Events != nil {
				s.deps.Events.Publish("received.full", map[string]any{
					"type":        TypeName(frame.Type),
					"frame_bytes": len(frame.Payload),
					"max_bytes":   quota,
				})
			}
			return persistedDelivery{}, fmt.Errorf("received-files quota exceeded: %d + %d > %d",
				current, len(frame.Payload), quota)
		}
	}

	safeName := filepath.Base(frame.Filename)
	ts := time.Now().Format("20060102-150405.000")
	seq := s.seq.Add(1)
	ext := filepath.Ext(safeName)
	base := safeName[:len(safeName)-len(ext)]
	destName := fmt.Sprintf("%s-%s-%06d%s", base, ts, seq, ext)
	destPath := filepath.Join(dir, destName)
	retention, err := s.prepareGovernedRetention(disclosure, destPath)
	if err != nil {
		return persistedDelivery{}, err
	}

	if err := os.WriteFile(destPath, frame.Payload, 0600); err != nil {
		_ = os.Remove(destPath)
		_ = retention.rollback()
		slog.Warn("save received file: write failed", "path", destPath, "err", err)
		return persistedDelivery{}, fmt.Errorf("write: %w", err)
	}
	return persistedDelivery{
		rollback: func() error {
			removeErr := os.Remove(destPath)
			retentionErr := retention.rollback()
			if removeErr != nil && !os.IsNotExist(removeErr) {
				return removeErr
			}
			return retentionErr
		},
		commit: func() {
			slog.Info("file saved", "path", destPath, "bytes", len(frame.Payload))
			if s.deps.Events != nil {
				s.deps.Events.Publish("file.received", map[string]any{
					"filename": safeName, "size": len(frame.Payload), "path": destPath,
				})
			}
		},
	}, nil
}

func (s *Service) saveInboxMessage(frame *Frame, from protocol.Addr) error {
	delivery, err := s.prepareInboxMessage(frame, from, nil)
	if err != nil {
		return err
	}
	delivery.commit()
	return nil
}

func (s *Service) prepareInboxMessage(frame *Frame, from protocol.Addr, disclosure *decision.DisclosureBinding) (persistedDelivery, error) {
	dir, err := s.inboxDir()
	if err != nil {
		return persistedDelivery{}, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return persistedDelivery{}, fmt.Errorf("mkdir: %w", err)
	}

	ts := time.Now()
	msg := map[string]interface{}{
		"type":        TypeName(frame.Type),
		"from":        from.String(),
		"bytes":       len(frame.Payload),
		"received_at": ts.Format(time.RFC3339Nano),
	}
	// Store the payload losslessly. JSON cannot represent arbitrary bytes in
	// a string — invalid UTF-8 is replaced with U+FFFD by encoding/json — so
	// any payload that is not valid UTF-8 (all binary frames, in practice)
	// is written as base64 instead of being silently corrupted. IncludeBase64
	// forces base64 for every payload (back-compat for consumers that always
	// expect data_b64). A `data_encoding` field tells the reader which form
	// to expect.
	if s.cfg.IncludeBase64 || frame.Type == TypeBinary || !utf8.Valid(frame.Payload) {
		msg["data_b64"] = base64.StdEncoding.EncodeToString(frame.Payload)
		msg["data_encoding"] = "base64"
	} else {
		msg["data"] = string(frame.Payload)
		msg["data_encoding"] = "utf8"
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return persistedDelivery{}, fmt.Errorf("marshal: %w", err)
	}
	size := int64(len(data))

	// Byte budget: admit the exact file size BEFORE writing, evicting the
	// oldest messages if needed. The cap is always on (defaulted) unless the
	// operator explicitly disables it with a negative config value.
	maxBytes := s.effectiveInboxMaxBytes()
	if maxBytes > 0 {
		if err := s.reserveInbox(dir, size, maxBytes); err != nil {
			slog.Warn("inbox byte budget exceeded",
				"max_bytes", maxBytes,
				"message_bytes", size,
				"err", err)
			if s.deps.Events != nil {
				s.deps.Events.Publish("inbox.full", map[string]any{
					"from":        from.String(),
					"type":        TypeName(frame.Type),
					"frame_bytes": len(frame.Payload),
					"max_bytes":   maxBytes,
				})
			}
			return persistedDelivery{}, err
		}
	}
	written := false
	defer func() {
		if maxBytes > 0 {
			s.inboxWriteDone(size, written)
		}
	}()

	seq := s.seq.Add(1)
	filename := fmt.Sprintf("%s-%s-%06d.json", TypeName(frame.Type), ts.Format("20060102-150405.000"), seq)
	destPath := filepath.Join(dir, filename)
	retention, err := s.prepareGovernedRetention(disclosure, destPath)
	if err != nil {
		return persistedDelivery{}, err
	}
	if err := os.WriteFile(destPath, data, 0600); err != nil {
		_ = retention.rollback()
		return persistedDelivery{}, fmt.Errorf("write: %w", err)
	}
	written = true
	return persistedDelivery{
		rollback: func() error {
			removeErr := os.Remove(destPath)
			if removeErr == nil && maxBytes > 0 {
				s.inboxFileRemoved(size)
			}
			retentionErr := retention.rollback()
			if removeErr != nil && !os.IsNotExist(removeErr) {
				return removeErr
			}
			return retentionErr
		},
		commit: func() {
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
		},
	}, nil
}

// dirTotalBytes sums the on-disk size of every regular file under dir,
// recursively — so the received-files quota accounts for both completed
// files and the .partial fragments of in-flight streamed transfers. A
// missing directory counts as zero (not yet created).
func dirTotalBytes(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable entries; best-effort accounting
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	if os.IsNotExist(err) {
		return 0, nil
	}
	return total, err
}
