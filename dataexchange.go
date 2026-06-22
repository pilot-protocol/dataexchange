// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Frame types for data exchange on port 1001.
const (
	TypeText   uint32 = 1
	TypeBinary uint32 = 2
	TypeJSON   uint32 = 3
	TypeFile   uint32 = 4
	// TypeTrace wraps another frame type with nanosecond-precision timing.
	// Wire layout: [4-byte TypeTrace][4-byte len][4-byte inner_type][8-byte sent_at_ns][inner_payload]
	TypeTrace uint32 = 5
	// Type 6 is reserved (see Alex's reply-on-conn PR chain / TypeAutoAnswer).
	//
	// TypeFileStream is the chunked/ACK'd/resumable file-transfer protocol
	// (see docs/PROPOSAL-reliable-file-transfer.md and filestream.go). Each
	// TypeFileStream frame carries a small control header + at most one
	// chunk of file data, so a multi-GiB transfer never collapses into a
	// single giant frame the way TypeFile does. Backward compatible: a
	// peer that does not understand TypeFileStream never sends INIT-ACK, so
	// the sender falls back to TypeFile.
	TypeFileStream uint32 = 7
)

// TraceFrame carries timing metadata around an inner message frame.
type TraceFrame struct {
	SentAtNs  int64
	InnerType uint32
	Payload   []byte
}

// WriteTraceFrame serialises a TraceFrame as a TypeTrace outer frame.
func WriteTraceFrame(w io.Writer, tf *TraceFrame) error {
	buf := make([]byte, 12+len(tf.Payload))
	binary.BigEndian.PutUint32(buf[0:4], tf.InnerType)
	binary.BigEndian.PutUint64(buf[4:12], uint64(tf.SentAtNs))
	copy(buf[12:], tf.Payload)
	return WriteFrame(w, &Frame{Type: TypeTrace, Payload: buf})
}

// ReadTracePayload decodes a TraceFrame from a raw TypeTrace Frame.
func ReadTracePayload(f *Frame) (*TraceFrame, error) {
	if f.Type != TypeTrace {
		return nil, fmt.Errorf("expected TypeTrace, got %d", f.Type)
	}
	if len(f.Payload) < 12 {
		return nil, fmt.Errorf("trace payload too short: %d bytes", len(f.Payload))
	}
	return &TraceFrame{
		InnerType: binary.BigEndian.Uint32(f.Payload[0:4]),
		SentAtNs:  int64(binary.BigEndian.Uint64(f.Payload[4:12])),
		Payload:   f.Payload[12:],
	}, nil
}

// maxFilenameLen limits filename length to prevent abuse.
const maxFilenameLen = 255

// DefaultMaxFrameSize caps a single data-exchange frame at 64 MiB.
//
// The wire format's length field is a uint32 (see Frame docstring below),
// so the absolute ceiling is ~4 GiB; this cap exists to bound the memory a
// single hostile peer can make the receiver commit for one transfer. The
// receiver no longer pre-allocates the attacker-declared length up front
// (see ReadFrame) — it grows the buffer as bytes actually arrive — but the
// cap still bounds the steady-state worst case, so it is deliberately set
// well below the wire ceiling.
//
// 64 MiB comfortably covers inbox messages and the deprecated legacy
// single-frame TypeFile path; anything larger should ride the chunked
// TypeFileStream protocol (filestream.go), which never buffers a whole
// file in memory. Operators who genuinely need bigger single frames can
// raise the cap via PILOT_DATAEXCHANGE_MAX_FRAME (both ends must agree).
//
// History: 256 MiB pre-2026-06-14, then briefly 1 GiB (sized for the test
// fleet's 100 MiB payloads on multi-GiB-RAM hosts). 1 GiB let a single
// hostile peer OOM the receiver, so the default was lowered to 64 MiB and
// the up-front allocation was removed.
const DefaultMaxFrameSize uint32 = 64 << 20

// MaxFrameSize is the runtime-effective frame cap. Set at package init
// from the PILOT_DATAEXCHANGE_MAX_FRAME env var (in bytes) if present
// and within the safe range [64 KiB, 2 GiB); otherwise DefaultMaxFrameSize.
//
// Both ends of a transfer must agree on the cap — a sender that exceeds
// the receiver's cap will see the receiver return "frame too large" and
// drop the connection. The env var is honored at process start, so
// rolling out a higher cap means restarting daemons on both sides.
var MaxFrameSize uint32 = func() uint32 {
	v := os.Getenv("PILOT_DATAEXCHANGE_MAX_FRAME")
	if v == "" {
		return DefaultMaxFrameSize
	}
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n < 1<<16 || n >= 1<<31 {
		// Silently ignore garbage / unsafe values rather than crash the
		// daemon at startup — surface them via the daemon log if the
		// operator opted in.
		return DefaultMaxFrameSize
	}
	return uint32(n)
}()

// Frame is a typed data unit exchanged between agents.
// Wire format: [4-byte type][4-byte length][payload]
// For TypeFile, payload is: [2-byte name length][name bytes][file data]
type Frame struct {
	Type     uint32
	Payload  []byte
	Filename string // only for TypeFile
}

// WriteFrame writes a frame to a writer.
func WriteFrame(w io.Writer, f *Frame) error {
	payload := f.Payload
	if f.Type == TypeFile {
		// Prepend filename. Validate the length BEFORE the uint16 cast: a
		// name longer than 65535 bytes would wrap the 2-byte length field
		// and silently truncate, and any name over maxFilenameLen is
		// rejected by ReadFrame anyway — fail fast on the writer side.
		name := []byte(f.Filename)
		if len(name) > maxFilenameLen {
			return fmt.Errorf("filename too long: %d bytes (max %d)", len(name), maxFilenameLen)
		}
		payload = make([]byte, 2+len(name)+len(f.Payload))
		binary.BigEndian.PutUint16(payload[0:2], uint16(len(name)))
		copy(payload[2:], name)
		copy(payload[2+len(name):], f.Payload)
	}

	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], f.Type)
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads a frame from a reader.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	ftype := binary.BigEndian.Uint32(hdr[0:4])
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d (max %d)", length, MaxFrameSize)
	}

	// Do NOT pre-allocate `length` bytes — that is the attacker-declared
	// size, so a single hostile peer could announce a huge (but in-cap)
	// frame and never send the bytes, pinning that much RAM per connection.
	// Instead grow incrementally as bytes actually arrive, with a bounded
	// starting capacity. io.CopyN stops at exactly `length`, and the final
	// length is re-checked so a truncated stream surfaces as ErrUnexpectedEOF.
	payload, err := readBounded(r, int64(length))
	if err != nil {
		return nil, err
	}

	f := &Frame{Type: ftype, Payload: payload}

	if ftype == TypeFile && len(payload) >= 2 {
		nameLen := binary.BigEndian.Uint16(payload[0:2])
		if int(nameLen)+2 <= len(payload) {
			if nameLen > maxFilenameLen {
				return nil, fmt.Errorf("filename too long: %d bytes (max %d)", nameLen, maxFilenameLen)
			}
			nameBytes := payload[2 : 2+nameLen]
			if !utf8.Valid(nameBytes) {
				return nil, fmt.Errorf("filename contains invalid UTF-8")
			}
			name := string(nameBytes)
			if strings.ContainsAny(name, "/\\") {
				return nil, fmt.Errorf("invalid filename: path traversal characters not allowed")
			}
			if name != "" {
				f.Filename = filepath.Base(name)
				if f.Filename == "." || f.Filename == ".." {
					return nil, fmt.Errorf("invalid filename: path traversal name %q not allowed", f.Filename)
				}
			}
			f.Payload = payload[2+nameLen:]
		}
	}

	return f, nil
}

// readBoundedInitialCap bounds the initial buffer capacity reserved before
// any payload bytes arrive. A frame can legitimately be up to MaxFrameSize,
// but reserving that much for the declared (untrusted) length is exactly the
// OOM vector we are closing — so we reserve at most this much up front and
// let bytes.Buffer grow geometrically as real data lands.
const readBoundedInitialCap = 64 * 1024

// readBounded reads exactly n bytes from r without trusting n to size the
// initial allocation. It grows a buffer as bytes arrive (capped initial
// reservation), so an attacker who declares a large length but never sends
// the bytes only ties up the small initial buffer, not n bytes. A short
// read returns io.ErrUnexpectedEOF, matching io.ReadFull's contract.
func readBounded(r io.Reader, n int64) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}
	initial := n
	if initial > readBoundedInitialCap {
		initial = readBoundedInitialCap
	}
	buf := bytes.NewBuffer(make([]byte, 0, initial))
	read, err := io.CopyN(buf, r, n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if read != n {
		return nil, io.ErrUnexpectedEOF
	}
	return buf.Bytes(), nil
}

// TypeName returns a human-readable name for a frame type.
func TypeName(t uint32) string {
	switch t {
	case TypeText:
		return "TEXT"
	case TypeBinary:
		return "BINARY"
	case TypeJSON:
		return "JSON"
	case TypeFile:
		return "FILE"
	case TypeTrace:
		return "TRACE"
	case TypeFileStream:
		return "FILESTREAM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
