// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Request/reply correlation on the wire.
//
// A frame that carries a MessageID or ReplyTo travels as a TypeTagged frame:
//
//	[4-byte TypeTagged][4-byte length][payload]
//	payload = [2-byte header_len][header: UTF-8 JSON object]
//	          [4-byte inner_type][inner payload]
//
// The header is a JSON object such as
//
//	{"message_id":"4f1c…","reply_to":"9b2e…"}
//
// Both keys are optional; unknown keys are ignored so later versions can add
// fields. The inner payload is exactly what the inner type carries on its
// own (a TypeFile inner keeps its [2-byte name length][name] prefix), and
// the inner type may be any type except TypeTagged itself.
//
// Compatibility: a frame without a MessageID or ReplyTo is written in the
// original format, byte for byte, so nothing changes for peers that do not
// use correlation. A receiver that predates TypeTagged answers a tagged
// frame with "ERR UNKNOWN(10) ..." and stores nothing; Client.Send detects
// that answer and re-sends the same frame untagged on the same connection.

// MaxMessageIDLen is the longest MessageID or ReplyTo value accepted on the
// wire. IDs are 1..MaxMessageIDLen bytes of ASCII letters, digits, '-', '_',
// '.' or ':' — enough for UUIDs, ULIDs and hex nonces, and safe to embed in
// file names, JSON and log lines without escaping.
const MaxMessageIDLen = 128

// maxTaggedHeaderLen bounds the JSON header of a TypeTagged frame. Two
// maximal IDs plus their keys fit comfortably; the cap keeps a hostile peer
// from making the receiver parse a large JSON document per frame.
const maxTaggedHeaderLen = 1024

// taggedHeader is the JSON header of a TypeTagged frame.
type taggedHeader struct {
	MessageID string `json:"message_id,omitempty"`
	ReplyTo   string `json:"reply_to,omitempty"`
}

// NewMessageID returns a random 128-bit message ID as 32 lowercase hex
// characters, suitable for Frame.MessageID.
func NewMessageID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read does not fail on supported platforms (Go 1.24+
		// crashes the program instead of returning an error).
		panic(fmt.Sprintf("dataexchange: crypto/rand: %v", err))
	}
	return hex.EncodeToString(b[:])
}

// ValidMessageID reports whether id is acceptable as a Frame.MessageID or
// Frame.ReplyTo value on the wire.
func ValidMessageID(id string) bool {
	if len(id) == 0 || len(id) > MaxMessageIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}

func validateTaggedHeader(h taggedHeader) error {
	if h.MessageID != "" && !ValidMessageID(h.MessageID) {
		return fmt.Errorf("invalid message_id: want 1-%d bytes of [A-Za-z0-9._:-]", MaxMessageIDLen)
	}
	if h.ReplyTo != "" && !ValidMessageID(h.ReplyTo) {
		return fmt.Errorf("invalid reply_to: want 1-%d bytes of [A-Za-z0-9._:-]", MaxMessageIDLen)
	}
	return nil
}

// taggedWirePayload encodes f (which carries a MessageID and/or ReplyTo) as
// the payload of a TypeTagged frame.
func taggedWirePayload(f *Frame) ([]byte, error) {
	if f.Type == TypeTagged {
		return nil, fmt.Errorf("dataexchange: a TypeTagged frame cannot itself carry MessageID/ReplyTo")
	}
	h := taggedHeader{MessageID: f.MessageID, ReplyTo: f.ReplyTo}
	if err := validateTaggedHeader(h); err != nil {
		return nil, fmt.Errorf("dataexchange: %w", err)
	}
	header, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("dataexchange: marshal tagged header: %w", err)
	}
	inner, err := wirePayload(f)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 2+len(header)+4+len(inner))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(header)))
	copy(out[2:], header)
	binary.BigEndian.PutUint32(out[2+len(header):], f.Type)
	copy(out[2+len(header)+4:], inner)
	return out, nil
}

// decodeTaggedPayload splits a TypeTagged payload into its header, inner
// type and inner payload. The inner payload aliases the input.
func decodeTaggedPayload(payload []byte) (taggedHeader, uint32, []byte, error) {
	var h taggedHeader
	if len(payload) < 2 {
		return h, 0, nil, fmt.Errorf("tagged frame too short: %d bytes", len(payload))
	}
	headerLen := int(binary.BigEndian.Uint16(payload[0:2]))
	if headerLen == 0 || headerLen > maxTaggedHeaderLen {
		return h, 0, nil, fmt.Errorf("tagged frame header length %d out of range (1-%d)", headerLen, maxTaggedHeaderLen)
	}
	if len(payload) < 2+headerLen+4 {
		return h, 0, nil, fmt.Errorf("tagged frame truncated: %d bytes for a %d-byte header", len(payload), headerLen)
	}
	if err := json.Unmarshal(payload[2:2+headerLen], &h); err != nil {
		return taggedHeader{}, 0, nil, fmt.Errorf("tagged frame header: %w", err)
	}
	if err := validateTaggedHeader(h); err != nil {
		return taggedHeader{}, 0, nil, fmt.Errorf("tagged frame header: %w", err)
	}
	innerType := binary.BigEndian.Uint32(payload[2+headerLen : 2+headerLen+4])
	if innerType == TypeTagged {
		return taggedHeader{}, 0, nil, fmt.Errorf("tagged frame cannot wrap another tagged frame")
	}
	return h, innerType, payload[2+headerLen+4:], nil
}
