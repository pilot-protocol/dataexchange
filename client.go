// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

// Client connects to a remote data exchange service on port 1001.
type Client struct {
	conn *driver.Conn
}

// Dial connects to a remote agent's data exchange port.
func Dial(d *driver.Driver, addr protocol.Addr) (*Client, error) {
	conn, err := d.DialAddr(addr, protocol.PortDataExchange)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// ErrRejected is wrapped by the error Client.Send returns when the receiver
// answered with an "ERR ..." acknowledgement instead of storing the frame.
var ErrRejected = errors.New("dataexchange: receiver rejected frame")

// SendResult reports what the receiver did with a frame sent by Client.Send.
type SendResult struct {
	// Ack is the receiver's acknowledgement frame, normally a TypeText
	// "ACK <TYPE> <n> bytes" (or "ERR ..." on rejection).
	Ack *Frame
	// Tagged is true when the frame's MessageID/ReplyTo reached the
	// receiver. It is false when the frame carried neither, or when the
	// receiver predates TypeTagged and the frame was delivered untagged.
	Tagged bool
	// Duplicate is true when the receiver recognised the frame as an
	// identical re-delivery of one it had already stored, and did not store
	// it a second time.
	Duplicate bool
}

// duplicateAckSuffix is appended to the ACK of a frame the receiver
// suppressed as a duplicate. The ACK still starts with "ACK ", so senders
// that only check the prefix keep treating it as success.
const duplicateAckSuffix = " (duplicate)"

// untaggedReceiverAckPrefix is how a receiver that predates TypeTagged
// answers a tagged frame: it does not know type 10, stores nothing, and
// replies "ERR UNKNOWN(10) save failed: ...".
var untaggedReceiverAckPrefix = fmt.Sprintf("ERR UNKNOWN(%d) ", TypeTagged)

// Send writes frame, waits for the receiver's acknowledgement and reports
// the outcome. It is the preferred way to send a frame that carries a
// MessageID or ReplyTo: if the receiver predates TypeTagged, Send re-sends
// the same frame without the metadata on the same connection, so older peers
// still get the message (they could not have stored the tagged copy).
//
// If the receiver answers "ERR ...", Send returns the result together with
// an error wrapping ErrRejected. Send reads from the connection, so do not
// use it concurrently with Recv on the same Client.
func (c *Client) Send(frame *Frame) (*SendResult, error) {
	return sendAndAwaitAck(c.conn, frame)
}

func sendAndAwaitAck(rw io.ReadWriter, frame *Frame) (*SendResult, error) {
	if frame == nil {
		return nil, fmt.Errorf("dataexchange: frame is required")
	}
	tagged := frame.MessageID != "" || frame.ReplyTo != ""
	if err := WriteFrame(rw, frame); err != nil {
		return nil, err
	}
	ack, err := ReadFrame(rw)
	if err != nil {
		return nil, fmt.Errorf("dataexchange: read ack: %w", err)
	}
	if tagged && ack.Type == TypeText && strings.HasPrefix(string(ack.Payload), untaggedReceiverAckPrefix) {
		plain := *frame
		plain.MessageID, plain.ReplyTo = "", ""
		if err := WriteFrame(rw, &plain); err != nil {
			return nil, err
		}
		if ack, err = ReadFrame(rw); err != nil {
			return nil, fmt.Errorf("dataexchange: read ack: %w", err)
		}
		tagged = false
	}
	text := string(ack.Payload)
	result := &SendResult{
		Ack:       ack,
		Tagged:    tagged,
		Duplicate: ack.Type == TypeText && strings.HasPrefix(text, "ACK ") && strings.HasSuffix(text, duplicateAckSuffix),
	}
	if ack.Type == TypeText && strings.HasPrefix(text, "ERR ") {
		return result, fmt.Errorf("%w: %s", ErrRejected, text)
	}
	return result, nil
}

// SendText sends a text frame.
func (c *Client) SendText(text string) error {
	return WriteFrame(c.conn, &Frame{Type: TypeText, Payload: []byte(text)})
}

// SendJSON sends a JSON frame.
func (c *Client) SendJSON(data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeJSON, Payload: data})
}

// SendBinary sends a binary frame.
func (c *Client) SendBinary(data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeBinary, Payload: data})
}

// SendFile sends a file frame with a filename and data.
func (c *Client) SendFile(name string, data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeFile, Filename: name, Payload: data})
}

// SendGoverned sends a frame with exact signed intent/decision evidence.
// The remote service must have RequireGoverned enabled to enforce it.
func (c *Client) SendGoverned(frame *Frame, intent decision.Intent, result decision.Decision) error {
	governed, err := NewGovernedFrame(frame, intent, result)
	if err != nil {
		return err
	}
	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		return err
	}
	return WriteFrame(c.conn, envelope)
}

// SendGovernedWithDisclosure sends a single governed message or file with a
// typed disclosure binding. The Intent and Decision must already have been
// obtained for the exact binding.
func (c *Client) SendGovernedWithDisclosure(frame *Frame, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding) error {
	governed, err := NewGovernedFrameWithDisclosure(frame, intent, result, disclosure)
	if err != nil {
		return err
	}
	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		return err
	}
	return WriteFrame(c.conn, envelope)
}

// SendGovernedFileStream sends a large resumable file with a signed authority
// decision bound to its exact INIT metadata. Callers compute the intent payload
// hash with GovernedStreamPayloadHash over the deterministic INIT payload (use
// BuildStreamInitPayload after calculating the file hash), then pass the same
// signed intent and decision here. The receiver accepts chunks only for that
// verified transfer ID and records its receipt on successful completion.
func (c *Client) SendGovernedFileStream(name string, r io.ReadSeeker, size int64, intent decision.Intent, result decision.Decision, stepTimeout time.Duration) (*StreamResult, error) {
	return c.SendGovernedFileStreamWithAuthorizer(name, r, size, func(_ []byte) (decision.Intent, decision.Decision, error) {
		return intent, result, nil
	}, stepTimeout)
}

// SendGovernedFileStreamWithDisclosure sends a governed resumable file whose
// Intent and authority Decision bind the supplied typed disclosure metadata.
// The metadata must match the final INIT (content hash, size, filename, and
// transfer ID) exactly; callers can derive these with BuildStreamInitPayload.
func (c *Client) SendGovernedFileStreamWithDisclosure(name string, r io.ReadSeeker, size int64, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding, stepTimeout time.Duration) (*StreamResult, error) {
	return streamSendWithInit(c.conn, name, r, size, stepTimeout, func(id [transferIDLen]byte, declaredSize uint64, hash [32]byte, chunkSize uint32, filename string) (*Frame, error) {
		init := encodeInit(id, declaredSize, hash, chunkSize, filename)
		governed, err := NewGovernedStreamInitWithDisclosure(init, intent, result, disclosure)
		if err != nil {
			return nil, err
		}
		return EncodeGovernedStreamInit(governed)
	})
}

// GovernedStreamAuthorizer receives the exact FileStream INIT payload after
// its stable transfer ID and content hash have been calculated. It must return
// a short-lived signed Intent and Decision bound to that exact payload. The
// callback runs before any stream frame is written, so a deny or unavailable
// authority cannot produce a partial transfer.
type GovernedStreamAuthorizer func(initPayload []byte) (decision.Intent, decision.Decision, error)

// GovernedStreamDisclosureAuthorizer returns typed disclosure evidence for
// the exact INIT. Hosted federation clients use this after uploading the full
// file content and before the first stream byte is released to the peer.
type GovernedStreamDisclosureAuthorizer func(initPayload []byte) (decision.Intent, decision.Decision, decision.DisclosureBinding, error)

// SendGovernedFileStreamWithAuthorizer obtains an exact signed decision only
// after the resumable stream's INIT bytes are known. This is the preferred
// sender API when the decision comes from an online authority.
func (c *Client) SendGovernedFileStreamWithAuthorizer(name string, r io.ReadSeeker, size int64, authorize GovernedStreamAuthorizer, stepTimeout time.Duration) (*StreamResult, error) {
	if authorize == nil {
		return nil, fmt.Errorf("dataexchange: governed stream authorizer is required")
	}
	return streamSendWithInit(c.conn, name, r, size, stepTimeout, func(id [transferIDLen]byte, declaredSize uint64, hash [32]byte, chunkSize uint32, filename string) (*Frame, error) {
		init := encodeInit(id, declaredSize, hash, chunkSize, filename)
		intent, result, err := authorize(append([]byte(nil), init.Payload...))
		if err != nil {
			return nil, err
		}
		governed, err := NewGovernedStreamInit(init, intent, result)
		if err != nil {
			return nil, err
		}
		return EncodeGovernedStreamInit(governed)
	})
}

func (c *Client) SendGovernedFileStreamWithDisclosureAuthorizer(name string, r io.ReadSeeker, size int64, authorize GovernedStreamDisclosureAuthorizer, stepTimeout time.Duration) (*StreamResult, error) {
	if authorize == nil {
		return nil, fmt.Errorf("dataexchange: governed stream disclosure authorizer is required")
	}
	return streamSendWithInit(c.conn, name, r, size, stepTimeout, func(id [transferIDLen]byte, declaredSize uint64, hash [32]byte, chunkSize uint32, filename string) (*Frame, error) {
		init := encodeInit(id, declaredSize, hash, chunkSize, filename)
		intent, result, disclosure, err := authorize(append([]byte(nil), init.Payload...))
		if err != nil {
			return nil, err
		}
		governed, err := NewGovernedStreamInitWithDisclosure(init, intent, result, disclosure)
		if err != nil {
			return nil, err
		}
		return EncodeGovernedStreamInit(governed)
	})
}

// SendTrace wraps data in a TypeTrace frame with the current nanosecond clock.
// Returns sentAtNs so the caller can correlate it against the timing ACK.
func (c *Client) SendTrace(innerType uint32, data []byte) (sentAtNs int64, err error) {
	sentAtNs = time.Now().UnixNano()
	err = WriteTraceFrame(c.conn, &TraceFrame{
		SentAtNs:  sentAtNs,
		InnerType: innerType,
		Payload:   data,
	})
	return
}

// Recv reads the next frame from the connection.
func (c *Client) Recv() (*Frame, error) {
	return ReadFrame(c.conn)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
