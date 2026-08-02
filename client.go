// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"fmt"
	"io"
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
