// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"time"

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

// SendAutoAnswer sends a TypeAutoAnswer request: it opts in to
// reply-on-connection. The sender should follow this with a bounded Recv to
// read the reply an --auto-answer receiver writes back on this connection.
func (c *Client) SendAutoAnswer(text string) error {
	return WriteFrame(c.conn, &Frame{Type: TypeAutoAnswer, Payload: []byte(text)})
}

// SendBinary sends a binary frame.
func (c *Client) SendBinary(data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeBinary, Payload: data})
}

// SendFile sends a file frame with a filename and data.
func (c *Client) SendFile(name string, data []byte) error {
	return WriteFrame(c.conn, &Frame{Type: TypeFile, Filename: name, Payload: data})
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

// SetReadDeadline bounds the next Recv. A reply-aware sender uses this to wait
// a bounded window for a reply-on-connection (signalled by an "ACK+REPLY" ack
// from an --auto-answer receiver) without blocking forever on a plain receiver
// that never sends one. Pass the zero time to clear the deadline.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
