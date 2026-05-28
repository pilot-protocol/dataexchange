// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/driver"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// ---- IPC wire constants (mirror unexported driver.cmd* by value) -----------
//
// These MUST match driver/ipc.go. Duplicated here because the constants are
// unexported. A drift would surface as a test-only failure (the fake daemon
// would speak a different protocol than the real driver expects), not a
// production bug, so the duplication is contained.
const (
	wireCmdBind    byte = 0x01
	wireCmdBindOK  byte = 0x02
	wireCmdDial    byte = 0x03
	wireCmdDialOK  byte = 0x04
	wireCmdAccept  byte = 0x05
	wireCmdSend    byte = 0x06
	wireCmdRecv    byte = 0x07
	wireCmdClose   byte = 0x08
	wireCmdCloseOK byte = 0x09
)

// ---- length-prefixed IPC framer (mirrors internal/ipcutil) -----------------

func ipcWrite(w io.Writer, data []byte) error {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func ipcRead(r io.Reader) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lenBuf[:])
	if length > (1 << 20) {
		return nil, errors.New("ipc: oversized")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ---- fake daemon: just enough wire protocol for client.go ------------------

// shortSocketPath returns a /tmp path short enough for the macOS unix
// socket length limit (~104 chars). t.TempDir() paths exceed it on darwin.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join("/tmp", "dex-"+hex.EncodeToString(b[:])+".sock")
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeDaemon is a minimal IPC peer that responds to cmdDial with cmdDialOK
// and lets the test push cmdRecv frames + capture cmdSend frames.
type fakeDaemon struct {
	t       *testing.T
	ln      net.Listener
	path    string
	conn    net.Conn
	connSet chan struct{}

	// writeMu serialises writes from daemon→driver. The acceptLoop replies
	// to cmdBind/cmdDial concurrently with the test thread's push()/
	// pushAccept(); without this, interleaved writes corrupt the wire and
	// the driver's readLoop bails on a malformed length prefix.
	writeMu sync.Mutex

	mu   sync.Mutex
	sent [][]byte // every frame the driver wrote to us (post-Dial)
	// nextConnID returned on cmdDial.
	nextConnID uint32
}

// safeWrite is the only path that writes to d.conn. Acquires writeMu to
// prevent test thread pushes from interleaving with acceptLoop replies.
func (d *fakeDaemon) safeWrite(data []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c == nil {
		return errors.New("daemon: no conn yet")
	}
	return ipcWrite(c, data)
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	path := shortSocketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	d := &fakeDaemon{
		t:          t,
		ln:         ln,
		path:       path,
		connSet:    make(chan struct{}),
		nextConnID: 0x42,
	}
	go d.acceptLoop()
	return d
}

func (d *fakeDaemon) acceptLoop() {
	conn, err := d.ln.Accept()
	if err != nil {
		return
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	close(d.connSet)

	for {
		frame, err := ipcRead(conn)
		if err != nil {
			return
		}
		if len(frame) < 1 {
			continue
		}
		cmd := frame[0]
		switch cmd {
		case wireCmdDial:
			// Reply: [cmdDialOK][uint32 connID]
			resp := make([]byte, 5)
			resp[0] = wireCmdDialOK
			d.mu.Lock()
			cid := d.nextConnID
			d.nextConnID++
			d.mu.Unlock()
			binary.BigEndian.PutUint32(resp[1:5], cid)
			_ = d.safeWrite(resp)
		case wireCmdBind:
			// Reply: [cmdBindOK][port:2] — echo back the requested port.
			if len(frame) >= 3 {
				_ = d.safeWrite([]byte{wireCmdBindOK, frame[1], frame[2]})
			}
		case wireCmdSend, wireCmdClose:
			// Capture for assertion. cmdClose is fire-and-forget — no reply.
			d.mu.Lock()
			d.sent = append(d.sent, append([]byte(nil), frame...))
			d.mu.Unlock()
		}
	}
}

// newServerFakeDaemon is a thin alias: the same daemon, but the test
// name conveys that it'll handle cmdBind (server-side) rather than cmdDial
// (client-side). No behavioural difference — the handler accepts both.
func newServerFakeDaemon(t *testing.T) *fakeDaemon { return newFakeDaemon(t) }

// pushAccept fabricates a cmdAccept frame for `port` carrying a new conn
// `connID`. The full body the driver expects is:
//
//	[port:2][connID:4][remoteAddr:6][remotePort:2]
//
// (Driver's dispatchPush reads `port` from the leading 2 bytes; Listener.
// Accept then parses the rest.)
func (d *fakeDaemon) pushAccept(t *testing.T, port uint16, connID uint32) {
	t.Helper()
	// 1 (cmd) + 2 (port) + 4 (connID) + 6 (addr) + 2 (remotePort) = 15
	body := make([]byte, 1+2+4+6+2)
	body[0] = wireCmdAccept
	binary.BigEndian.PutUint16(body[1:3], port)
	binary.BigEndian.PutUint32(body[3:7], connID)
	// addr (6 zeros) + remotePort (2 zeros) are fine — server.handleConn
	// only uses the connection for reads, not addressing.
	d.push(t, body)
}

// push writes an unsolicited frame from daemon → driver (cmdRecv, etc.).
func (d *fakeDaemon) push(t *testing.T, frame []byte) {
	t.Helper()
	select {
	case <-d.connSet:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon: never accepted")
	}
	if err := d.safeWrite(frame); err != nil {
		t.Fatalf("push: %v", err)
	}
}

// allSent returns every captured cmd* frame in order.
func (d *fakeDaemon) allSent() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([][]byte, len(d.sent))
	copy(out, d.sent)
	return out
}

func (d *fakeDaemon) close() {
	_ = d.ln.Close()
	select {
	case <-d.connSet:
	case <-time.After(100 * time.Millisecond):
	}
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// reassembleSends concatenates the cmdSend bodies (after the 5-byte
// [cmd][connID] header) into one byte stream — i.e. the bytes the driver
// would have delivered to the remote peer's Conn.Read.
func reassembleSends(frames [][]byte) []byte {
	var out []byte
	for _, f := range frames {
		if len(f) < 5 || f[0] != wireCmdSend {
			continue
		}
		out = append(out, f[5:]...)
	}
	return out
}

// dialClient is the boilerplate shared by every Client_* test.
func dialClient(t *testing.T) (*driver.Driver, *fakeDaemon, *Client) {
	t.Helper()
	d := newFakeDaemon(t)
	drv, err := driver.Connect(d.path)
	if err != nil {
		d.close()
		t.Fatalf("driver.Connect: %v", err)
	}
	c, err := Dial(drv, protocol.Addr{Network: 1, Node: 0xBEEF})
	if err != nil {
		_ = drv.Close()
		d.close()
		t.Fatalf("Dial: %v", err)
	}
	return drv, d, c
}

// ---- Dial -----------------------------------------------------------------

func TestClient_Dial_Success(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	if c == nil {
		t.Fatal("Dial returned nil client")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestClient_Dial_NoDaemon — driver.Connect fails when the socket doesn't
// exist; Dial never gets called but the construction error is the same shape.
func TestClient_Dial_DaemonUnreachable(t *testing.T) {
	t.Parallel()
	// Bogus socket path: connect must fail.
	_, err := driver.Connect("/this/path/should/not/exist.sock")
	if err == nil {
		t.Fatal("expected Connect to fail with bogus socket path")
	}
}

// ---- SendText / SendJSON / SendBinary / SendFile / SendTrace --------------

func TestClient_SendText(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	if err := c.SendText("hello world"); err != nil {
		t.Fatalf("SendText: %v", err)
	}
	body := waitForCompleteFrame(t, d)
	f, err := ReadFrame(newByteReader(body))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeText {
		t.Errorf("Type = %d, want TypeText", f.Type)
	}
	if string(f.Payload) != "hello world" {
		t.Errorf("Payload = %q", f.Payload)
	}
	_ = c.Close()
}

func TestClient_SendJSON(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	payload := []byte(`{"k":42}`)
	if err := c.SendJSON(payload); err != nil {
		t.Fatalf("SendJSON: %v", err)
	}
	f, err := ReadFrame(newByteReader(waitForCompleteFrame(t, d)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeJSON || string(f.Payload) != string(payload) {
		t.Errorf("frame mismatch: %+v", f)
	}
	_ = c.Close()
}

func TestClient_SendBinary(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	if err := c.SendBinary(payload); err != nil {
		t.Fatalf("SendBinary: %v", err)
	}
	f, err := ReadFrame(newByteReader(waitForCompleteFrame(t, d)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeBinary {
		t.Errorf("Type = %d, want Binary", f.Type)
	}
	if string(f.Payload) != string(payload) {
		t.Errorf("Payload mismatch")
	}
	_ = c.Close()
}

func TestClient_SendFile(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	if err := c.SendFile("report.csv", []byte("a,b,c")); err != nil {
		t.Fatalf("SendFile: %v", err)
	}
	f, err := ReadFrame(newByteReader(waitForCompleteFrame(t, d)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if f.Type != TypeFile {
		t.Errorf("Type = %d, want File", f.Type)
	}
	if f.Filename != "report.csv" {
		t.Errorf("Filename = %q", f.Filename)
	}
	if string(f.Payload) != "a,b,c" {
		t.Errorf("Payload = %q", f.Payload)
	}
	_ = c.Close()
}

func TestClient_SendTrace(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	before := time.Now().UnixNano()
	sentAt, err := c.SendTrace(TypeJSON, []byte(`{"ok":1}`))
	if err != nil {
		t.Fatalf("SendTrace: %v", err)
	}
	after := time.Now().UnixNano()
	if sentAt < before || sentAt > after {
		t.Errorf("sentAt %d outside [%d,%d]", sentAt, before, after)
	}
	outer, err := ReadFrame(newByteReader(waitForCompleteFrame(t, d)))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if outer.Type != TypeTrace {
		t.Fatalf("outer.Type = %d, want TypeTrace", outer.Type)
	}
	tf, err := ReadTracePayload(outer)
	if err != nil {
		t.Fatalf("ReadTracePayload: %v", err)
	}
	if tf.InnerType != TypeJSON {
		t.Errorf("InnerType = %d, want JSON", tf.InnerType)
	}
	if string(tf.Payload) != `{"ok":1}` {
		t.Errorf("Payload = %q", tf.Payload)
	}
	if tf.SentAtNs != sentAt {
		t.Errorf("SentAtNs = %d, want %d", tf.SentAtNs, sentAt)
	}
	_ = c.Close()
}

// ---- Recv -----------------------------------------------------------------

// TestClient_Recv pushes a full Frame at the driver via cmdRecv and asserts
// Client.Recv decodes it.
func TestClient_Recv(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	// Serialise a TypeText frame and shove it through cmdRecv to connID=0x42
	// (the first ID handed out by the fake daemon).
	body := frameBytes(t, &Frame{Type: TypeText, Payload: []byte("ack 5 bytes")})
	push := make([]byte, 1+4+len(body))
	push[0] = wireCmdRecv
	binary.BigEndian.PutUint32(push[1:5], 0x42)
	copy(push[5:], body)
	d.push(t, push)

	got, err := c.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if got.Type != TypeText {
		t.Errorf("Type = %d, want Text", got.Type)
	}
	if string(got.Payload) != "ack 5 bytes" {
		t.Errorf("Payload = %q", got.Payload)
	}
	_ = c.Close()
}

// TestServer_ListenAndServe_DispatchesIncomingFrame drives Server end-to-end:
// the fake daemon answers cmdBind, pushes one cmdAccept (a new connection),
// then pushes a cmdRecv carrying a serialized Frame. The handler must fire.
// This covers server.go:ListenAndServe (the bind + Accept loop path).
func TestServer_ListenAndServe_DispatchesIncomingFrame(t *testing.T) {
	t.Parallel()
	d := newServerFakeDaemon(t)
	defer d.close()

	drv, err := driver.Connect(d.path)
	if err != nil {
		t.Fatalf("driver.Connect: %v", err)
	}
	defer drv.Close()

	handlerFired := make(chan *Frame, 1)
	srv := NewServer(drv, func(_ net.Conn, f *Frame) {
		handlerFired <- f
	})

	// ListenAndServe blocks; run in a goroutine. It returns when Accept
	// errors (we close the daemon on test teardown to trigger that).
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()

	// Push a cmdAccept for port 1001 carrying a new conn (id=0x77).
	// Wire format: [port:2][connID:4][srcAddr:6][srcPort:2]
	// Driver only reads port from the leading 2 bytes; the rest is
	// the body the daemon would normally put together.
	d.pushAccept(t, protocol.PortDataExchange, 0x77)

	// Now push a cmdRecv carrying a TypeText Frame for connID=0x77.
	payload := frameBytes(t, &Frame{Type: TypeText, Payload: []byte("server-frame")})
	push := make([]byte, 1+4+len(payload))
	push[0] = wireCmdRecv
	binary.BigEndian.PutUint32(push[1:5], 0x77)
	copy(push[5:], payload)
	d.push(t, push)

	select {
	case got := <-handlerFired:
		if got.Type != TypeText {
			t.Errorf("handler got Type=%d, want Text", got.Type)
		}
		if string(got.Payload) != "server-frame" {
			t.Errorf("handler got Payload=%q", got.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not fire")
	case err := <-serveErr:
		t.Fatalf("ListenAndServe returned early: %v", err)
	}
}

// TestClient_Close exercises Close (cmdClose fire-and-forget). The daemon
// captures the close frame, so we can assert it was sent.
func TestClient_Close(t *testing.T) {
	t.Parallel()
	drv, d, c := dialClient(t)
	t.Cleanup(func() { _ = drv.Close(); d.close() })

	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Wait for the cmdClose frame to land in the daemon's capture buffer.
	waitFor(t, time.Second, func() bool {
		for _, f := range d.allSent() {
			if len(f) > 0 && f[0] == wireCmdClose {
				return true
			}
		}
		return false
	}, "cmdClose frame")
}

// ---- helpers --------------------------------------------------------------

// frameBytes serialises a Frame into raw wire bytes for cmdRecv injection.
func frameBytes(t *testing.T, f *Frame) []byte {
	t.Helper()
	bw := &byteWriter{}
	if err := WriteFrame(bw, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	return bw.b
}

// byteWriter is a minimal io.Writer that buffers into an in-memory slice.
type byteWriter struct{ b []byte }

func (w *byteWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

// byteReader is a minimal io.Reader over a byte slice. We avoid bytes.Reader
// only to keep this file dependency-light alongside the rest of the suite.
type byteReader struct {
	b []byte
	i int
}

func newByteReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

// waitForSends polls until d has captured n cmdSend frames or fails.
func waitForSends(t *testing.T, d *fakeDaemon, n int) {
	t.Helper()
	waitFor(t, 2*time.Second, func() bool {
		count := 0
		for _, f := range d.allSent() {
			if len(f) > 0 && f[0] == wireCmdSend {
				count++
			}
		}
		return count >= n
	}, "cmdSend frames")
}

// waitForCompleteFrame polls until reassembleSends(d.allSent()) yields
// enough bytes to decode at least one full data-exchange Frame. The driver
// chops WriteFrame's two writes (header + payload) into separate cmdSend
// IPC messages, so callers can't wait on a fixed cmdSend count — they need
// to wait on the application-level frame boundary.
func waitForCompleteFrame(t *testing.T, d *fakeDaemon) []byte {
	t.Helper()
	var bytesOut []byte
	waitFor(t, 2*time.Second, func() bool {
		bytesOut = reassembleSends(d.allSent())
		if len(bytesOut) < 8 {
			return false
		}
		payloadLen := binary.BigEndian.Uint32(bytesOut[4:8])
		return len(bytesOut) >= int(8+payloadLen)
	}, "complete data-exchange frame")
	return bytesOut
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}
