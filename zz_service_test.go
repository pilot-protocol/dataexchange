// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/protocol"
)

// fakeStream is a coreapi.Stream backed by io.Pipe pairs.
type fakeStream struct {
	r          *io.PipeReader
	w          *io.PipeWriter
	closed     chan struct{}
	closeOnce  sync.Once
}

func newFakeStream(r *io.PipeReader, w *io.PipeWriter) *fakeStream {
	return &fakeStream{r: r, w: w, closed: make(chan struct{})}
}

func (s *fakeStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *fakeStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *fakeStream) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.r.Close()
		_ = s.w.Close()
	})
	return nil
}
func (s *fakeStream) LocalAddr() coreapi.Addr        { return protocol.Addr{} }
func (s *fakeStream) LocalPort() uint16              { return 1001 }
func (s *fakeStream) RemoteAddr() coreapi.Addr       { return protocol.Addr{Node: 0xCAFE} }
func (s *fakeStream) RemotePort() uint16             { return 33000 }
func (s *fakeStream) SetDeadline(time.Time) error    { return nil }
func (s *fakeStream) SetReadDeadline(time.Time) error  { return nil }
func (s *fakeStream) SetWriteDeadline(time.Time) error { return nil }

// fakeListener emits one Stream, then EOFs.
type fakeListener struct {
	stream    coreapi.Stream
	emitted   bool
	mu        sync.Mutex
	closeCh   chan struct{}
	closeOnce sync.Once
}

func newFakeListener(stream coreapi.Stream) *fakeListener {
	return &fakeListener{stream: stream, closeCh: make(chan struct{})}
}

func (l *fakeListener) Accept() (coreapi.Stream, error) {
	l.mu.Lock()
	if !l.emitted {
		l.emitted = true
		s := l.stream
		l.mu.Unlock()
		return s, nil
	}
	l.mu.Unlock()
	<-l.closeCh
	return nil, errors.New("listener closed")
}

func (l *fakeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closeCh) })
	return nil
}

func (l *fakeListener) Addr() coreapi.Addr { return protocol.Addr{} }
func (l *fakeListener) Port() uint16       { return 1001 }

// fakeStreams returns a programmable listener.
type fakeStreams struct {
	listener coreapi.Listener
	listenErr error
}

func (s *fakeStreams) Listen(port uint16) (coreapi.Listener, error) {
	if s.listenErr != nil {
		return nil, s.listenErr
	}
	return s.listener, nil
}
func (s *fakeStreams) Dial(context.Context, coreapi.Addr, uint16) (coreapi.Stream, error) {
	return nil, errors.New("Dial stub")
}
func (s *fakeStreams) SendDatagram(context.Context, coreapi.Addr, uint16, []byte) error {
	return errors.New("SendDatagram stub")
}

func TestService_StartListenError(t *testing.T) {
	t.Parallel()
	s := NewService(ServiceConfig{})
	deps := coreapi.Deps{Streams: &fakeStreams{listenErr: errors.New("listen failed")}}
	if err := s.Start(context.Background(), deps); err == nil {
		t.Error("expected Start to propagate Listen error")
	}
}

// TestService_HandleConn_DispatchesFrames drives Service.handleConn end-to-end
// by feeding a TypeText frame down a pipe and reading the ACK back.
func TestService_HandleConn_DispatchesFrames(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	svc := NewService(ServiceConfig{ReceivedDir: tmp, InboxDir: tmp})

	// Two pipes: clientToServer (we write requests), serverToClient (we read ACKs).
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()

	// The Service treats the conn as a single bidirectional stream.
	// Compose: server reads from c2sR, writes to s2cW.
	serverStream := &fakeStream{r: c2sR, w: s2cW, closed: make(chan struct{})}

	listener := newFakeListener(serverStream)
	streams := &fakeStreams{listener: listener}
	deps := coreapi.Deps{Streams: streams}

	if err := svc.Start(context.Background(), deps); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		_ = svc.Stop(context.Background())
	})

	// Send a TypeText frame.
	frame := &Frame{Type: TypeText, Payload: []byte("hi")}
	if err := WriteFrame(c2sW, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	// Read the ACK frame back.
	ackCh := make(chan *Frame, 1)
	errCh := make(chan error, 1)
	go func() {
		ack, err := ReadFrame(s2cR)
		if err != nil {
			errCh <- err
			return
		}
		ackCh <- ack
	}()

	select {
	case ack := <-ackCh:
		if ack.Type != TypeText {
			t.Errorf("ack.Type = %d, want TypeText", ack.Type)
		}
		if !bytes.Contains(ack.Payload, []byte("ACK")) {
			t.Errorf("ack payload = %q, want contains 'ACK'", ack.Payload)
		}
	case err := <-errCh:
		t.Fatalf("ReadFrame: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ACK")
	}

	// Close the client end so handleConn's ReadFrame returns and the
	// goroutine exits.
	_ = c2sW.Close()
	_ = s2cR.Close()
}
