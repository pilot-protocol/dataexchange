// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// TestNewServer_DriverLessConstructor exercises the constructor with a
// nil driver — the struct is initialized but ListenAndServe will fail
// when invoked.
func TestNewServer_DriverLessConstructor(t *testing.T) {
	t.Parallel()
	called := 0
	s := NewServer(nil, func(net.Conn, *Frame) { called++ })
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.handler == nil {
		t.Error("handler not stashed")
	}
}

// TestServer_HandleConnDispatchesFrames drives Server.handleConn
// directly via a net.Pipe pair, exercising the loop until ReadFrame
// returns an error.
func TestServer_HandleConnDispatchesFrames(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var received []*Frame
	handler := func(_ net.Conn, f *Frame) {
		mu.Lock()
		received = append(received, f)
		mu.Unlock()
	}

	s := &Server{handler: handler}

	// Client writes frames; server-side handleConn reads them.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	doneCh := make(chan struct{})
	go func() {
		s.handleConn(b)
		close(doneCh)
	}()

	// Write two frames then close the writer end → handleConn's
	// ReadFrame returns EOF and the loop exits.
	if err := WriteFrame(a, &Frame{Type: TypeText, Payload: []byte("one")}); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if err := WriteFrame(a, &Frame{Type: TypeJSON, Payload: []byte(`{"k":1}`)}); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	a.Close()

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("handleConn did not exit after client closed")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("received len = %d, want 2", len(received))
	}
	if received[0].Type != TypeText || !bytes.Equal(received[0].Payload, []byte("one")) {
		t.Errorf("frame[0] = %+v", received[0])
	}
	if received[1].Type != TypeJSON {
		t.Errorf("frame[1] type = %d", received[1].Type)
	}
}

// TestServer_HandleConnExitsOnReadError drives the early-return path
// — first read returns an error → handler is never invoked.
func TestServer_HandleConnExitsOnReadError(t *testing.T) {
	t.Parallel()
	called := 0
	s := &Server{handler: func(net.Conn, *Frame) { called++ }}

	a, b := net.Pipe()
	a.Close() // immediately close so ReadFrame on b sees EOF
	defer b.Close()

	doneCh := make(chan struct{})
	go func() {
		s.handleConn(b)
		close(doneCh)
	}()

	select {
	case <-doneCh:
	case <-time.After(time.Second):
		t.Fatal("handleConn did not exit on read error")
	}
	if called != 0 {
		t.Errorf("handler called %d times, want 0", called)
	}
}
