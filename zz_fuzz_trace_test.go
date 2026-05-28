// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/pilot-protocol/dataexchange"
)

// FuzzReadTracePayload exercises the trace-frame inner decoder. The
// caller hands ReadTracePayload a Frame whose Payload is wire-controlled;
// the decoder reads inner_type (4B) + sent_at_ns (8B) and slices the rest.
// Out-of-bounds risks: if the length guard (`< 12`) ever regressed, a
// 0-byte payload would crash. Round-trip via WriteTraceFrame +
// ReadFrame + ReadTracePayload validates encode-decode symmetry.
func FuzzReadTracePayload(f *testing.F) {
	// Seed: valid trace frame.
	{
		var buf bytes.Buffer
		_ = dataexchange.WriteTraceFrame(&buf, &dataexchange.TraceFrame{
			InnerType: dataexchange.TypeText, SentAtNs: 1_700_000_000_000_000_000,
			Payload: []byte("hello"),
		})
		frame, _ := dataexchange.ReadFrame(&buf)
		if frame != nil {
			f.Add(frame.Payload)
		}
	}
	// Seed: minimum valid (12 bytes — empty inner payload).
	f.Add(make([]byte, 12))
	// Seed: zero payload (should error cleanly).
	f.Add([]byte{})
	// Seed: 11 bytes (one byte under the minimum guard).
	f.Add(make([]byte, 11))
	// Seed: large negative SentAtNs (sign-bit set across all 8 bytes).
	{
		buf := make([]byte, 12+4)
		binary.BigEndian.PutUint32(buf[0:4], 0xFFFFFFFF)
		for i := 4; i < 12; i++ {
			buf[i] = 0xFF
		}
		f.Add(buf)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input %x: %v", data, r)
			}
		}()
		fr := &dataexchange.Frame{Type: dataexchange.TypeTrace, Payload: data}
		_, _ = dataexchange.ReadTracePayload(fr)
	})
}

// FuzzWriteThenReadTrace is the round-trip variant: build a TraceFrame
// from random fields, encode via WriteTraceFrame, decode via ReadFrame +
// ReadTracePayload, and assert the recovered fields match.
func FuzzWriteThenReadTrace(f *testing.F) {
	f.Add(uint32(1), int64(0), []byte("hi"))
	f.Add(uint32(2), int64(-1), []byte{})
	f.Add(uint32(0xFFFFFFFF), int64(1<<62), bytes.Repeat([]byte{0xAA}, 64))

	f.Fuzz(func(t *testing.T, innerType uint32, sentAt int64, payload []byte) {
		if len(payload) > 1<<16 {
			return
		}
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panic on input type=%d sentAt=%d payload=%x: %v",
					innerType, sentAt, payload, r)
			}
		}()

		tf := &dataexchange.TraceFrame{
			InnerType: innerType, SentAtNs: sentAt, Payload: payload,
		}
		var buf bytes.Buffer
		if err := dataexchange.WriteTraceFrame(&buf, tf); err != nil {
			t.Errorf("WriteTraceFrame: %v", err)
			return
		}
		frame, err := dataexchange.ReadFrame(&buf)
		if err != nil {
			t.Errorf("ReadFrame: %v", err)
			return
		}
		if frame.Type != dataexchange.TypeTrace {
			t.Errorf("expected TypeTrace, got %d", frame.Type)
			return
		}
		got, err := dataexchange.ReadTracePayload(frame)
		if err != nil {
			t.Errorf("ReadTracePayload: %v", err)
			return
		}
		if got.InnerType != innerType {
			t.Errorf("innerType: %d != %d", got.InnerType, innerType)
		}
		if got.SentAtNs != sentAt {
			t.Errorf("sentAt: %d != %d", got.SentAtNs, sentAt)
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Errorf("payload mismatch")
		}
	})
}
