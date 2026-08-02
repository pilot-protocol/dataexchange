// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
)

const governedFrameVersion uint16 = 1

// GovernedFrame transports an ordinary data frame with the exact signed
// authorization evidence for that frame. PayloadHash is computed over frame
// type, filename, and bytes, so a decision for text cannot be replayed as a
// file or against different contents.
type GovernedFrame struct {
	Version    uint16                      `json:"version"`
	Type       uint32                      `json:"type"`
	Filename   string                      `json:"filename,omitempty"`
	Payload    []byte                      `json:"payload"`
	Disclosure *decision.DisclosureBinding `json:"disclosure,omitempty"`
	Intent     decision.Intent             `json:"intent"`
	Decision   decision.Decision           `json:"decision"`
}

// GovernedFrameVerifier maps a trusted transport peer and governed frame into
// a local enforcement decision. The service invokes it before any disk write.
type GovernedFrameVerifier interface {
	VerifyGovernedFrame(context.Context, coreapi.Addr, GovernedFrame) error
}

// GovernedReceiptRecorder durably records a receiver-side enforcement receipt
// for a verified governed delivery. It receives the exact signed objects that
// authorized the data frame; implementations must fail closed on a recording
// error when their deployment requires evidence before acknowledgement.
type GovernedReceiptRecorder interface {
	RecordGovernedReceipt(context.Context, decision.Intent, decision.Decision) error
}

// GovernedDisclosureReceiptRecorder is the evidence extension for a
// disclosure-bound transport. A configured recorder must implement this when
// it receives typed metadata: silently emitting a V1 receipt would lose the
// evidence a required disclosure profile relies on.
type GovernedDisclosureReceiptRecorder interface {
	RecordGovernedDisclosureReceipt(context.Context, decision.Intent, decision.Decision, decision.DisclosureBinding) error
}

func recordGovernedReceipt(ctx context.Context, recorder GovernedReceiptRecorder, intent decision.Intent, result decision.Decision, disclosure *decision.DisclosureBinding) error {
	if recorder == nil {
		return fmt.Errorf("dataexchange: governed receipt recorder is not configured")
	}
	if disclosure == nil {
		return recorder.RecordGovernedReceipt(ctx, intent, result)
	}
	typed, supported := recorder.(GovernedDisclosureReceiptRecorder)
	if !supported {
		return fmt.Errorf("dataexchange: governed receipt recorder does not support disclosure evidence")
	}
	return typed.RecordGovernedDisclosureReceipt(ctx, intent, result, *disclosure)
}

// DecisionFrameVerifier is the reference receiver-side verifier. Resource
// must return the exact local resource identifier expected for this incoming
// frame (for example, "agent:finance/inbox"). This prevents a sender from
// reusing a valid decision for a different local destination.
type DecisionFrameVerifier struct {
	Enforcer          *decision.Enforcer
	Resource          func(coreapi.Addr, *Frame) string
	RequireDisclosure bool
}

func NewGovernedFrame(frame *Frame, intent decision.Intent, result decision.Decision) (GovernedFrame, error) {
	if frame == nil {
		return GovernedFrame{}, fmt.Errorf("dataexchange: governed frame is required")
	}
	governed := GovernedFrame{
		Version: governedFrameVersion, Type: frame.Type, Filename: frame.Filename,
		Payload: append([]byte(nil), frame.Payload...), Intent: intent, Decision: result,
	}
	if err := governed.Validate(); err != nil {
		return GovernedFrame{}, err
	}
	return governed, nil
}

// NewGovernedFrameWithDisclosure creates a governed frame whose Intent binds
// a canonical disclosure metadata object. The caller must obtain the Decision
// for the disclosure-bound Intent; this constructor never changes authority.
func NewGovernedFrameWithDisclosure(frame *Frame, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding) (GovernedFrame, error) {
	if frame == nil {
		return GovernedFrame{}, fmt.Errorf("dataexchange: governed frame is required")
	}
	disclosure.Labels = append([]string(nil), disclosure.Labels...)
	governed := GovernedFrame{
		Version: governedFrameVersion, Type: frame.Type, Filename: frame.Filename,
		Payload: append([]byte(nil), frame.Payload...), Disclosure: &disclosure, Intent: intent, Decision: result,
	}
	if err := governed.Validate(); err != nil {
		return GovernedFrame{}, err
	}
	return governed, nil
}

func (frame GovernedFrame) Validate() error {
	if frame.Version != governedFrameVersion || !governedDataType(frame.Type) {
		return fmt.Errorf("dataexchange: invalid governed frame type")
	}
	if frame.Type == TypeFile {
		if !validGovernedFilename(frame.Filename) {
			return fmt.Errorf("dataexchange: invalid governed filename")
		}
	} else if frame.Filename != "" {
		return fmt.Errorf("dataexchange: filename is only valid for file frames")
	}
	if uint64(len(frame.Payload)) > uint64(MaxFrameSize) {
		return fmt.Errorf("dataexchange: governed payload exceeds maximum frame size")
	}
	if err := frame.Intent.Validate(); err != nil {
		return fmt.Errorf("dataexchange: invalid governed intent: %w", err)
	}
	if frame.Intent.Signature == "" || frame.Decision.Signature == "" {
		return fmt.Errorf("dataexchange: governed intent and decision must be signed")
	}
	if frame.Intent.Action != GovernedAction(frame.Type) {
		return fmt.Errorf("dataexchange: governed intent action does not match frame type")
	}
	if err := frame.verifyPayloadBinding(); err != nil {
		return err
	}
	if err := frame.Decision.Validate(); err != nil {
		return fmt.Errorf("dataexchange: invalid governed decision: %w", err)
	}
	return nil
}

func (frame GovernedFrame) verifyPayloadBinding() error {
	if frame.Disclosure == nil {
		if frame.Intent.PayloadHash != GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload) {
			return fmt.Errorf("dataexchange: governed intent payload binding mismatch")
		}
		return nil
	}
	if frame.Disclosure.ContentHash != decision.HashPayload(frame.Payload) || frame.Disclosure.DeclaredBytes != uint64(len(frame.Payload)) || frame.Disclosure.Filename != frame.Filename || frame.Disclosure.TransferID != "" {
		return fmt.Errorf("dataexchange: governed disclosure does not match frame")
	}
	if err := frame.Disclosure.VerifyIntent(frame.Intent); err != nil {
		return fmt.Errorf("dataexchange: governed disclosure intent binding: %w", err)
	}
	return nil
}

func (frame GovernedFrame) DataFrame() *Frame {
	return &Frame{Type: frame.Type, Filename: frame.Filename, Payload: append([]byte(nil), frame.Payload...)}
}

func EncodeGovernedFrame(frame GovernedFrame) (*Frame, error) {
	if err := frame.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("dataexchange: encode governed frame: %w", err)
	}
	if uint64(len(body)) > uint64(MaxFrameSize) {
		return nil, fmt.Errorf("dataexchange: governed envelope exceeds maximum frame size")
	}
	return &Frame{Type: TypeGoverned, Payload: body}, nil
}

func DecodeGovernedFrame(frame *Frame) (GovernedFrame, error) {
	if frame == nil || frame.Type != TypeGoverned || uint64(len(frame.Payload)) > uint64(MaxFrameSize) {
		return GovernedFrame{}, fmt.Errorf("dataexchange: invalid governed envelope")
	}
	decoder := json.NewDecoder(bytes.NewReader(frame.Payload))
	decoder.DisallowUnknownFields()
	var governed GovernedFrame
	if err := decoder.Decode(&governed); err != nil {
		return GovernedFrame{}, fmt.Errorf("dataexchange: decode governed envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return GovernedFrame{}, fmt.Errorf("dataexchange: trailing governed envelope data")
	}
	if err := governed.Validate(); err != nil {
		return GovernedFrame{}, err
	}
	return governed, nil
}

func (verifier DecisionFrameVerifier) VerifyGovernedFrame(ctx context.Context, remote coreapi.Addr, governed GovernedFrame) error {
	if verifier.Enforcer == nil || verifier.Resource == nil {
		return fmt.Errorf("dataexchange: decision frame verifier is not initialized")
	}
	if err := governed.Validate(); err != nil {
		return err
	}
	if verifier.RequireDisclosure && governed.Disclosure == nil {
		return fmt.Errorf("dataexchange: governed disclosure is required")
	}
	frame := governed.DataFrame()
	resource := verifier.Resource(remote, frame)
	if resource == "" || governed.Intent.Resource != resource {
		return fmt.Errorf("dataexchange: governed intent resource binding mismatch")
	}
	var verifyErr error
	if governed.Disclosure != nil {
		verifyErr = verifier.Enforcer.VerifyDisclosure(ctx, governed.Intent, governed.Decision, *governed.Disclosure)
	} else {
		verifyErr = verifier.Enforcer.Verify(ctx, governed.Intent, governed.Decision)
	}
	if verifyErr != nil {
		return fmt.Errorf("dataexchange: verify governed decision: %w", verifyErr)
	}
	switch governed.Decision.Outcome {
	case decision.Allow:
		return nil
	case decision.Constrain:
		return enforceFrameConstraints(governed.Decision.Constraints, remote, frame)
	default:
		return fmt.Errorf("dataexchange: governed decision outcome %q cannot permit delivery", governed.Decision.Outcome)
	}
}

// GovernedAction returns the only signed Intent action that can authorize a
// regular governed data frame of frameType. An empty result means the type is
// not eligible for a governed envelope.
func GovernedAction(frameType uint32) string {
	switch frameType {
	case TypeText:
		return "data.send.text"
	case TypeJSON:
		return "data.send.json"
	case TypeBinary:
		return "data.send.binary"
	case TypeFile:
		return "file.share"
	default:
		return ""
	}
}

func governedAction(frameType uint32) string { return GovernedAction(frameType) }

func governedDataType(frameType uint32) bool { return GovernedAction(frameType) != "" }

// GovernedPayloadHash returns the exact payload binding required by a
// TypeGoverned Intent. It includes the frame kind and filename as well as the
// bytes, so callers must use it when creating the Intent before SendGoverned.
func GovernedPayloadHash(frameType uint32, filename string, payload []byte) string {
	var header [12]byte
	binary.BigEndian.PutUint32(header[:4], frameType)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(filename)))
	binary.BigEndian.PutUint32(header[8:12], uint32(len(payload)))
	hash := sha256.New()
	_, _ = hash.Write([]byte("pilot-dataexchange-governed-frame-v1\x00"))
	_, _ = hash.Write(header[:])
	_, _ = hash.Write([]byte(filename))
	_, _ = hash.Write(payload)
	return decision.HashPayload(hash.Sum(nil))
}

func validGovernedFilename(name string) bool {
	return name != "" && utf8.ValidString(name) && len(name) <= maxFilenameLen && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\")
}

func enforceFrameConstraints(constraints []decision.Constraint, remote coreapi.Addr, frame *Frame) error {
	attributes := map[string]string{
		"sender": remote.String(), "frame_type": TypeName(frame.Type), "bytes": strconv.Itoa(len(frame.Payload)), "filename": frame.Filename,
	}
	for _, constraint := range constraints {
		actual, found := attributes[constraint.Key]
		if !found {
			return fmt.Errorf("dataexchange: constraint %q has no enforceable frame attribute", constraint.Key)
		}
		switch constraint.Operator {
		case "eq":
			if actual != constraint.Value {
				return fmt.Errorf("dataexchange: constraint %s rejected", constraint.Key)
			}
		case "one_of":
			matched := false
			for _, allowed := range strings.Split(constraint.Value, ",") {
				if actual == strings.TrimSpace(allowed) {
					matched = true
					break
				}
			}
			if !matched {
				return fmt.Errorf("dataexchange: constraint %s rejected", constraint.Key)
			}
		case "max", "min":
			value, valueErr := strconv.ParseUint(actual, 10, 64)
			limit, limitErr := strconv.ParseUint(constraint.Value, 10, 64)
			if valueErr != nil || limitErr != nil || (constraint.Operator == "max" && value > limit) || (constraint.Operator == "min" && value < limit) {
				return fmt.Errorf("dataexchange: numeric constraint %s rejected", constraint.Key)
			}
		case "require":
			if constraint.Value != "" && actual != constraint.Value {
				return fmt.Errorf("dataexchange: required constraint %s rejected", constraint.Key)
			}
		default:
			return fmt.Errorf("dataexchange: constraint operator %q is not enforceable", constraint.Operator)
		}
	}
	return nil
}
