// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
)

const governedStreamVersion uint16 = 1

// GovernedStreamInit binds a signed authority decision to the exact INIT
// frame for a resumable file stream. The INIT includes the full file hash,
// filename, declared length, and transfer ID; individual chunks are accepted
// only after this envelope has been verified locally.
type GovernedStreamInit struct {
	Version     uint16                      `json:"version"`
	InitPayload []byte                      `json:"init_payload"`
	Disclosure  *decision.DisclosureBinding `json:"disclosure,omitempty"`
	Intent      decision.Intent             `json:"intent"`
	Decision    decision.Decision           `json:"decision"`
}

// GovernedStreamVerifier verifies a stream INIT before the receiver creates a
// partial file. It is intentionally distinct from GovernedFrameVerifier so
// embedders that do not support large files need not accidentally authorize
// them.
type GovernedStreamVerifier interface {
	VerifyGovernedStreamInit(context.Context, coreapi.Addr, GovernedStreamInit) error
}

func NewGovernedStreamInit(init *Frame, intent decision.Intent, result decision.Decision) (GovernedStreamInit, error) {
	if init == nil || init.Type != TypeFileStream {
		return GovernedStreamInit{}, fmt.Errorf("dataexchange: stream INIT frame is required")
	}
	governed := GovernedStreamInit{
		Version: governedStreamVersion, InitPayload: append([]byte(nil), init.Payload...), Intent: intent, Decision: result,
	}
	if err := governed.Validate(); err != nil {
		return GovernedStreamInit{}, err
	}
	return governed, nil
}

// NewGovernedStreamInitWithDisclosure creates a governed resumable transfer
// whose signed Intent binds typed metadata as well as the content hash,
// filename, declared bytes, and stable transfer ID in its INIT frame.
func NewGovernedStreamInitWithDisclosure(init *Frame, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding) (GovernedStreamInit, error) {
	if init == nil || init.Type != TypeFileStream {
		return GovernedStreamInit{}, fmt.Errorf("dataexchange: stream INIT frame is required")
	}
	disclosure.Labels = append([]string(nil), disclosure.Labels...)
	governed := GovernedStreamInit{
		Version: governedStreamVersion, InitPayload: append([]byte(nil), init.Payload...), Disclosure: &disclosure, Intent: intent, Decision: result,
	}
	if err := governed.Validate(); err != nil {
		return GovernedStreamInit{}, err
	}
	return governed, nil
}

func (stream GovernedStreamInit) Validate() error {
	if stream.Version != governedStreamVersion || len(stream.InitPayload) == 0 || uint64(len(stream.InitPayload)) > uint64(MaxFrameSize) {
		return fmt.Errorf("dataexchange: invalid governed stream INIT")
	}
	_, id, body, ok := decodeStreamFrame(&Frame{Type: TypeFileStream, Payload: stream.InitPayload})
	if !ok || stream.InitPayload[0] != streamKindInit {
		return fmt.Errorf("dataexchange: governed stream must contain a file-stream INIT")
	}
	size, hash, chunkSize, name, valid := decodeInit(body)
	if !valid || !validGovernedFilename(name) || chunkSize == 0 || size > uint64(^uint64(0)>>1) {
		return fmt.Errorf("dataexchange: invalid governed stream metadata")
	}
	if !bytes.Equal(id[:], hash[:transferIDLen]) {
		return fmt.Errorf("dataexchange: governed stream transfer ID does not match content hash")
	}
	if err := stream.Intent.Validate(); err != nil {
		return fmt.Errorf("dataexchange: invalid governed stream intent: %w", err)
	}
	if stream.Intent.Signature == "" || stream.Decision.Signature == "" {
		return fmt.Errorf("dataexchange: governed stream intent and decision must be signed")
	}
	if stream.Intent.Action != "file.share" {
		return fmt.Errorf("dataexchange: governed stream intent action mismatch")
	}
	if stream.Disclosure == nil && stream.Intent.PayloadHash != GovernedStreamPayloadHash(stream.InitPayload) {
		return fmt.Errorf("dataexchange: governed stream intent binding mismatch")
	}
	if stream.Disclosure != nil {
		if stream.Disclosure.ContentHash != hex.EncodeToString(hash[:]) || stream.Disclosure.DeclaredBytes != size || stream.Disclosure.Filename != name || stream.Disclosure.TransferID != hex.EncodeToString(id[:]) {
			return fmt.Errorf("dataexchange: governed stream disclosure does not match INIT")
		}
		if err := stream.Disclosure.VerifyIntent(stream.Intent); err != nil {
			return fmt.Errorf("dataexchange: governed stream disclosure intent binding: %w", err)
		}
	}
	if err := stream.Decision.Validate(); err != nil {
		return fmt.Errorf("dataexchange: invalid governed stream decision: %w", err)
	}
	return nil
}

func (stream GovernedStreamInit) InitFrame() *Frame {
	return &Frame{Type: TypeFileStream, Payload: append([]byte(nil), stream.InitPayload...)}
}

func (stream GovernedStreamInit) TransferID() ([transferIDLen]byte, error) {
	_, id, _, ok := decodeStreamFrame(stream.InitFrame())
	if !ok {
		return [transferIDLen]byte{}, fmt.Errorf("dataexchange: invalid governed stream transfer ID")
	}
	return id, nil
}

// DeclaredBytes returns the signed stream length from its verified INIT. It is
// used by receiver-local admission controls before any stream chunks are
// accepted.
func (stream GovernedStreamInit) DeclaredBytes() (uint64, error) {
	if err := stream.Validate(); err != nil {
		return 0, err
	}
	_, _, body, ok := decodeStreamFrame(stream.InitFrame())
	if !ok {
		return 0, fmt.Errorf("dataexchange: invalid governed stream INIT")
	}
	size, _, _, _, valid := decodeInit(body)
	if !valid {
		return 0, fmt.Errorf("dataexchange: invalid governed stream metadata")
	}
	return size, nil
}

func EncodeGovernedStreamInit(stream GovernedStreamInit) (*Frame, error) {
	if err := stream.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(stream)
	if err != nil {
		return nil, fmt.Errorf("dataexchange: encode governed stream: %w", err)
	}
	if uint64(len(body)) > uint64(MaxFrameSize) {
		return nil, fmt.Errorf("dataexchange: governed stream envelope exceeds maximum frame size")
	}
	return &Frame{Type: TypeGovernedFileStream, Payload: body}, nil
}

func DecodeGovernedStreamInit(frame *Frame) (GovernedStreamInit, error) {
	if frame == nil || frame.Type != TypeGovernedFileStream || uint64(len(frame.Payload)) > uint64(MaxFrameSize) {
		return GovernedStreamInit{}, fmt.Errorf("dataexchange: invalid governed stream envelope")
	}
	decoder := json.NewDecoder(bytes.NewReader(frame.Payload))
	decoder.DisallowUnknownFields()
	var stream GovernedStreamInit
	if err := decoder.Decode(&stream); err != nil {
		return GovernedStreamInit{}, fmt.Errorf("dataexchange: decode governed stream envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return GovernedStreamInit{}, fmt.Errorf("dataexchange: trailing governed stream envelope data")
	}
	if err := stream.Validate(); err != nil {
		return GovernedStreamInit{}, err
	}
	return stream, nil
}

// GovernedStreamPayloadHash binds the exact bytes of the file-stream INIT
// frame. It therefore covers the filename, size, full content hash, chunk
// size, and transfer ID without having to duplicate the stream wire grammar.
func GovernedStreamPayloadHash(initPayload []byte) string {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(initPayload)))
	buffer := make([]byte, 0, len("pilot-dataexchange-governed-stream-v1\x00")+len(length)+len(initPayload))
	buffer = append(buffer, []byte("pilot-dataexchange-governed-stream-v1\x00")...)
	buffer = append(buffer, length[:]...)
	buffer = append(buffer, initPayload...)
	return decision.HashPayload(buffer)
}

// GovernedStreamDisclosureMetadata returns the canonical values a hosted
// federation disclosure must bind for an already-built stream INIT.
func GovernedStreamDisclosureMetadata(initPayload []byte) (transferID string, declaredBytes uint64, contentHash string, filename string, err error) {
	_, id, body, ok := decodeStreamFrame(&Frame{Type: TypeFileStream, Payload: initPayload})
	if !ok || len(initPayload) == 0 || initPayload[0] != streamKindInit {
		err = fmt.Errorf("dataexchange: invalid file-stream INIT")
		return
	}
	size, hash, _, name, valid := decodeInit(body)
	if !valid || !validGovernedFilename(name) || !bytes.Equal(id[:], hash[:transferIDLen]) {
		err = fmt.Errorf("dataexchange: invalid file-stream disclosure metadata")
		return
	}
	return hex.EncodeToString(id[:]), size, hex.EncodeToString(hash[:]), name, nil
}

func (verifier DecisionFrameVerifier) VerifyGovernedStreamInit(ctx context.Context, remote coreapi.Addr, stream GovernedStreamInit) error {
	if verifier.Enforcer == nil || verifier.Resource == nil {
		return fmt.Errorf("dataexchange: decision stream verifier is not initialized")
	}
	if err := stream.Validate(); err != nil {
		return err
	}
	if verifier.RequireDisclosure && stream.Disclosure == nil {
		return fmt.Errorf("dataexchange: governed stream disclosure is required")
	}
	init := stream.InitFrame()
	_, _, body, _ := decodeStreamFrame(init)
	size, _, _, name, _ := decodeInit(body)
	resourceFrame := &Frame{Type: TypeFileStream, Filename: name}
	resource := verifier.Resource(remote, resourceFrame)
	if resource == "" || stream.Intent.Resource != resource {
		return fmt.Errorf("dataexchange: governed stream intent resource binding mismatch")
	}
	var verifyErr error
	if stream.Disclosure != nil {
		verifyErr = verifier.Enforcer.VerifyDisclosure(ctx, stream.Intent, stream.Decision, *stream.Disclosure)
	} else {
		verifyErr = verifier.Enforcer.Verify(ctx, stream.Intent, stream.Decision)
	}
	if verifyErr != nil {
		return fmt.Errorf("dataexchange: verify governed stream decision: %w", verifyErr)
	}
	switch stream.Decision.Outcome {
	case decision.Allow:
		return nil
	case decision.Constrain:
		return enforceStreamConstraints(stream.Decision.Constraints, remote, name, size)
	default:
		return fmt.Errorf("dataexchange: governed stream decision outcome %q cannot permit delivery", stream.Decision.Outcome)
	}
}

func enforceStreamConstraints(constraints []decision.Constraint, remote coreapi.Addr, filename string, size uint64) error {
	attributes := map[string]string{
		"sender": remote.String(), "frame_type": TypeName(TypeFileStream), "bytes": strconv.FormatUint(size, 10), "filename": filename,
	}
	for _, constraint := range constraints {
		actual, found := attributes[constraint.Key]
		if !found {
			return fmt.Errorf("dataexchange: constraint %q has no enforceable stream attribute", constraint.Key)
		}
		switch constraint.Operator {
		case "eq":
			if actual != constraint.Value {
				return fmt.Errorf("dataexchange: stream constraint %s rejected", constraint.Key)
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
				return fmt.Errorf("dataexchange: stream constraint %s rejected", constraint.Key)
			}
		case "max", "min":
			value, valueErr := strconv.ParseUint(actual, 10, 64)
			limit, limitErr := strconv.ParseUint(constraint.Value, 10, 64)
			if valueErr != nil || limitErr != nil || (constraint.Operator == "max" && value > limit) || (constraint.Operator == "min" && value < limit) {
				return fmt.Errorf("dataexchange: numeric stream constraint %s rejected", constraint.Key)
			}
		case "require":
			if constraint.Value != "" && actual != constraint.Value {
				return fmt.Errorf("dataexchange: required stream constraint %s rejected", constraint.Key)
			}
		default:
			return fmt.Errorf("dataexchange: constraint operator %q is not enforceable for a stream", constraint.Operator)
		}
	}
	return nil
}

var _ GovernedStreamVerifier = DecisionFrameVerifier{}
