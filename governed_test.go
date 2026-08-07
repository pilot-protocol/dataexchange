// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/coreapi"
	"github.com/pilot-protocol/common/decision"
)

type governedTestTrust struct {
	intentKey   ed25519.PublicKey
	decisionKey ed25519.PublicKey
}

type noWriteStream struct{ writes bytes.Buffer }

func (stream *noWriteStream) Read([]byte) (int, error) {
	return 0, errors.New("read should not occur before authorization")
}
func (stream *noWriteStream) Write(value []byte) (int, error) {
	return stream.writes.Write(value)
}
func (stream *noWriteStream) Close() error { return nil }

func (trust governedTestTrust) IntentKey(context.Context, string, string, string) (ed25519.PublicKey, error) {
	return trust.intentKey, nil
}

func (trust governedTestTrust) DecisionKey(context.Context, string, string) (ed25519.PublicKey, error) {
	return trust.decisionKey, nil
}

func (governedTestTrust) MinimumState(context.Context, string) (uint64, uint64, error) {
	return 7, 3, nil
}

type governedTestCeiling struct{}

func (governedTestCeiling) Check(context.Context, decision.Intent, decision.Decision) error {
	return nil
}

func (governedTestCeiling) CheckDisclosure(context.Context, decision.Intent, decision.Decision, decision.DisclosureBinding) error {
	return nil
}

type governedReceiptRecorder struct {
	calls    int
	intent   decision.Intent
	decision decision.Decision
	err      error
}

type contentInspectorFunc func(context.Context, decision.Intent, *decision.DisclosureBinding, string, string, io.Reader) error

func (inspect contentInspectorFunc) InspectDisclosureContent(ctx context.Context, intent decision.Intent, disclosure *decision.DisclosureBinding, contentType, filename string, content io.Reader) error {
	return inspect(ctx, intent, disclosure, contentType, filename, content)
}

func TestGovernedContentInspectionIsLocalAndFailClosed(t *testing.T) {
	frame := &Frame{Type: TypeFile, Filename: "invoice.pdf", Payload: []byte("classified invoice")}
	governed, _ := newGovernedTestFrame(t, frame, decision.Allow, nil)
	disclosure := decision.DisclosureBinding{Version: decision.DisclosureBindingVersion, ContentType: "application/pdf", Filename: frame.Filename}
	governed.Disclosure = &disclosure
	var observed []byte
	service := NewService(ServiceConfig{GovernedContentInspector: contentInspectorFunc(func(_ context.Context, intent decision.Intent, got *decision.DisclosureBinding, contentType, filename string, content io.Reader) error {
		if intent.ID != governed.Intent.ID || got == nil || contentType != "application/pdf" || filename != frame.Filename {
			t.Fatalf("inspection metadata intent=%+v disclosure=%+v content_type=%q filename=%q", intent, got, contentType, filename)
		}
		var err error
		observed, err = io.ReadAll(content)
		return err
	})})
	if err := service.inspectGovernedFrame(context.Background(), governed); err != nil || string(observed) != string(frame.Payload) {
		t.Fatalf("inspection err=%v payload=%q", err, observed)
	}
	service.cfg.GovernedContentInspector = contentInspectorFunc(func(context.Context, decision.Intent, *decision.DisclosureBinding, string, string, io.Reader) error {
		return errors.New("detector unavailable")
	})
	if err := service.inspectGovernedFrame(context.Background(), governed); err == nil || err.Error() != "governed content inspection rejected" {
		t.Fatalf("inspection failure leaked or was accepted: %v", err)
	}
	if err := (&Service{cfg: ServiceConfig{RequireGoverned: true, RequireGovernedContentInspection: true}}).validateGovernedConfig(); err == nil || !strings.Contains(err.Error(), "local inspector") {
		t.Fatalf("required inspection without local hook err=%v", err)
	}
}

func TestGovernedTransferQuotaChargesOnlyVerifiedAgentIdentity(t *testing.T) {
	limiter, err := decision.NewTransferQuotaLimiter(decision.TransferQuotaConfig{Window: time.Minute, MaxBytes: 5, MaxSenders: 2})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(ServiceConfig{RequireGoverned: true, GovernedTransferQuota: limiter})
	if err := service.validateGovernedConfig(); err != nil {
		t.Fatal(err)
	}
	if err := service.admitGovernedTransfer(decision.Intent{AgentID: "sender-a"}, 5); err != nil {
		t.Fatal(err)
	}
	if err := service.admitGovernedTransfer(decision.Intent{AgentID: "sender-a"}, 1); err == nil || err.Error() != "governed transfer quota rejected" {
		t.Fatalf("quota error=%v", err)
	}
	if err := (&Service{cfg: ServiceConfig{GovernedTransferQuota: limiter}}).validateGovernedConfig(); err == nil || !strings.Contains(err.Error(), "requires a governed receiver") {
		t.Fatalf("legacy quota configuration error=%v", err)
	}
}

func (recorder *governedReceiptRecorder) RecordGovernedReceipt(_ context.Context, intent decision.Intent, result decision.Decision) error {
	recorder.calls++
	recorder.intent, recorder.decision = intent, result
	return recorder.err
}

type legacyGovernedReceiptRecorder struct{}

func (legacyGovernedReceiptRecorder) RecordGovernedReceipt(context.Context, decision.Intent, decision.Decision) error {
	return nil
}

type disclosureGovernedReceiptRecorder struct {
	governedReceiptRecorder
	disclosure decision.DisclosureBinding
}

func (recorder *disclosureGovernedReceiptRecorder) RecordGovernedDisclosureReceipt(_ context.Context, intent decision.Intent, result decision.Decision, disclosure decision.DisclosureBinding) error {
	recorder.calls++
	recorder.intent, recorder.decision, recorder.disclosure = intent, result, disclosure
	return recorder.err
}

func TestDisclosureReceiptRecorderRequiresV2Evidence(t *testing.T) {
	disclosure := decision.DisclosureBinding{Version: decision.DisclosureBindingVersion}
	if err := recordGovernedReceipt(context.Background(), legacyGovernedReceiptRecorder{}, decision.Intent{ID: "intent"}, decision.Decision{ID: "decision"}, &disclosure); err == nil || !strings.Contains(err.Error(), "does not support disclosure") {
		t.Fatalf("legacy disclosure recorder err=%v", err)
	}
	recorder := &disclosureGovernedReceiptRecorder{}
	if err := recordGovernedReceipt(context.Background(), recorder, decision.Intent{ID: "intent"}, decision.Decision{ID: "decision"}, &disclosure); err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 1 || recorder.disclosure.Version != decision.DisclosureBindingVersion {
		t.Fatalf("disclosure recorder=%+v", recorder)
	}
}

func newGovernedTestFrame(t *testing.T, frame *Frame, outcome decision.Outcome, constraints []decision.Constraint) (GovernedFrame, DecisionFrameVerifier) {
	t.Helper()
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate intent key: %v", err)
	}
	decisionPublic, decisionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate decision key: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "governed-intent", TenantID: "tenant-a", AgentID: "sender-a",
		Action: governedAction(frame.Type), Resource: "agent:receiver/inbox", PayloadHash: GovernedPayloadHash(frame.Type, frame.Filename, frame.Payload),
		Risk: decision.RiskMedium, IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatalf("sign intent: %v", err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatalf("hash intent: %v", err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "governed-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: outcome, Constraints: constraints, PolicyRevision: 7, RevocationEpoch: 3, ProviderID: "authority-a",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * time.Second).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	governed, err := NewGovernedFrame(frame, intent, result)
	if err != nil {
		t.Fatalf("new governed frame: %v", err)
	}
	verifier := DecisionFrameVerifier{
		Enforcer: &decision.Enforcer{
			Trust: governedTestTrust{intentKey: intentPublic, decisionKey: decisionPublic}, Ceiling: governedTestCeiling{}, Now: func() time.Time { return now },
		},
		Resource: func(_ coreapi.Addr, _ *Frame) string { return "agent:receiver/inbox" },
	}
	return governed, verifier
}

func newGovernedStreamForTest(t *testing.T, name string, payload []byte, outcome decision.Outcome, constraints []decision.Constraint) (GovernedStreamInit, DecisionFrameVerifier) {
	t.Helper()
	intentPublic, intentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decisionPublic, decisionPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	fullHash := sha256.Sum256(payload)
	initPayload, err := BuildStreamInitPayload(name, int64(len(payload)), fullHash)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := decision.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "governed-stream-intent", TenantID: "tenant-a", AgentID: "sender-a",
		Action: "file.share", Resource: "agent:receiver/inbox", PayloadHash: GovernedStreamPayloadHash(initPayload),
		Risk: decision.RiskMedium, IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(), Nonce: nonce, KeyID: "sender-key",
	}
	if err := intent.Sign(intentPrivate); err != nil {
		t.Fatal(err)
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "governed-stream-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: outcome, Constraints: constraints, PolicyRevision: 7, RevocationEpoch: 3, ProviderID: "authority-a",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * time.Second).Unix(), KeyID: "authority-key",
	}
	if err := result.Sign(decisionPrivate); err != nil {
		t.Fatal(err)
	}
	stream, err := NewGovernedStreamInit(&Frame{Type: TypeFileStream, Payload: initPayload}, intent, result)
	if err != nil {
		t.Fatal(err)
	}
	verifier := DecisionFrameVerifier{
		Enforcer: &decision.Enforcer{
			Trust: governedTestTrust{intentKey: intentPublic, decisionKey: decisionPublic}, Ceiling: governedTestCeiling{}, Now: func() time.Time { return now },
		},
		Resource: func(_ coreapi.Addr, _ *Frame) string { return "agent:receiver/inbox" },
	}
	return stream, verifier
}

func TestGovernedStreamAuthorizerReceivesExactInitBeforeAnyWrite(t *testing.T) {
	payload := []byte("sensitive export")
	stream := &noWriteStream{}
	var initPayload []byte
	denied := errors.New("policy denied")
	_, err := streamSendWithInit(stream, "export.txt", bytes.NewReader(payload), int64(len(payload)), time.Second, func(id [transferIDLen]byte, size uint64, hash [32]byte, chunkSize uint32, name string) (*Frame, error) {
		init := encodeInit(id, size, hash, chunkSize, name)
		initPayload = append([]byte(nil), init.Payload...)
		return nil, denied
	})
	if !errors.Is(err, denied) {
		t.Fatalf("err=%v, want denied authorization", err)
	}
	if len(stream.writes.Bytes()) != 0 {
		t.Fatalf("authorization rejection wrote %d transport bytes", stream.writes.Len())
	}
	fullHash := sha256.Sum256(payload)
	want, err := BuildStreamInitPayload("export.txt", int64(len(payload)), fullHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(initPayload, want) {
		t.Fatalf("authorizer init does not match governed payload binding")
	}
}

func TestGovernedFrameRoundTripBindsPayloadAndDecision(t *testing.T) {
	frame := &Frame{Type: TypeFile, Filename: "report.pdf", Payload: []byte("approved report")}
	governed, _ := newGovernedTestFrame(t, frame, decision.Allow, nil)
	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		t.Fatalf("encode governed frame: %v", err)
	}
	decoded, err := DecodeGovernedFrame(envelope)
	if err != nil {
		t.Fatalf("decode governed frame: %v", err)
	}
	if got := decoded.DataFrame(); got.Type != frame.Type || got.Filename != frame.Filename || string(got.Payload) != string(frame.Payload) {
		t.Fatalf("decoded data frame = %#v, want %#v", got, frame)
	}

	decoded.Payload = []byte("substituted report")
	tamperedBody, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("marshal tampered frame: %v", err)
	}
	if _, err := DecodeGovernedFrame(&Frame{Type: TypeGoverned, Payload: tamperedBody}); err == nil || !strings.Contains(err.Error(), "payload binding") {
		t.Fatalf("tampered payload error = %v, want payload-binding failure", err)
	}

	invalidName := governed
	invalidName.Filename = string([]byte{0xff})
	if err := invalidName.Validate(); err == nil || !strings.Contains(err.Error(), "invalid governed filename") {
		t.Fatalf("invalid filename error = %v, want UTF-8 validation failure", err)
	}
}

func TestGovernedFrameDisclosureBindingAndRequiredProfile(t *testing.T) {
	frame := &Frame{Type: TypeFile, Filename: "report.json", Payload: []byte(`{"amount":42}`)}
	governed, verifier := newGovernedTestFrame(t, frame, decision.Allow, nil)
	strict := verifier
	strict.RequireDisclosure = true
	if err := strict.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, governed); err == nil || !strings.Contains(err.Error(), "disclosure is required") {
		t.Fatalf("missing disclosure error=%v", err)
	}

	binding := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload(frame.Payload), DeclaredBytes: uint64(len(frame.Payload)),
		ContentType: "application/json", Labels: []string{"finance", "pii"}, Recipient: "agent:finance", Purpose: "invoice-payment", Residency: "eu-west-1", Filename: frame.Filename,
	}
	hash, err := binding.Hash()
	if err != nil {
		t.Fatal(err)
	}
	// Constructing a fresh signed Intent/Decision is covered by the common
	// disclosure tests; this transport test verifies the frame-level mismatch
	// and required-profile checks before receiver-side signature resolution.
	governed.Intent.PayloadHash = hash
	governed.Intent.Audience = binding.Recipient
	governed.Intent.Purpose = binding.Purpose
	governed.Intent.Signature = "transport-test-signature"
	governed.Decision.Signature = "transport-test-signature"
	governed, err = NewGovernedFrameWithDisclosure(frame, governed.Intent, governed.Decision, binding)
	if err != nil {
		t.Fatalf("valid disclosure envelope: %v", err)
	}
	tampered := governed
	tampered.Disclosure = &binding
	tampered.Disclosure.Residency = "us-east-1"
	if err := tampered.Validate(); err == nil || !strings.Contains(err.Error(), "disclosure intent binding") {
		t.Fatalf("disclosure mutation error=%v", err)
	}
}

func TestDecisionFrameVerifierBindsReceiverAndEnforcesConstraints(t *testing.T) {
	frame := &Frame{Type: TypeText, Payload: []byte("hello")}
	governed, verifier := newGovernedTestFrame(t, frame, decision.Constrain, []decision.Constraint{
		{Key: "frame_type", Operator: "eq", Value: "TEXT"},
		{Key: "bytes", Operator: "max", Value: "5"},
	})
	if err := verifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, governed); err != nil {
		t.Fatalf("verify governed frame: %v", err)
	}

	wrongDestination := verifier
	wrongDestination.Resource = func(_ coreapi.Addr, _ *Frame) string { return "agent:other/inbox" }
	if err := wrongDestination.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, governed); err == nil || !strings.Contains(err.Error(), "resource binding") {
		t.Fatalf("wrong destination error = %v, want resource-binding failure", err)
	}

	tooLarge, constrainedVerifier := newGovernedTestFrame(t, &Frame{Type: TypeText, Payload: []byte("too large")}, decision.Constrain, []decision.Constraint{{Key: "bytes", Operator: "max", Value: "3"}})
	if err := constrainedVerifier.VerifyGovernedFrame(context.Background(), coreapi.Addr{}, tooLarge); err == nil || !strings.Contains(err.Error(), "numeric constraint") {
		t.Fatalf("oversize payload error = %v, want constraint failure", err)
	}
}

func TestGovernedStreamInitBindsExactMetadataAndConstraints(t *testing.T) {
	stream, verifier := newGovernedStreamForTest(t, "large.bin", []byte("governed streaming payload"), decision.Constrain, []decision.Constraint{{Key: "bytes", Operator: "max", Value: "32"}})
	envelope, err := EncodeGovernedStreamInit(stream)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGovernedStreamInit(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyGovernedStreamInit(context.Background(), coreapi.Addr{}, decoded); err != nil {
		t.Fatalf("verify governed stream: %v", err)
	}
	tampered := decoded
	tampered.InitPayload[len(tampered.InitPayload)-1] ^= 0x01
	body, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeGovernedStreamInit(&Frame{Type: TypeGovernedFileStream, Payload: body}); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("tampered stream error=%v", err)
	}
	tooLarge, constrainedVerifier := newGovernedStreamForTest(t, "large.bin", bytes.Repeat([]byte("x"), 33), decision.Constrain, []decision.Constraint{{Key: "bytes", Operator: "max", Value: "32"}})
	if err := constrainedVerifier.VerifyGovernedStreamInit(context.Background(), coreapi.Addr{}, tooLarge); err == nil || !strings.Contains(err.Error(), "numeric stream constraint") {
		t.Fatalf("oversize stream constraint error=%v", err)
	}
}

func TestGovernedStreamDisclosureBindingAndRequiredProfile(t *testing.T) {
	stream, verifier := newGovernedStreamForTest(t, "export.txt", []byte("sensitive export"), decision.Allow, nil)
	verifier.RequireDisclosure = true
	if err := verifier.VerifyGovernedStreamInit(context.Background(), coreapi.Addr{}, stream); err == nil || !strings.Contains(err.Error(), "disclosure is required") {
		t.Fatalf("stream without required disclosure err=%v", err)
	}

	payload := []byte("sensitive export")
	fullHash := sha256.Sum256(payload)
	initPayload, err := BuildStreamInitPayload("export.txt", int64(len(payload)), fullHash)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingVersion, ContentHash: decision.HashPayload(payload), DeclaredBytes: uint64(len(payload)),
		ContentType: "text/plain", Labels: []string{"confidential", "pii"}, Recipient: "agent:receiver",
		Purpose: "customer-support", Residency: "eu-west-1", Filename: "export.txt", TransferID: fmt.Sprintf("%x", fullHash[:transferIDLen]),
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		t.Fatal(err)
	}
	intent := decision.Intent{
		Version: decision.SchemaVersion, ID: "governed-stream-disclosure-intent", TenantID: "tenant-a", AgentID: "sender-a",
		Action: "file.share", Resource: "agent:receiver/inbox", Audience: disclosure.Recipient, Purpose: disclosure.Purpose,
		PayloadHash: disclosureHash, Risk: decision.RiskHigh, IssuedAt: 1785500000, ExpiresAt: 1785500060,
		Nonce: strings.Repeat("a", 32), KeyID: "sender-key", Signature: "test-signature",
	}
	intentHash, err := intent.Hash()
	if err != nil {
		t.Fatal(err)
	}
	result := decision.Decision{
		Version: decision.SchemaVersion, ID: "governed-stream-disclosure-decision", IntentHash: intentHash, TenantID: intent.TenantID, AgentID: intent.AgentID,
		Outcome: decision.Allow, PolicyRevision: 7, RevocationEpoch: 3, ProviderID: "authority-a", IssuedAt: 1785500000, ExpiresAt: 1785500060,
		KeyID: "authority-key", Signature: "test-signature",
	}
	governed, err := NewGovernedStreamInitWithDisclosure(&Frame{Type: TypeFileStream, Payload: initPayload}, intent, result, disclosure)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeGovernedStreamInit(governed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeGovernedStreamInit(encoded)
	if err != nil || decoded.Disclosure == nil || decoded.Disclosure.TransferID != disclosure.TransferID {
		t.Fatalf("decode disclosure stream err=%v decoded=%+v", err, decoded)
	}
	decoded.Disclosure.Residency = "us-east-1"
	if err := decoded.Validate(); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("residency mutation accepted: %v", err)
	}
}

func TestRequireGovernedServicePersistsOnlyVerifiedFrames(t *testing.T) {
	tmp := t.TempDir()
	governed, verifier := newGovernedTestFrame(t, &Frame{Type: TypeText, Payload: []byte("approved")}, decision.Allow, nil)
	w, r, wait := makeServiceConn(t, ServiceConfig{InboxDir: tmp, RequireGoverned: true, GovernedVerifier: verifier})
	defer wait()

	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		t.Fatalf("encode governed frame: %v", err)
	}
	if err := WriteFrame(w, envelope); err != nil {
		t.Fatalf("write governed frame: %v", err)
	}
	ack, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("read governed ack: %v", err)
	}
	if !strings.Contains(string(ack.Payload), "ACK TEXT 8 bytes") {
		t.Fatalf("governed ack = %q", ack.Payload)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil || len(entries) != 1 {
		t.Fatalf("inbox after governed delivery: entries=%d err=%v", len(entries), err)
	}

	if err := WriteFrame(w, &Frame{Type: TypeText, Payload: []byte("unsigned")}); err != nil {
		t.Fatalf("write unsigned frame: %v", err)
	}
	ack, err = ReadFrame(r)
	if err != nil {
		t.Fatalf("read unsigned ack: %v", err)
	}
	if !strings.Contains(string(ack.Payload), "ERR TEXT save failed: unsigned legacy frame rejected") {
		t.Fatalf("unsigned ack = %q", ack.Payload)
	}
	entries, err = os.ReadDir(tmp)
	if err != nil || len(entries) != 1 {
		t.Fatalf("unsigned delivery changed inbox: entries=%d err=%v", len(entries), err)
	}
}

func TestGovernedReceiptIsRequiredBeforeDeliveryAcknowledgement(t *testing.T) {
	governed, verifier := newGovernedTestFrame(t, &Frame{Type: TypeText, Payload: []byte("approved")}, decision.Allow, nil)
	envelope, err := EncodeGovernedFrame(governed)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &governedReceiptRecorder{}
	directory := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{
		InboxDir: directory, RequireGoverned: true, GovernedVerifier: verifier,
		RequireGovernedReceipts: true, GovernedReceiptRecorder: recorder,
	})
	defer wait()
	if err := WriteFrame(w, envelope); err != nil {
		t.Fatal(err)
	}
	ack, err := ReadFrame(r)
	if err != nil || !strings.Contains(string(ack.Payload), "ACK TEXT 8 bytes") {
		t.Fatalf("receipt-backed acknowledgement=%q err=%v", ack.Payload, err)
	}
	if recorder.calls != 1 || recorder.intent.ID != governed.Intent.ID || recorder.decision.ID != governed.Decision.ID {
		t.Fatalf("receipt recorder=%+v", recorder)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("receipt-backed delivery entries=%d err=%v", len(entries), err)
	}

	failingDirectory := t.TempDir()
	failing := &governedReceiptRecorder{err: os.ErrPermission}
	w, r, wait = makeServiceConn(t, ServiceConfig{
		InboxDir: failingDirectory, RequireGoverned: true, GovernedVerifier: verifier,
		RequireGovernedReceipts: true, GovernedReceiptRecorder: failing,
	})
	defer wait()
	if err := WriteFrame(w, envelope); err != nil {
		t.Fatal(err)
	}
	ack, err = ReadFrame(r)
	if err != nil || !strings.Contains(string(ack.Payload), "record governed delivery receipt") {
		t.Fatalf("receipt failure acknowledgement=%q err=%v", ack.Payload, err)
	}
	entries, err = os.ReadDir(failingDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unreceipted delivery remained on disk: entries=%d err=%v", len(entries), err)
	}
}

func TestGovernedStreamRequiresReceiptBeforeComplete(t *testing.T) {
	payload := []byte("a governed resumable file")
	stream, verifier := newGovernedStreamForTest(t, "report.bin", payload, decision.Allow, nil)
	envelope, err := EncodeGovernedStreamInit(stream)
	if err != nil {
		t.Fatal(err)
	}
	id, err := stream.TransferID()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &governedReceiptRecorder{}
	directory := t.TempDir()
	w, r, wait := makeServiceConn(t, ServiceConfig{
		ReceivedDir: directory, RequireGoverned: true, GovernedVerifier: verifier, GovernedStreamVerifier: verifier,
		RequireGovernedReceipts: true, GovernedReceiptRecorder: recorder,
	})
	defer wait()
	if err := WriteFrame(w, envelope); err != nil {
		t.Fatal(err)
	}
	initAck, err := ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	kind, gotID, _, ok := decodeStreamFrame(initAck)
	if !ok || kind != streamKindInitAck || gotID != id {
		t.Fatalf("governed stream init response=%#v", initAck)
	}
	if err := WriteFrame(w, encodeChunk(id, 0, payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(w, encodeStreamFrame(streamKindDone, id, nil)); err != nil {
		t.Fatal(err)
	}
	complete, err := ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	kind, _, body, ok := decodeStreamFrame(complete)
	completeOK, message := decodeComplete(body)
	if !ok || kind != streamKindComplete || !completeOK || message != "" {
		t.Fatalf("governed stream completion=%#v ok=%v message=%q", complete, completeOK, message)
	}
	if recorder.calls != 1 || recorder.intent.ID != stream.Intent.ID || recorder.decision.ID != stream.Decision.ID {
		t.Fatalf("stream receipt recorder=%+v", recorder)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var saved string
	for _, entry := range entries {
		if !entry.IsDir() {
			saved = entry.Name()
		}
	}
	contents, err := os.ReadFile(filepath.Join(directory, saved))
	if err != nil || string(contents) != string(payload) {
		t.Fatalf("saved governed stream contents=%q err=%v", contents, err)
	}

	failingDirectory := t.TempDir()
	w, r, wait = makeServiceConn(t, ServiceConfig{
		ReceivedDir: failingDirectory, RequireGoverned: true, GovernedVerifier: verifier, GovernedStreamVerifier: verifier,
		RequireGovernedReceipts: true, GovernedReceiptRecorder: &governedReceiptRecorder{err: os.ErrPermission},
	})
	defer wait()
	if err := WriteFrame(w, envelope); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(w, encodeChunk(id, 0, payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(r); err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(w, encodeStreamFrame(streamKindDone, id, nil)); err != nil {
		t.Fatal(err)
	}
	complete, err = ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	kind, _, body, ok = decodeStreamFrame(complete)
	completeOK, message = decodeComplete(body)
	if !ok || kind != streamKindComplete || completeOK || !strings.Contains(message, "record governed stream receipt") {
		t.Fatalf("receipt-failed stream completion=%#v ok=%v message=%q", complete, completeOK, message)
	}
	entries, err = os.ReadDir(failingDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			t.Fatalf("unreceipted stream file remained: %s", entry.Name())
		}
	}

	rawDirectory := t.TempDir()
	w, r, wait = makeServiceConn(t, ServiceConfig{
		ReceivedDir: rawDirectory, RequireGoverned: true, GovernedVerifier: verifier, GovernedStreamVerifier: verifier,
		RequireGovernedReceipts: true, GovernedReceiptRecorder: &governedReceiptRecorder{},
	})
	defer wait()
	if err := WriteFrame(w, stream.InitFrame()); err != nil {
		t.Fatal(err)
	}
	rejected, err := ReadFrame(r)
	if err != nil {
		t.Fatal(err)
	}
	kind, _, body, ok = decodeStreamFrame(rejected)
	completeOK, message = decodeComplete(body)
	if !ok || kind != streamKindComplete || completeOK || !strings.Contains(message, "unsigned stream frame") {
		t.Fatalf("raw stream rejection=%#v ok=%v message=%q", rejected, completeOK, message)
	}
}

func TestGovernedReceiptRequirementFailsStartupWithoutRecorder(t *testing.T) {
	service := NewService(ServiceConfig{RequireGoverned: true, RequireGovernedReceipts: true})
	if err := service.Start(context.Background(), coreapi.Deps{}); err == nil || !strings.Contains(err.Error(), "receipt recorder") {
		t.Fatalf("start error=%v, want missing receipt recorder", err)
	}
}

var _ decision.TrustStore = governedTestTrust{}
var _ decision.AuthorityCeiling = governedTestCeiling{}
var _ GovernedReceiptRecorder = (*governedReceiptRecorder)(nil)
