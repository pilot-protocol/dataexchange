// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !no_dataexchange
// +build !no_dataexchange

package dataexchange

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/protocol"
)

func TestGovernedRetentionManagerDurablyExpiresOnlyManagedContent(t *testing.T) {
	root := t.TempDir()
	inbox := filepath.Join(root, "inbox")
	received := filepath.Join(root, "received")
	state := filepath.Join(root, "retention")
	if err := os.MkdirAll(inbox, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(received, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(inbox, "message.json")
	if err := os.WriteFile(path, []byte("classified"), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1785500000, 0).UTC()
	manager, err := newGovernedRetentionManager(state, map[string]string{"inbox": inbox, "received": received}, []GovernedRetentionPolicy{{Class: "finance-7y", RetainFor: time.Second}}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	disclosure := decision.DisclosureBinding{
		Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload([]byte("classified")), DeclaredBytes: 10,
		ContentType: "application/json", Labels: []string{"finance"}, Recipient: "agent:finance", Purpose: "inbox-delivery", Residency: "eu-west-1", RetentionClass: "finance-7y",
	}
	ticket, err := manager.prepare(&disclosure, path)
	if err != nil || ticket.entryPath == "" {
		t.Fatalf("prepare ticket=%+v err=%v", ticket, err)
	}
	if err := manager.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("content deleted before expiry: %v", err)
	}
	now = now.Add(time.Second)
	if err := manager.Sweep(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired content remained: %v", err)
	}
	if _, err := os.Stat(ticket.entryPath); !os.IsNotExist(err) {
		t.Fatalf("expired journal remained: %v", err)
	}
}

func TestGovernedRetentionManagerRejectsUnknownClassAndEscape(t *testing.T) {
	root := t.TempDir()
	inbox := filepath.Join(root, "inbox")
	if err := os.MkdirAll(inbox, 0700); err != nil {
		t.Fatal(err)
	}
	manager, err := newGovernedRetentionManager(filepath.Join(root, "retention"), map[string]string{"inbox": inbox}, []GovernedRetentionPolicy{{Class: "finance-7y", RetainFor: time.Hour}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	disclosure := &decision.DisclosureBinding{Version: decision.DisclosureBindingRetentionVersion, RetentionClass: "finance-30d"}
	if _, err := manager.prepare(disclosure, filepath.Join(inbox, "message.json")); err == nil {
		t.Fatal("unknown retention class was accepted")
	}
	disclosure.RetentionClass = "finance-7y"
	if _, err := manager.prepare(disclosure, filepath.Join(root, "outside.json")); err == nil {
		t.Fatal("retention path escape was accepted")
	}
}

func TestServicePersistsAndExpiresGovernedRetention(t *testing.T) {
	root := t.TempDir()
	inbox := filepath.Join(root, "inbox")
	received := filepath.Join(root, "received")
	state := filepath.Join(root, "retention")
	now := time.Unix(1785500000, 0).UTC()
	service := NewService(ServiceConfig{
		InboxDir: inbox, ReceivedDir: received, RequireGoverned: true,
		GovernedRetentionPolicies: []GovernedRetentionPolicy{{Class: "finance-7y", RetainFor: time.Second}},
		RetentionStateDir:         state,
	})
	if err := service.initializeGovernedRetention(); err != nil {
		t.Fatal(err)
	}
	service.retention.now = func() time.Time { return now }
	disclosure := &decision.DisclosureBinding{
		Version: decision.DisclosureBindingRetentionVersion, ContentHash: decision.HashPayload([]byte("classified")), DeclaredBytes: 10,
		ContentType: "text/plain", Labels: []string{"finance"}, Recipient: "agent:finance", Purpose: "inbox-delivery", Residency: "eu-west-1", RetentionClass: "finance-7y",
	}
	if err := service.requireGovernedRetention(disclosure); err != nil {
		t.Fatal(err)
	}
	delivery, err := service.prepareInboxMessage(&Frame{Type: TypeText, Payload: []byte("classified")}, protocol.Addr{Node: 1}, disclosure)
	if err != nil {
		t.Fatal(err)
	}
	delivery.commit()
	files, err := os.ReadDir(inbox)
	if err != nil || len(files) != 1 {
		t.Fatalf("retained inbox files=%v err=%v", files, err)
	}
	now = now.Add(time.Second)
	if err := service.retention.Sweep(); err != nil {
		t.Fatal(err)
	}
	files, err = os.ReadDir(inbox)
	if err != nil || len(files) != 0 {
		t.Fatalf("expired inbox files=%v err=%v", files, err)
	}
}

func TestStreamRetentionPreparationRunsBeforeFinalRename(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("classified")
	hash := sha256.Sum256(payload)
	var id [transferIDLen]byte
	copy(id[:], hash[:transferIDLen])
	prepared, committed := false, false
	receiver := NewStreamReceiverWithQuotaAndPrepareAndCommit(
		dir,
		func(string) string { return "final.txt" },
		nil,
		func(_ [transferIDLen]byte, _ string, path string, _ int64) error {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("final path was visible before preparation: %v", err)
			}
			prepared = true
			return nil
		},
		func(_ [transferIDLen]byte, _ string, path string, _ int64) error {
			if !prepared {
				t.Fatal("commit ran before preparation")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("final path was not visible at commit: %v", err)
			}
			committed = true
			return nil
		},
		0,
	)
	if response := receiver.HandleFrame(encodeInit(id, uint64(len(payload)), hash, uint32(StreamChunkSize), "source.txt")); response == nil {
		t.Fatal("INIT did not produce a response")
	}
	if response := receiver.HandleFrame(encodeChunk(id, 0, payload)); response == nil {
		t.Fatal("CHUNK did not produce a response")
	}
	response := receiver.HandleFrame(encodeStreamFrame(streamKindDone, id, nil))
	if response == nil {
		t.Fatal("DONE did not produce completion")
	}
	_, _, body, ok := decodeStreamFrame(response)
	complete, _ := decodeComplete(body)
	if !ok || !complete || !prepared || !committed {
		t.Fatalf("stream lifecycle response=%+v prepared=%v committed=%v", response, prepared, committed)
	}
}
