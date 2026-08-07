// SPDX-License-Identifier: AGPL-3.0-or-later

package dataexchange

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pilot-protocol/common/decision"
)

const (
	retentionEntryVersion uint16 = 1
	defaultRetentionSweep        = time.Minute
	minRetentionDuration         = time.Second
	maxRetentionDuration         = 10 * 365 * 24 * time.Hour
	maxRetentionPolicies         = 32
)

// GovernedRetentionPolicy maps one V2 signed retention class to a local
// retention duration. The class is selected by signed policy and bound to the
// Intent; the duration is attachment-controlled, so a sender cannot extend it.
type GovernedRetentionPolicy struct {
	Class     string
	RetainFor time.Duration
}

type governedRetentionEntry struct {
	Version        uint16 `json:"version"`
	Root           string `json:"root"`
	RelativePath   string `json:"relative_path"`
	RetentionClass string `json:"retention_class"`
	DisclosureHash string `json:"disclosure_hash"`
	ExpiresAt      int64  `json:"expires_at"`
}

type governedRetentionManager struct {
	stateDir string
	roots    map[string]string
	policies map[string]time.Duration
	now      func() time.Time
}

type retentionTicket struct {
	entryPath string
}

func newGovernedRetentionManager(stateDir string, roots map[string]string, policies []GovernedRetentionPolicy, now func() time.Time) (*governedRetentionManager, error) {
	if len(policies) == 0 || len(policies) > maxRetentionPolicies {
		return nil, fmt.Errorf("dataexchange: retention needs 1-%d policies", maxRetentionPolicies)
	}
	if strings.TrimSpace(stateDir) == "" {
		return nil, fmt.Errorf("dataexchange: retention state directory is required")
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("dataexchange: retention roots are required")
	}
	cleanRoots := make(map[string]string, len(roots))
	for name, root := range roots {
		if name == "" || strings.TrimSpace(root) == "" || !filepath.IsAbs(root) {
			return nil, fmt.Errorf("dataexchange: invalid retention root")
		}
		cleanRoots[name] = filepath.Clean(root)
	}
	policyMap := make(map[string]time.Duration, len(policies))
	for _, policy := range policies {
		if !validRetentionClass(policy.Class) || policy.RetainFor < minRetentionDuration || policy.RetainFor > maxRetentionDuration {
			return nil, fmt.Errorf("dataexchange: invalid retention policy")
		}
		if _, exists := policyMap[policy.Class]; exists {
			return nil, fmt.Errorf("dataexchange: duplicate retention class %q", policy.Class)
		}
		policyMap[policy.Class] = policy.RetainFor
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("dataexchange: create retention state directory: %w", err)
	}
	return &governedRetentionManager{stateDir: filepath.Clean(stateDir), roots: cleanRoots, policies: policyMap, now: now}, nil
}

func (manager *governedRetentionManager) prepare(disclosure *decision.DisclosureBinding, path string) (retentionTicket, error) {
	if manager == nil {
		return retentionTicket{}, nil
	}
	if disclosure == nil || disclosure.Version != decision.DisclosureBindingRetentionVersion || disclosure.RetentionClass == "" {
		return retentionTicket{}, fmt.Errorf("dataexchange: governed retention requires a V2 disclosure retention class")
	}
	retention, exists := manager.policies[disclosure.RetentionClass]
	if !exists {
		return retentionTicket{}, fmt.Errorf("dataexchange: disclosure retention class is not configured")
	}
	rootName, relativePath, err := manager.relativePath(path)
	if err != nil {
		return retentionTicket{}, err
	}
	disclosureHash, err := disclosure.Hash()
	if err != nil {
		return retentionTicket{}, err
	}
	entry := governedRetentionEntry{
		Version: retentionEntryVersion, Root: rootName, RelativePath: relativePath,
		RetentionClass: disclosure.RetentionClass, DisclosureHash: disclosureHash,
		ExpiresAt: manager.now().UTC().Add(retention).Unix(),
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return retentionTicket{}, fmt.Errorf("dataexchange: encode retention entry: %w", err)
	}
	sum := sha256.Sum256([]byte(rootName + "\x00" + relativePath))
	entryPath := filepath.Join(manager.stateDir, hex.EncodeToString(sum[:])+".json")
	if err := writeRetentionEntry(entryPath, encoded); err != nil {
		return retentionTicket{}, err
	}
	return retentionTicket{entryPath: entryPath}, nil
}

func (ticket retentionTicket) rollback() error {
	if ticket.entryPath == "" {
		return nil
	}
	if err := os.Remove(ticket.entryPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("dataexchange: remove retention entry: %w", err)
	}
	return nil
}

// Sweep deletes expired governed content and only then removes its durable
// journal entry. A malformed journal causes an error instead of silently
// disabling a retention obligation after restart.
func (manager *governedRetentionManager) Sweep() error {
	if manager == nil {
		return nil
	}
	entries, err := os.ReadDir(manager.stateDir)
	if err != nil {
		return fmt.Errorf("dataexchange: read retention state: %w", err)
	}
	now := manager.now().UTC().Unix()
	for _, file := range entries {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		entryPath := filepath.Join(manager.stateDir, file.Name())
		entry, err := readRetentionEntry(entryPath)
		if err != nil {
			return err
		}
		if err := manager.validateEntry(entry); err != nil {
			return err
		}
		if entry.ExpiresAt > now {
			continue
		}
		path, err := manager.pathFor(entry.Root, entry.RelativePath)
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("dataexchange: expire retained content: %w", err)
		}
		if err := os.Remove(entryPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("dataexchange: remove expired retention entry: %w", err)
		}
	}
	return nil
}

func (manager *governedRetentionManager) run(stop <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = defaultRetentionSweep
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if err := manager.Sweep(); err != nil {
				// Keep retrying. Startup already verifies the journal, and a
				// transient removal error must not kill future retention work.
				slog.Error("governed retention sweep failed", "error", err)
				continue
			}
		}
	}
}

func (manager *governedRetentionManager) relativePath(path string) (string, string, error) {
	cleanPath := filepath.Clean(path)
	for name, root := range manager.roots {
		relativePath, err := filepath.Rel(root, cleanPath)
		if err == nil && relativePath != "." && relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)) && !filepath.IsAbs(relativePath) {
			return name, relativePath, nil
		}
	}
	return "", "", fmt.Errorf("dataexchange: retention path is outside managed roots")
}

func (manager *governedRetentionManager) pathFor(rootName, relativePath string) (string, error) {
	root, exists := manager.roots[rootName]
	if !exists || relativePath == "" || filepath.IsAbs(relativePath) {
		return "", fmt.Errorf("dataexchange: invalid retention entry path")
	}
	path := filepath.Join(root, relativePath)
	_, checkedRelative, err := manager.relativePath(path)
	if err != nil || checkedRelative != filepath.Clean(relativePath) {
		return "", fmt.Errorf("dataexchange: invalid retention entry path")
	}
	return path, nil
}

func (manager *governedRetentionManager) validateEntry(entry governedRetentionEntry) error {
	if entry.Version != retentionEntryVersion || !validRetentionClass(entry.RetentionClass) || len(entry.DisclosureHash) != 64 || entry.ExpiresAt <= 0 {
		return fmt.Errorf("dataexchange: invalid retention entry")
	}
	for _, character := range entry.DisclosureHash {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return fmt.Errorf("dataexchange: invalid retention entry")
		}
	}
	_, err := manager.pathFor(entry.Root, entry.RelativePath)
	return err
}

func writeRetentionEntry(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".retention-*")
	if err != nil {
		return fmt.Errorf("dataexchange: create retention entry: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("dataexchange: protect retention entry: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("dataexchange: write retention entry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("dataexchange: sync retention entry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("dataexchange: close retention entry: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("dataexchange: publish retention entry: %w", err)
	}
	return nil
}

func readRetentionEntry(path string) (governedRetentionEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return governedRetentionEntry{}, fmt.Errorf("dataexchange: read retention entry: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4<<10))
	decoder.DisallowUnknownFields()
	var entry governedRetentionEntry
	if err := decoder.Decode(&entry); err != nil {
		return governedRetentionEntry{}, fmt.Errorf("dataexchange: decode retention entry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return governedRetentionEntry{}, fmt.Errorf("dataexchange: invalid retention entry")
	}
	return entry, nil
}

func validRetentionClass(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (character == '-' && index > 0 && index+1 < len(value)) {
			continue
		}
		return false
	}
	return true
}
