package viracochan

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// JournalEntry represents a single change in the journal
type JournalEntry struct {
	ID        string    `json:"id"`
	Version   uint64    `json:"v"`
	CS        string    `json:"cs"`
	PrevCS    string    `json:"prev_cs,omitempty"`
	Time      time.Time `json:"t"`
	Operation string    `json:"op"`
	Config    *Config   `json:"config,omitempty"`
}

// Journal manages change log for configurations
type Journal struct {
	storage Storage
	path    string
	mu      sync.Mutex
}

// NewJournal creates new journal instance
func NewJournal(storage Storage, path string) *Journal {
	return &Journal{
		storage: storage,
		path:    path,
	}
}

// Append adds entry to journal
func (j *Journal) Append(ctx context.Context, entry *JournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	existing, _ := j.storage.Read(ctx, j.path)
	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		existing = append(existing, '\n')
	}

	newData := append(existing, data...)
	newData = append(newData, '\n')

	return j.storage.Write(ctx, j.path, newData)
}

// ReadAll reads all journal entries
func (j *Journal) ReadAll(ctx context.Context) ([]*JournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	data, err := j.storage.Read(ctx, j.path)
	if err != nil {
		if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "no such file") {
			return nil, nil
		}
		return nil, err
	}

	var entries []*JournalEntry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry JournalEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("invalid journal entry: %w", err)
		}
		entries = append(entries, &entry)
	}

	return entries, scanner.Err()
}

// Resequence rebuilds ordered chain from scattered journal entries
func (j *Journal) Resequence(entries []*JournalEntry) ([]*JournalEntry, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	csToEntry := make(map[string]*JournalEntry, len(entries))
	prevToEntries := make(map[string][]*JournalEntry, len(entries))
	csSet := make(map[string]struct{}, len(entries))

	for _, entry := range entries {
		if entry.CS == "" {
			continue
		}
		csToEntry[entry.CS] = entry
		prevToEntries[entry.PrevCS] = append(prevToEntries[entry.PrevCS], entry)
		csSet[entry.CS] = struct{}{}
	}

	var head *JournalEntry
	for _, entry := range entries {
		if entry.PrevCS == "" || (entry.PrevCS != "" && csToEntry[entry.PrevCS] == nil) {
			if head != nil {
				return nil, fmt.Errorf("multiple chain heads found")
			}
			head = entry
		}
	}

	if head == nil {
		return nil, fmt.Errorf("no chain head found")
	}

	ordered := make([]*JournalEntry, 0, len(entries))
	current := head

	for current != nil {
		ordered = append(ordered, current)
		nexts := prevToEntries[current.CS]

		if len(nexts) == 0 {
			break
		}
		if len(nexts) > 1 {
			return nil, fmt.Errorf("fork detected at version %d", current.Version)
		}

		current = nexts[0]
	}

	if len(ordered) != len(entries) {
		return nil, fmt.Errorf("incomplete chain: found %d of %d entries", len(ordered), len(entries))
	}

	return ordered, nil
}

// ValidateChain verifies integrity of entry sequence
func (j *Journal) ValidateChain(entries []*JournalEntry) error {
	if len(entries) == 0 {
		return nil
	}

	for i, entry := range entries {
		if entry.Config != nil {
			if err := entry.Config.Validate(); err != nil {
				return fmt.Errorf("entry %d invalid: %w", i, err)
			}

			if entry.CS != entry.Config.Meta.CS {
				return fmt.Errorf("entry %d checksum mismatch", i)
			}
		}

		if i > 0 {
			prev := entries[i-1]
			if entry.PrevCS != prev.CS {
				return fmt.Errorf("chain break at %d: prev_cs mismatch", i)
			}
			if entry.Version != prev.Version+1 {
				return fmt.Errorf("version break at %d: %d -> %d", i, prev.Version, entry.Version)
			}
			if entry.Time.Before(prev.Time) {
				return fmt.Errorf("timestamp regression at %d", i)
			}
		}
	}

	return nil
}

// FindByID returns all entries for specific configuration ID
func (j *Journal) FindByID(ctx context.Context, id string) ([]*JournalEntry, error) {
	all, err := j.ReadAll(ctx)
	if err != nil {
		return nil, err
	}

	var filtered []*JournalEntry
	for _, entry := range all {
		if entry.ID == id {
			filtered = append(filtered, entry)
		}
	}

	return filtered, nil
}

// Compact removes redundant entries while preserving chain integrity
func (j *Journal) Compact(ctx context.Context) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Read without locking since we already have the lock
	data, err := j.storage.Read(ctx, j.path)
	if err != nil {
		if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "no such file") {
			return nil
		}
		return err
	}

	var entries []*JournalEntry
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry JournalEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return fmt.Errorf("invalid journal entry: %w", err)
		}
		entries = append(entries, &entry)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	byID := make(map[string][]*JournalEntry)
	for _, entry := range entries {
		byID[entry.ID] = append(byID[entry.ID], entry)
	}

	var compacted []*JournalEntry
	for id, idEntries := range byID {
		ordered, err := j.Resequence(idEntries)
		if err != nil {
			fmt.Printf("Warning: skipping %s due to resequence error: %v\n", id, err)
			compacted = append(compacted, idEntries...)
			continue
		}

		if len(ordered) > 10 {
			compacted = append(compacted, ordered[len(ordered)-10:]...)
		} else {
			compacted = append(compacted, ordered...)
		}
	}

	var buf strings.Builder
	for _, entry := range compacted {
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		buf.Write(data)
		buf.WriteByte('\n')
	}

	return j.storage.Write(ctx, j.path, []byte(buf.String()))
}

// Reconstruct rebuilds latest state from journal and scattered files
func (j *Journal) Reconstruct(ctx context.Context, id string, storage Storage) (*Config, error) {
	entries, err := j.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		cs := NewConfigStorage(storage, "configs")
		return cs.LoadLatest(ctx, id)
	}

	ordered, err := j.Resequence(entries)
	if err != nil {
		return nil, fmt.Errorf("failed to resequence: %w", err)
	}

	if err := j.ValidateChain(ordered); err != nil {
		return nil, fmt.Errorf("invalid chain: %w", err)
	}

	latest := ordered[len(ordered)-1]
	if latest.Config != nil {
		return latest.Config, nil
	}

	cs := NewConfigStorage(storage, "configs")
	return cs.Load(ctx, id, latest.Version)
}

// JournalReader provides streaming read of journal entries
type JournalReader struct {
	storage Storage
	path    string
	offset  int64
}

// NewJournalReader creates new streaming journal reader
func NewJournalReader(storage Storage, path string) *JournalReader {
	return &JournalReader{
		storage: storage,
		path:    path,
	}
}

// Next reads next journal entry
func (jr *JournalReader) Next(ctx context.Context) (*JournalEntry, error) {
	data, err := jr.storage.Read(ctx, jr.path)
	if err != nil {
		return nil, err
	}

	if jr.offset >= int64(len(data)) {
		return nil, io.EOF
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data[jr.offset:])))
	if !scanner.Scan() {
		return nil, io.EOF
	}

	line := scanner.Text()
	jr.offset += int64(len(line) + 1)

	var entry JournalEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, err
	}

	return &entry, nil
}

// Reset resets reader to beginning
func (jr *JournalReader) Reset() {
	jr.offset = 0
}
