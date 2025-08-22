package viracochan

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestJournalAppendAndRead(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	journal := NewJournal(storage, "test.journal")
	
	entries := []*JournalEntry{
		{
			ID:        "test1",
			Version:   1,
			CS:        "cs1",
			Time:      time.Now(),
			Operation: "create",
		},
		{
			ID:        "test1",
			Version:   2,
			CS:        "cs2",
			PrevCS:    "cs1",
			Time:      time.Now(),
			Operation: "update",
		},
	}
	
	for _, entry := range entries {
		if err := journal.Append(ctx, entry); err != nil {
			t.Fatalf("Failed to append entry: %v", err)
		}
	}
	
	read, err := journal.ReadAll(ctx)
	if err != nil {
		t.Fatalf("Failed to read journal: %v", err)
	}
	
	if len(read) != len(entries) {
		t.Errorf("Expected %d entries, got %d", len(entries), len(read))
	}
	
	for i, entry := range read {
		if entry.ID != entries[i].ID {
			t.Errorf("Entry %d ID mismatch: expected %s, got %s", i, entries[i].ID, entry.ID)
		}
		if entry.Version != entries[i].Version {
			t.Errorf("Entry %d version mismatch: expected %d, got %d", i, entries[i].Version, entry.Version)
		}
	}
}

func TestJournalResequence(t *testing.T) {
	journal := &Journal{}
	
	entries := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 2, CS: "cs2", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
		{ID: "test", Version: 3, CS: "cs3", PrevCS: "cs2", Time: time.Now().Add(2 * time.Second)},
		{ID: "test", Version: 4, CS: "cs4", PrevCS: "cs3", Time: time.Now().Add(3 * time.Second)},
		{ID: "test", Version: 5, CS: "cs5", PrevCS: "cs4", Time: time.Now().Add(4 * time.Second)},
	}
	
	shuffled := make([]*JournalEntry, len(entries))
	copy(shuffled, entries)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	
	resequenced, err := journal.Resequence(shuffled)
	if err != nil {
		t.Fatalf("Resequence failed: %v", err)
	}
	
	if len(resequenced) != len(entries) {
		t.Errorf("Expected %d entries, got %d", len(entries), len(resequenced))
	}
	
	for i, entry := range resequenced {
		if entry.Version != entries[i].Version {
			t.Errorf("Position %d: expected version %d, got %d", i, entries[i].Version, entry.Version)
		}
		if entry.CS != entries[i].CS {
			t.Errorf("Position %d: checksum mismatch", i)
		}
	}
}

func TestJournalValidateChain(t *testing.T) {
	journal := &Journal{}
	
	validEntries := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 2, CS: "cs2", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
		{ID: "test", Version: 3, CS: "cs3", PrevCS: "cs2", Time: time.Now().Add(2 * time.Second)},
	}
	
	if err := journal.ValidateChain(validEntries); err != nil {
		t.Errorf("Valid chain validation failed: %v", err)
	}
	
	invalidVersion := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 3, CS: "cs2", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
	}
	
	if err := journal.ValidateChain(invalidVersion); err == nil {
		t.Error("Expected version break error")
	}
	
	invalidPrevCS := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 2, CS: "cs2", PrevCS: "wrong", Time: time.Now().Add(1 * time.Second)},
	}
	
	if err := journal.ValidateChain(invalidPrevCS); err == nil {
		t.Error("Expected chain break error")
	}
	
	timestampRegression := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 2, CS: "cs2", PrevCS: "cs1", Time: time.Now().Add(-1 * time.Second)},
	}
	
	if err := journal.ValidateChain(timestampRegression); err == nil {
		t.Error("Expected timestamp regression error")
	}
}

func TestJournalReconstruct(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	journal := NewJournal(storage, "test.journal")
	configStore := NewConfigStorage(storage, "configs")
	
	cfg1 := &Config{
		Content: json.RawMessage(`{"value": 1}`),
	}
	cfg1.UpdateMeta()
	
	cfg2 := &Config{
		Meta:    cfg1.Meta,
		Content: json.RawMessage(`{"value": 2}`),
	}
	cfg2.UpdateMeta()
	
	configStore.Save(ctx, "test", cfg1)
	configStore.Save(ctx, "test", cfg2)
	
	entries := []*JournalEntry{
		{
			ID:      "test",
			Version: cfg1.Meta.Version,
			CS:      cfg1.Meta.CS,
			PrevCS:  cfg1.Meta.PrevCS,
			Time:    cfg1.Meta.Time,
			Config:  cfg1,
		},
		{
			ID:      "test",
			Version: cfg2.Meta.Version,
			CS:      cfg2.Meta.CS,
			PrevCS:  cfg2.Meta.PrevCS,
			Time:    cfg2.Meta.Time,
			Config:  cfg2,
		},
	}
	
	for _, entry := range entries {
		journal.Append(ctx, entry)
	}
	
	reconstructed, err := journal.Reconstruct(ctx, "test", storage)
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}
	
	if reconstructed.Meta.Version != cfg2.Meta.Version {
		t.Errorf("Expected version %d, got %d", cfg2.Meta.Version, reconstructed.Meta.Version)
	}
	
	if reconstructed.Meta.CS != cfg2.Meta.CS {
		t.Error("Checksum mismatch in reconstructed config")
	}
}

func TestJournalForkDetection(t *testing.T) {
	journal := &Journal{}
	
	forkedEntries := []*JournalEntry{
		{ID: "test", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
		{ID: "test", Version: 2, CS: "cs2a", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
		{ID: "test", Version: 2, CS: "cs2b", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
	}
	
	_, err := journal.Resequence(forkedEntries)
	if err == nil {
		t.Error("Expected fork detection error")
	}
}

func TestJournalCompact(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	journal := NewJournal(storage, "test.journal")
	
	for i := 0; i < 20; i++ {
		entry := &JournalEntry{
			ID:        "test1",
			Version:   uint64(i + 1),
			CS:        fmt.Sprintf("cs%d", i+1),
			PrevCS:    fmt.Sprintf("cs%d", i),
			Time:      time.Now().Add(time.Duration(i) * time.Second),
			Operation: "update",
		}
		if i == 0 {
			entry.PrevCS = ""
		}
		journal.Append(ctx, entry)
	}
	
	for i := 0; i < 5; i++ {
		entry := &JournalEntry{
			ID:        "test2",
			Version:   uint64(i + 1),
			CS:        fmt.Sprintf("test2_cs%d", i+1),
			PrevCS:    fmt.Sprintf("test2_cs%d", i),
			Time:      time.Now().Add(time.Duration(i) * time.Second),
			Operation: "update",
		}
		if i == 0 {
			entry.PrevCS = ""
		}
		journal.Append(ctx, entry)
	}
	
	if err := journal.Compact(ctx); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}
	
	entries, err := journal.ReadAll(ctx)
	if err != nil {
		t.Fatalf("ReadAll after compact failed: %v", err)
	}
	
	if len(entries) > 15 {
		t.Errorf("Expected compacted journal to have <= 15 entries, got %d", len(entries))
	}
}