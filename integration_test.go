package viracochan

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// TestIntegrationFullWorkflow tests complete workflow with all features
func TestIntegrationFullWorkflow(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	signer, _ := NewSigner()

	// Create manager with signing
	manager, err := NewManager(storage, WithSigner(signer))
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Phase 1: Create initial configuration
	initialConfig := map[string]interface{}{
		"environment": "development",
		"features": map[string]interface{}{
			"auth":    true,
			"logging": true,
			"cache":   false,
		},
		"limits": map[string]interface{}{
			"max_connections": 100,
			"timeout":         30,
		},
	}

	cfg1, err := manager.Create(ctx, "app", initialConfig)
	if err != nil {
		t.Fatalf("Failed to create config: %v", err)
	}

	// Verify initial state
	if cfg1.Meta.Version != 1 {
		t.Errorf("Expected version 1, got %d", cfg1.Meta.Version)
	}
	if cfg1.Meta.Signature == "" {
		t.Error("Config not signed")
	}
	if err := manager.Verify(cfg1, signer.PublicKey()); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	// Phase 2: Multiple updates
	updates := []map[string]interface{}{
		{
			"environment": "staging",
			"features": map[string]interface{}{
				"auth":    true,
				"logging": true,
				"cache":   true, // Enable cache
			},
			"limits": map[string]interface{}{
				"max_connections": 200, // Increase connections
				"timeout":         30,
			},
		},
		{
			"environment": "production",
			"features": map[string]interface{}{
				"auth":      true,
				"logging":   false, // Disable debug logging
				"cache":     true,
				"ratelimit": true, // Add rate limiting
			},
			"limits": map[string]interface{}{
				"max_connections": 500, // Production scale
				"timeout":         60,  // Longer timeout
			},
		},
	}

	for _, update := range updates {
		if _, err := manager.Update(ctx, "app", update); err != nil {
			t.Fatalf("Update failed: %v", err)
		}
	}

	// Phase 3: Validate chain integrity
	if err := manager.ValidateChain(ctx, "app"); err != nil {
		t.Errorf("Chain validation failed: %v", err)
	}

	// Phase 4: Get history and verify progression
	history, err := manager.GetHistory(ctx, "app")
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	if len(history) != 3 {
		t.Errorf("Expected 3 versions, got %d", len(history))
	}

	// Verify chain links
	for i := 1; i < len(history); i++ {
		if err := history[i].NextOf(history[i-1]); err != nil {
			t.Errorf("Chain broken at version %d: %v", i+1, err)
		}
	}

	// Verify all signatures
	if err := VerifyChainSignatures(history, signer.PublicKey()); err != nil {
		t.Errorf("Chain signature verification failed: %v", err)
	}

	// Phase 5: Simulate journal reconstruction from scattered entries
	journal := manager.journal
	entries, _ := journal.ReadAll(ctx)

	// Shuffle entries to simulate scattered data
	shuffled := make([]*JournalEntry, len(entries))
	copy(shuffled, entries)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Resequence and validate
	resequenced, err := journal.Resequence(shuffled)
	if err != nil {
		t.Fatalf("Failed to resequence: %v", err)
	}

	if err := journal.ValidateChain(resequenced); err != nil {
		t.Errorf("Resequenced chain validation failed: %v", err)
	}

	// Phase 6: Rollback test
	rolled, err := manager.Rollback(ctx, "app", 2)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	if rolled.Meta.Version != 4 {
		t.Errorf("Expected version 4 after rollback, got %d", rolled.Meta.Version)
	}

	// Verify rolled back content matches v2
	var rolledContent, v2Content map[string]interface{}
	json.Unmarshal(rolled.Content, &rolledContent)
	json.Unmarshal(history[1].Content, &v2Content)

	if rolledContent["environment"] != v2Content["environment"] {
		t.Error("Rollback content mismatch")
	}

	// Phase 7: Export and import to new manager
	exported, err := manager.Export(ctx, "app")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Create new manager with different storage
	storage2 := NewMemoryStorage()
	manager2, _ := NewManager(storage2, WithSigner(signer))

	if err := manager2.Import(ctx, "imported-app", exported); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	imported, err := manager2.GetLatest(ctx, "imported-app")
	if err != nil {
		t.Fatalf("Failed to get imported config: %v", err)
	}

	if imported.Meta.CS != rolled.Meta.CS {
		t.Error("Import/export checksum mismatch")
	}

	// Phase 8: Reconstruction from partial data
	manager.cache = make(map[string]*Config) // Clear cache

	reconstructed, err := manager.Reconstruct(ctx, "app")
	if err != nil {
		t.Fatalf("Reconstruction failed: %v", err)
	}

	latest, _ := manager.GetLatest(ctx, "app")
	if reconstructed.Meta.CS != latest.Meta.CS {
		t.Error("Reconstruction mismatch")
	}
}

// TestIntegrationConcurrentOperations tests thread safety
func TestIntegrationConcurrentOperations(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create multiple configs concurrently
	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			config := map[string]interface{}{
				"worker_id": id,
				"timestamp": time.Now().UnixNano(),
			}

			_, err := manager.Create(ctx, fmt.Sprintf("worker-%d", id), config)
			done <- err
		}(i)
	}

	// Collect results
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("Concurrent create failed: %v", err)
		}
	}

	// Verify all configs exist
	list, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(list) != 10 {
		t.Errorf("Expected 10 configs, got %d", len(list))
	}

	// Concurrent updates to same config
	manager.Create(ctx, "shared", map[string]interface{}{"counter": 0})

	for i := 0; i < 10; i++ {
		go func(n int) {
			time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)

			current, _ := manager.GetLatest(ctx, "shared")
			var content map[string]interface{}
			json.Unmarshal(current.Content, &content)

			content["counter"] = n
			_, err := manager.Update(ctx, "shared", content)
			done <- err
		}(i)
	}

	// Collect update results
	for i := 0; i < 10; i++ {
		<-done // Some updates may fail due to version conflicts, which is expected
	}

	// Verify chain is still valid
	if err := manager.ValidateChain(ctx, "shared"); err != nil {
		t.Errorf("Chain validation failed after concurrent updates: %v", err)
	}
}

// TestIntegrationRecoveryScenarios tests various recovery scenarios
func TestIntegrationRecoveryScenarios(t *testing.T) {
	ctx := context.Background()

	// Scenario 1: Recover from journal only (lost config files)
	t.Run("RecoverFromJournalOnly", func(t *testing.T) {
		storage := NewMemoryStorage()
		manager, _ := NewManager(storage)

		// Create configs
		for i := 1; i <= 5; i++ {
			config := map[string]interface{}{"iteration": i}
			if i == 1 {
				manager.Create(ctx, "test", config)
			} else {
				manager.Update(ctx, "test", config)
			}
		}

		// Delete all config files, keep journal
		files, _ := storage.List(ctx, "configs")
		for _, file := range files {
			storage.Delete(ctx, file)
		}

		// Should still reconstruct from journal
		reconstructed, err := manager.Reconstruct(ctx, "test")
		if err != nil {
			t.Errorf("Failed to reconstruct from journal: %v", err)
		}

		if reconstructed.Meta.Version != 5 {
			t.Errorf("Expected version 5, got %d", reconstructed.Meta.Version)
		}
	})

	// Scenario 2: Recover from scattered out-of-order journal
	t.Run("RecoverFromScatteredJournal", func(t *testing.T) {
		journal := &Journal{}

		// Create out-of-order entries
		entries := []*JournalEntry{
			{ID: "cfg", Version: 5, CS: "cs5", PrevCS: "cs4", Time: time.Now().Add(4 * time.Second)},
			{ID: "cfg", Version: 2, CS: "cs2", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
			{ID: "cfg", Version: 4, CS: "cs4", PrevCS: "cs3", Time: time.Now().Add(3 * time.Second)},
			{ID: "cfg", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
			{ID: "cfg", Version: 3, CS: "cs3", PrevCS: "cs2", Time: time.Now().Add(2 * time.Second)},
		}

		// Resequence
		ordered, err := journal.Resequence(entries)
		if err != nil {
			t.Fatalf("Failed to resequence: %v", err)
		}

		// Verify correct order
		for i, entry := range ordered {
			if entry.Version != uint64(i+1) {
				t.Errorf("Wrong order at position %d: version %d", i, entry.Version)
			}
		}

		// Validate chain
		if err := journal.ValidateChain(ordered); err != nil {
			t.Errorf("Resequenced chain invalid: %v", err)
		}
	})

	// Scenario 3: Detect and handle forked chains
	t.Run("DetectForkedChain", func(t *testing.T) {
		journal := &Journal{}

		// Create forked entries (two different v2 from same v1)
		forked := []*JournalEntry{
			{ID: "cfg", Version: 1, CS: "cs1", PrevCS: "", Time: time.Now()},
			{ID: "cfg", Version: 2, CS: "cs2a", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
			{ID: "cfg", Version: 2, CS: "cs2b", PrevCS: "cs1", Time: time.Now().Add(1 * time.Second)},
			{ID: "cfg", Version: 3, CS: "cs3a", PrevCS: "cs2a", Time: time.Now().Add(2 * time.Second)},
			{ID: "cfg", Version: 3, CS: "cs3b", PrevCS: "cs2b", Time: time.Now().Add(2 * time.Second)},
		}

		// Should detect fork
		_, err := journal.Resequence(forked)
		if err == nil {
			t.Error("Expected fork detection error")
		}
	})
}
