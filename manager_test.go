package viracochan

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestManagerCreate(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()

	manager, err := NewManager(storage)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	content := map[string]interface{}{
		"setting1": "value1",
		"setting2": 42,
	}

	cfg, err := manager.Create(ctx, "test-config", content)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if cfg.Meta.Version != 1 {
		t.Errorf("Expected version 1, got %d", cfg.Meta.Version)
	}

	if cfg.Meta.CS == "" {
		t.Error("Checksum not set")
	}

	// Verify content
	var loaded map[string]interface{}
	if err := json.Unmarshal(cfg.Content, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal content: %v", err)
	}

	if loaded["setting1"] != "value1" {
		t.Error("Content mismatch")
	}
}

func TestManagerUpdate(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create initial config
	initial := map[string]interface{}{"version": 1}
	cfg1, err := manager.Create(ctx, "test", initial)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Update config
	updated := map[string]interface{}{"version": 2, "new": "field"}
	cfg2, err := manager.Update(ctx, "test", updated)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if cfg2.Meta.Version != 2 {
		t.Errorf("Expected version 2, got %d", cfg2.Meta.Version)
	}

	if cfg2.Meta.PrevCS != cfg1.Meta.CS {
		t.Error("PrevCS not linked correctly")
	}

	// Verify chain integrity
	if err := cfg2.NextOf(cfg1); err != nil {
		t.Errorf("Chain validation failed: %v", err)
	}
}

func TestManagerGetAndHistory(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create multiple versions
	for i := 1; i <= 5; i++ {
		content := map[string]interface{}{"iteration": i}
		if i == 1 {
			manager.Create(ctx, "test", content)
		} else {
			manager.Update(ctx, "test", content)
		}
	}

	// Get specific version
	cfg3, err := manager.Get(ctx, "test", 3)
	if err != nil {
		t.Fatalf("Get version 3 failed: %v", err)
	}

	if cfg3.Meta.Version != 3 {
		t.Errorf("Expected version 3, got %d", cfg3.Meta.Version)
	}

	// Get latest
	latest, err := manager.GetLatest(ctx, "test")
	if err != nil {
		t.Fatalf("GetLatest failed: %v", err)
	}

	if latest.Meta.Version != 5 {
		t.Errorf("Expected latest version 5, got %d", latest.Meta.Version)
	}

	// Get history
	history, err := manager.GetHistory(ctx, "test")
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	if len(history) != 5 {
		t.Errorf("Expected 5 versions in history, got %d", len(history))
	}

	// Verify history is ordered
	for i, cfg := range history {
		if cfg.Meta.Version != uint64(i+1) {
			t.Errorf("History out of order at index %d", i)
		}
	}
}

func TestManagerWithSigner(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	signer, _ := NewSigner()

	manager, err := NewManager(storage, WithSigner(signer))
	if err != nil {
		t.Fatalf("NewManager with signer failed: %v", err)
	}

	cfg, err := manager.Create(ctx, "signed", map[string]interface{}{"signed": true})
	if err != nil {
		t.Fatalf("Create with signing failed: %v", err)
	}

	if cfg.Meta.Signature == "" {
		t.Error("Config not signed")
	}

	// Verify signature
	if err := manager.Verify(cfg, signer.PublicKey()); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestManagerValidateChain(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create chain
	for i := 1; i <= 3; i++ {
		content := map[string]interface{}{"step": i}
		if i == 1 {
			manager.Create(ctx, "chain", content)
		} else {
			manager.Update(ctx, "chain", content)
		}
	}

	// Validate chain
	if err := manager.ValidateChain(ctx, "chain"); err != nil {
		t.Errorf("Valid chain validation failed: %v", err)
	}
}

func TestManagerReconstruct(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create some configs
	content := map[string]interface{}{"data": "original"}
	manager.Create(ctx, "test", content)

	for i := 0; i < 3; i++ {
		content["iteration"] = i
		manager.Update(ctx, "test", content)
	}

	// Clear cache to force reconstruction
	manager.cache = make(map[string]*Config)

	// Reconstruct
	reconstructed, err := manager.Reconstruct(ctx, "test")
	if err != nil {
		t.Fatalf("Reconstruct failed: %v", err)
	}

	if reconstructed.Meta.Version != 4 {
		t.Errorf("Expected version 4, got %d", reconstructed.Meta.Version)
	}
}

func TestManagerImportExport(t *testing.T) {
	ctx := context.Background()
	storage1 := NewMemoryStorage()
	manager1, _ := NewManager(storage1)

	// Create config
	content := map[string]interface{}{
		"exported": true,
		"data":     "test",
	}
	cfg, _ := manager1.Create(ctx, "export-test", content)

	// Export
	exported, err := manager1.Export(ctx, "export-test")
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Import to new manager
	storage2 := NewMemoryStorage()
	manager2, _ := NewManager(storage2)

	if err := manager2.Import(ctx, "imported", exported); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify imported config
	imported, err := manager2.GetLatest(ctx, "imported")
	if err != nil {
		t.Fatalf("GetLatest after import failed: %v", err)
	}

	if imported.Meta.CS != cfg.Meta.CS {
		t.Error("Checksum mismatch after import")
	}

	// Compare content semantically
	var origContent, importedContent interface{}
	json.Unmarshal(cfg.Content, &origContent)
	json.Unmarshal(imported.Content, &importedContent)

	if !reflect.DeepEqual(origContent, importedContent) {
		t.Errorf("Content mismatch after import: %v != %v", origContent, importedContent)
	}
}

func TestManagerRollback(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create versions
	versions := make([]*Config, 5)
	for i := 0; i < 5; i++ {
		content := map[string]interface{}{"version": i + 1}
		var cfg *Config
		var err error

		if i == 0 {
			cfg, err = manager.Create(ctx, "rollback-test", content)
		} else {
			cfg, err = manager.Update(ctx, "rollback-test", content)
		}

		if err != nil {
			t.Fatalf("Create/Update %d failed: %v", i, err)
		}
		versions[i] = cfg
	}

	// Rollback to version 3
	rolled, err := manager.Rollback(ctx, "rollback-test", 3)
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Version should be 6 (new version after rollback)
	if rolled.Meta.Version != 6 {
		t.Errorf("Expected version 6 after rollback, got %d", rolled.Meta.Version)
	}

	// Content should match version 3
	var v3Content, rolledContent map[string]interface{}
	json.Unmarshal(versions[2].Content, &v3Content)
	json.Unmarshal(rolled.Content, &rolledContent)

	if v3Content["version"] != rolledContent["version"] {
		t.Error("Content mismatch after rollback")
	}
}

func TestManagerList(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create multiple configs
	ids := []string{"config1", "config2", "config3"}
	for _, id := range ids {
		content := map[string]interface{}{"id": id}
		if _, err := manager.Create(ctx, id, content); err != nil {
			t.Fatalf("Create %s failed: %v", id, err)
		}
	}

	// List all
	listed, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(listed) != len(ids) {
		t.Errorf("Expected %d configs, got %d", len(ids), len(listed))
	}

	// Verify all IDs are present
	found := make(map[string]bool)
	for _, id := range listed {
		found[id] = true
	}

	for _, id := range ids {
		if !found[id] {
			t.Errorf("ID %s not found in list", id)
		}
	}
}

func TestManagerWatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create initial config
	manager.Create(ctx, "watch-test", map[string]interface{}{"v": 1})

	// Start watching
	ch, err := manager.Watch(ctx, "watch-test", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Watch failed: %v", err)
	}

	// Update config
	go func() {
		time.Sleep(200 * time.Millisecond)
		manager.Update(ctx, "watch-test", map[string]interface{}{"v": 2})
	}()

	// Wait for update
	select {
	case cfg := <-ch:
		if cfg == nil {
			t.Error("Received nil config")
		} else if cfg.Meta.Version != 2 {
			t.Errorf("Expected version 2, got %d", cfg.Meta.Version)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timeout waiting for config update")
	}
}

func TestManagerCompact(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	manager, _ := NewManager(storage)

	// Create many versions
	for i := 0; i < 20; i++ {
		content := map[string]interface{}{"iteration": i}
		if i == 0 {
			manager.Create(ctx, "compact-test", content)
		} else {
			manager.Update(ctx, "compact-test", content)
		}
	}

	// Compact journal
	if err := manager.Compact(ctx); err != nil {
		t.Fatalf("Compact failed: %v", err)
	}

	// Should still be able to get latest
	latest, err := manager.GetLatest(ctx, "compact-test")
	if err != nil {
		t.Fatalf("GetLatest after compact failed: %v", err)
	}

	if latest.Meta.Version != 20 {
		t.Errorf("Expected version 20, got %d", latest.Meta.Version)
	}
}
