package viracochan_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/source-c/viracochan"
)

func ExampleManager_basic() {
	ctx := context.Background()

	// Create storage backend (in-memory for this example)
	storage := viracochan.NewMemoryStorage()

	// Create manager
	manager, err := viracochan.NewManager(storage)
	if err != nil {
		log.Fatal(err)
	}

	// Create initial configuration
	config := map[string]interface{}{
		"database": map[string]interface{}{
			"host":      "localhost",
			"port":      5432,
			"name":      "myapp",
			"pool_size": 10,
		},
		"cache": map[string]interface{}{
			"enabled": true,
			"ttl":     3600,
		},
	}

	cfg, err := manager.Create(ctx, "app-config", config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Created config version %d with checksum %s\n",
		cfg.Meta.Version, cfg.Meta.CS[:8])

	// Update configuration
	config["cache"].(map[string]interface{})["ttl"] = 7200

	updated, err := manager.Update(ctx, "app-config", config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Updated to version %d, linked to previous %s\n",
		updated.Meta.Version, updated.Meta.PrevCS[:8])
}

func ExampleManager_withSigning() {
	ctx := context.Background()
	storage := viracochan.NewMemoryStorage()

	// Create signer for cryptographic signatures
	signer, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Public key: %s\n", signer.PublicKey()[:16])

	// Create manager with signing enabled
	manager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Create signed configuration
	config := map[string]interface{}{
		"api_key":  "secret-key-123",
		"endpoint": "https://api.example.com",
	}

	cfg, err := manager.Create(ctx, "api-config", config)
	if err != nil {
		log.Fatal(err)
	}

	// Verify signature
	if err := manager.Verify(cfg, signer.PublicKey()); err != nil {
		log.Fatal("Signature verification failed:", err)
	}

	fmt.Printf("Created signed config v%d\n", cfg.Meta.Version)
}

func ExampleManager_reconstruction() {
	ctx := context.Background()
	storage := viracochan.NewMemoryStorage()
	manager, _ := viracochan.NewManager(storage)

	// Create multiple versions
	for i := 1; i <= 5; i++ {
		config := map[string]interface{}{
			"version": i,
			"feature_flags": map[string]interface{}{
				fmt.Sprintf("feature_%d", i): true,
			},
		}

		if i == 1 {
			manager.Create(ctx, "features", config)
		} else {
			manager.Update(ctx, "features", config)
		}
	}

	// Reconstruct from journal and storage
	reconstructed, err := manager.Reconstruct(ctx, "features")
	if err != nil {
		log.Fatal(err)
	}

	var content map[string]interface{}
	json.Unmarshal(reconstructed.Content, &content)

	fmt.Printf("Reconstructed version %d with content: %v\n",
		reconstructed.Meta.Version, content["version"])
}

func ExampleManager_history() {
	ctx := context.Background()
	storage := viracochan.NewMemoryStorage()
	manager, _ := viracochan.NewManager(storage)

	// Create configuration history
	configs := []map[string]interface{}{
		{"stage": "development", "debug": true},
		{"stage": "staging", "debug": true},
		{"stage": "production", "debug": false},
	}

	for i, config := range configs {
		if i == 0 {
			manager.Create(ctx, "deployment", config)
		} else {
			manager.Update(ctx, "deployment", config)
		}
	}

	// Get full history
	history, err := manager.GetHistory(ctx, "deployment")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Configuration history:\n")
	for _, cfg := range history {
		var content map[string]interface{}
		json.Unmarshal(cfg.Content, &content)
		fmt.Printf("  v%d: stage=%s, checksum=%s\n",
			cfg.Meta.Version, content["stage"], cfg.Meta.CS[:8])
	}
}

func ExampleManager_rollback() {
	ctx := context.Background()
	storage := viracochan.NewMemoryStorage()
	manager, _ := viracochan.NewManager(storage)

	// Create versions
	versions := []string{"1.0.0", "1.1.0", "2.0.0-beta", "2.0.0"}

	for i, version := range versions {
		config := map[string]interface{}{"app_version": version}
		if i == 0 {
			manager.Create(ctx, "release", config)
		} else {
			manager.Update(ctx, "release", config)
		}
	}

	// Rollback to version 2 (1.1.0)
	rolled, err := manager.Rollback(ctx, "release", 2)
	if err != nil {
		log.Fatal(err)
	}

	var content map[string]interface{}
	json.Unmarshal(rolled.Content, &content)

	fmt.Printf("Rolled back to: %s (new version %d)\n",
		content["app_version"], rolled.Meta.Version)
}

func ExampleJournal_resequence() {
	// Demonstrate reconstruction from scattered journal entries
	journal := &viracochan.Journal{}

	// Simulate scattered/out-of-order entries
	entries := []*viracochan.JournalEntry{
		{ID: "cfg", Version: 3, CS: "cs3", PrevCS: "cs2"},
		{ID: "cfg", Version: 1, CS: "cs1", PrevCS: ""},
		{ID: "cfg", Version: 4, CS: "cs4", PrevCS: "cs3"},
		{ID: "cfg", Version: 2, CS: "cs2", PrevCS: "cs1"},
	}

	// Resequence into correct order
	ordered, err := journal.Resequence(entries)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Resequenced order:\n")
	for _, entry := range ordered {
		fmt.Printf("  v%d: %s -> %s\n",
			entry.Version, entry.PrevCS, entry.CS)
	}
}

func ExampleFileStorage() {
	ctx := context.Background()

	// Create file-based storage
	storage, err := viracochan.NewFileStorage("/tmp/configs")
	if err != nil {
		log.Fatal(err)
	}

	// Use with manager
	manager, err := viracochan.NewManager(storage)
	if err != nil {
		log.Fatal(err)
	}

	// Create persistent configuration
	config := map[string]interface{}{
		"persistent": true,
		"data":       "This will be saved to disk",
	}

	cfg, err := manager.Create(ctx, "persistent-config", config)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Saved to disk: version %d\n", cfg.Meta.Version)

	// Config is now persisted in /tmp/configs/configs/persistent-config/v1.json
	// Journal is in /tmp/configs/journal.jsonl
}
