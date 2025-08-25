// Demo: Disaster Recovery and State Reconstruction
// Shows recovery from corrupted journals, scattered files, and out-of-order entries
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/source-c/viracochan"
)

func main() {
	var (
		dataDir = flag.String("dir", "./disaster-recovery-demo", "data directory")
		chaos   = flag.Bool("chaos", true, "enable chaos mode for testing")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*dataDir)

	fmt.Println("=== Disaster Recovery Demo ===")
	fmt.Println("Simulating various failure scenarios and recovery methods\n")

	// Phase 1: Create healthy system with configuration history
	fmt.Println("--- Phase 1: Building Configuration History ---")

	storage, err := viracochan.NewFileStorage(*dataDir)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	signer, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal("Failed to create signer:", err)
	}

	manager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
		viracochan.WithJournalPath("primary.journal"),
	)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}

	// Create configuration with multiple versions
	configID := "critical-config"
	versions := []map[string]interface{}{
		{
			"version": "1.0.0",
			"database": map[string]interface{}{
				"host": "localhost",
				"port": 5432,
			},
			"cache": map[string]interface{}{
				"enabled": false,
			},
		},
		{
			"version": "1.1.0",
			"database": map[string]interface{}{
				"host": "db.production.local",
				"port": 5432,
				"ssl":  true,
			},
			"cache": map[string]interface{}{
				"enabled": true,
				"ttl":     300,
			},
		},
		{
			"version": "1.2.0",
			"database": map[string]interface{}{
				"host":     "db.production.local",
				"port":     5432,
				"ssl":      true,
				"pool_min": 5,
				"pool_max": 20,
			},
			"cache": map[string]interface{}{
				"enabled": true,
				"ttl":     600,
				"backend": "redis",
			},
			"monitoring": map[string]interface{}{
				"enabled":  true,
				"interval": 60,
			},
		},
		{
			"version": "2.0.0",
			"database": map[string]interface{}{
				"primary": map[string]interface{}{
					"host": "db-primary.production.local",
					"port": 5432,
				},
				"replica": map[string]interface{}{
					"host": "db-replica.production.local",
					"port": 5432,
				},
				"ssl":      true,
				"pool_min": 10,
				"pool_max": 50,
			},
			"cache": map[string]interface{}{
				"enabled": true,
				"ttl":     1800,
				"backend": "redis-cluster",
			},
			"monitoring": map[string]interface{}{
				"enabled":  true,
				"interval": 30,
				"metrics":  []string{"cpu", "memory", "disk", "network"},
			},
		},
		{
			"version": "2.1.0",
			"database": map[string]interface{}{
				"primary": map[string]interface{}{
					"host": "db-primary.production.local",
					"port": 5432,
				},
				"replicas": []map[string]interface{}{
					{"host": "db-replica-1.production.local", "port": 5432, "weight": 1},
					{"host": "db-replica-2.production.local", "port": 5432, "weight": 2},
				},
				"ssl":      true,
				"pool_min": 10,
				"pool_max": 100,
			},
			"cache": map[string]interface{}{
				"enabled": true,
				"ttl":     3600,
				"backend": "redis-cluster",
				"nodes":   3,
			},
			"monitoring": map[string]interface{}{
				"enabled":  true,
				"interval": 30,
				"metrics":  []string{"cpu", "memory", "disk", "network", "latency"},
				"alerting": true,
			},
			"features": map[string]bool{
				"new_ui":        true,
				"beta_features": false,
				"debug_mode":    false,
			},
		},
	}

	var lastCfg *viracochan.Config
	for i, content := range versions {
		if i == 0 {
			lastCfg, err = manager.Create(ctx, configID, content)
		} else {
			lastCfg, err = manager.Update(ctx, configID, content)
		}
		if err != nil {
			log.Fatal("Failed to save version:", err)
		}
		fmt.Printf("Created v%d: %s (cs: %s)\n",
			lastCfg.Meta.Version,
			content["version"],
			lastCfg.Meta.CS[:8]+"...")
		time.Sleep(100 * time.Millisecond) // Ensure different timestamps
	}

	// Validate the healthy chain
	if err := manager.ValidateChain(ctx, configID); err != nil {
		log.Fatal("Initial chain validation failed:", err)
	}
	fmt.Println("✓ Initial configuration chain validated")

	// Phase 2: Simulate disasters
	fmt.Println("\n--- Phase 2: Simulating Disasters ---")

	if *chaos {
		// Disaster 1: Corrupt journal entries
		fmt.Println("\n[Disaster 1] Corrupting journal entries...")
		corruptJournal(filepath.Join(*dataDir, "primary.journal"))

		// Disaster 2: Delete random config files
		fmt.Println("[Disaster 2] Deleting random configuration files...")
		deleteRandomConfigs(*dataDir, configID)

		// Disaster 3: Create duplicate/conflicting entries
		fmt.Println("[Disaster 3] Creating duplicate journal entries...")
		createDuplicateEntries(storage, configID)

		// Disaster 4: Scramble file timestamps
		fmt.Println("[Disaster 4] Scrambling file timestamps...")
		scrambleTimestamps(*dataDir)
	}

	// Phase 3: Recovery attempts
	fmt.Println("\n--- Phase 3: Recovery Operations ---")

	// Recovery 1: Try to read with standard manager (should fail or give partial results)
	fmt.Println("\n[Recovery 1] Attempting standard read...")
	manager2, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
		viracochan.WithJournalPath("primary.journal"),
	)
	if err != nil {
		fmt.Printf("✗ Failed to create recovery manager: %v\n", err)
	} else {
		latest, err := manager2.GetLatest(ctx, configID)
		if err != nil {
			fmt.Printf("✗ Standard read failed: %v\n", err)
		} else {
			fmt.Printf("⚠ Partial read successful: v%d\n", latest.Meta.Version)
		}
	}

	// Recovery 2: Read journal directly and attempt resequencing
	fmt.Println("\n[Recovery 2] Direct journal reconstruction...")
	journal := viracochan.NewJournal(storage, "primary.journal")
	entries, err := journal.ReadAll(ctx)
	if err != nil {
		fmt.Printf("✗ Failed to read journal: %v\n", err)
	} else {
		fmt.Printf("Found %d journal entries (may include corrupted)\n", len(entries))

		// Filter valid entries
		validEntries := []*viracochan.JournalEntry{}
		for _, entry := range entries {
			if entry.ID == configID && entry.CS != "" {
				validEntries = append(validEntries, entry)
			}
		}
		fmt.Printf("Filtered to %d valid entries for %s\n", len(validEntries), configID)

		// Attempt resequencing
		ordered, err := journal.Resequence(validEntries)
		if err != nil {
			fmt.Printf("⚠ Resequence warning: %v\n", err)
			// Try to recover what we can
			if len(validEntries) > 0 {
				fmt.Println("Attempting partial recovery from available entries...")
			}
		} else {
			fmt.Printf("✓ Resequenced %d entries successfully\n", len(ordered))
		}
	}

	// Recovery 3: Scan for scattered config files
	fmt.Println("\n[Recovery 3] Scanning for scattered configuration files...")
	configStore := viracochan.NewConfigStorage(storage, "configs")
	foundVersions, err := configStore.ListVersions(ctx, configID)
	if err != nil {
		fmt.Printf("✗ Failed to list versions: %v\n", err)
	} else {
		fmt.Printf("Found %d config file versions\n", len(foundVersions))

		// Try to load each version
		validConfigs := []*viracochan.Config{}
		for _, v := range foundVersions {
			cfg, err := configStore.Load(ctx, configID, v)
			if err != nil {
				fmt.Printf("  ✗ v%d failed to load: %v\n", v, err)
			} else {
				if err := cfg.Validate(); err != nil {
					fmt.Printf("  ⚠ v%d loaded but invalid: %v\n", v, err)
				} else {
					fmt.Printf("  ✓ v%d loaded and valid\n", v)
					validConfigs = append(validConfigs, cfg)
				}
			}
		}

		if len(validConfigs) > 0 {
			fmt.Printf("Recovered %d valid configurations\n", len(validConfigs))
		}
	}

	// Recovery 4: Create new journal from recovered data
	fmt.Println("\n[Recovery 4] Rebuilding journal from recovered data...")
	recoveryJournal := viracochan.NewJournal(storage, "recovery.journal")

	// Collect all available configs
	allConfigs := make(map[uint64]*viracochan.Config)

	// From journal entries
	if entries != nil {
		for _, entry := range entries {
			if entry.Config != nil && entry.ID == configID {
				allConfigs[entry.Version] = entry.Config
			}
		}
	}

	// From scattered files
	if foundVersions != nil {
		for _, v := range foundVersions {
			if _, exists := allConfigs[v]; !exists {
				cfg, err := configStore.Load(ctx, configID, v)
				if err == nil && cfg.Validate() == nil {
					allConfigs[v] = cfg
				}
			}
		}
	}

	// Rebuild journal in order
	fmt.Printf("Rebuilding from %d unique versions\n", len(allConfigs))
	rebuiltCount := 0
	for v := uint64(1); v <= uint64(len(versions)); v++ {
		if cfg, ok := allConfigs[v]; ok {
			entry := &viracochan.JournalEntry{
				ID:        configID,
				Version:   cfg.Meta.Version,
				CS:        cfg.Meta.CS,
				PrevCS:    cfg.Meta.PrevCS,
				Time:      cfg.Meta.Time,
				Operation: "recovered",
				Config:    cfg,
			}
			if err := recoveryJournal.Append(ctx, entry); err != nil {
				fmt.Printf("  ✗ Failed to rebuild v%d: %v\n", v, err)
			} else {
				fmt.Printf("  ✓ Rebuilt v%d\n", v)
				rebuiltCount++
			}
		} else {
			fmt.Printf("  ✗ v%d missing\n", v)
		}
	}

	fmt.Printf("Rebuilt %d/%d versions in recovery journal\n", rebuiltCount, len(versions))

	// Recovery 5: Use recovery journal with new manager
	fmt.Println("\n[Recovery 5] Creating manager with recovery journal...")
	recoveryManager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
		viracochan.WithJournalPath("recovery.journal"),
	)
	if err != nil {
		fmt.Printf("✗ Failed to create recovery manager: %v\n", err)
	} else {
		// Attempt final reconstruction
		reconstructed, err := recoveryManager.Reconstruct(ctx, configID)
		if err != nil {
			fmt.Printf("✗ Reconstruction failed: %v\n", err)
		} else {
			fmt.Printf("✓ Successfully reconstructed to v%d\n", reconstructed.Meta.Version)

			// Verify the reconstructed config
			if err := reconstructed.Validate(); err != nil {
				fmt.Printf("✗ Reconstructed config invalid: %v\n", err)
			} else {
				fmt.Printf("✓ Reconstructed config validated\n")
			}

			// Verify signature if present
			if reconstructed.Meta.Signature != "" {
				if err := recoveryManager.Verify(reconstructed, signer.PublicKey()); err != nil {
					fmt.Printf("⚠ Signature verification failed: %v\n", err)
				} else {
					fmt.Printf("✓ Signature verified\n")
				}
			}

			// Show recovered content
			var content map[string]interface{}
			json.Unmarshal(reconstructed.Content, &content)
			fmt.Printf("\nRecovered configuration (version %s):\n", content["version"])
			prettyJSON, _ := json.MarshalIndent(content, "  ", "  ")
			fmt.Printf("  %s\n", prettyJSON)
		}
	}

	// Phase 4: Validation and reporting
	fmt.Println("\n--- Phase 4: Recovery Report ---")

	// Compare original vs recovered
	originalJournalSize := getFileSize(filepath.Join(*dataDir, "primary.journal"))
	recoveryJournalSize := getFileSize(filepath.Join(*dataDir, "recovery.journal"))

	fmt.Printf("\nJournal comparison:\n")
	fmt.Printf("  Original: %d bytes\n", originalJournalSize)
	fmt.Printf("  Recovery: %d bytes\n", recoveryJournalSize)

	// Count remaining files
	remainingConfigs := countFiles(filepath.Join(*dataDir, "configs", configID), "*.json")
	fmt.Printf("\nRemaining config files: %d/%d\n", remainingConfigs, len(versions))

	// Final status
	fmt.Println("\n=== Recovery Summary ===")
	if rebuiltCount == len(versions) {
		fmt.Println("✓ Full recovery successful - all versions recovered")
	} else if rebuiltCount > 0 {
		fmt.Printf("⚠ Partial recovery - recovered %d/%d versions\n", rebuiltCount, len(versions))
	} else {
		fmt.Println("✗ Recovery failed - no versions recovered")
	}

	fmt.Println("\n✓ Disaster recovery demo completed")
}

func corruptJournal(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) > 2 {
		// Corrupt a random line
		idx := rand.Intn(len(lines)-1) + 1
		if lines[idx] != "" {
			// Corrupt the JSON by removing closing brace
			lines[idx] = strings.TrimSuffix(lines[idx], "}")
		}
	}

	// Add some garbage data
	lines = append(lines, "CORRUPTED_DATA_HERE", "{invalid json}")

	os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

func deleteRandomConfigs(dataDir, configID string) {
	configPath := filepath.Join(dataDir, "configs", configID)
	files, err := filepath.Glob(filepath.Join(configPath, "v*.json"))
	if err != nil || len(files) == 0 {
		return
	}

	// Delete 30-50% of files randomly
	deleteCount := len(files) / 3
	if deleteCount == 0 {
		deleteCount = 1
	}

	for i := 0; i < deleteCount && i < len(files); i++ {
		idx := rand.Intn(len(files))
		os.Remove(files[idx])
		files = append(files[:idx], files[idx+1:]...)
	}
}

func createDuplicateEntries(storage viracochan.Storage, configID string) {
	ctx := context.Background()
	journal := viracochan.NewJournal(storage, "primary.journal")

	// Add duplicate entry with different checksum (will cause resequence issues)
	entry := &viracochan.JournalEntry{
		ID:        configID,
		Version:   2,
		CS:        "duplicate_checksum_xxx",
		PrevCS:    "some_prev_cs",
		Time:      time.Now(),
		Operation: "duplicate",
	}
	journal.Append(ctx, entry)
}

func scrambleTimestamps(dataDir string) {
	// This simulates clock skew or filesystem timestamp corruption
	files, _ := filepath.Glob(filepath.Join(dataDir, "configs", "*", "*.json"))
	for _, file := range files {
		randomTime := time.Now().Add(time.Duration(rand.Intn(3600)) * time.Second)
		os.Chtimes(file, randomTime, randomTime)
	}
}

func getFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func countFiles(dir, pattern string) int {
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return 0
	}
	return len(files)
}
