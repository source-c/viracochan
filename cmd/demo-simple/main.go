package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/source-c/viracochan"
)

func main() {
	ctx := context.Background()

	// Create storage (use file storage for persistence)
	storageDir := "./config-data"
	if len(os.Args) > 1 {
		storageDir = os.Args[1]
	}

	storage, err := viracochan.NewFileStorage(storageDir)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Create signer for cryptographic signatures
	signer, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal("Failed to create signer:", err)
	}

	fmt.Printf("=== Viracochan Configuration Manager ===\n")
	fmt.Printf("Storage directory: %s\n", storageDir)
	fmt.Printf("Public key: %s\n\n", signer.PublicKey()[:16]+"...")

	// Create manager with signing
	manager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}

	// Configuration ID
	configID := "app-settings"

	// Check if config exists
	existing, err := manager.GetLatest(ctx, configID)
	if err == nil {
		fmt.Printf("Found existing config version %d\n", existing.Meta.Version)

		// Verify signature
		if err := manager.Verify(existing, signer.PublicKey()); err != nil {
			fmt.Println("Warning: Signature verification failed:", err)
		} else {
			fmt.Println("Signature verified successfully")
		}

		// Show current content
		var content map[string]interface{}
		if err := json.Unmarshal(existing.Content, &content); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}
		fmt.Printf("Current content: %+v\n\n", content)

		// Update configuration
		content["last_updated"] = "2025-08-22"
		content["counter"] = getCounter(content) + 1

		updated, err := manager.Update(ctx, configID, content)
		if err != nil {
			log.Fatal("Failed to update config:", err)
		}

		fmt.Printf("Updated to version %d\n", updated.Meta.Version)
		fmt.Printf("Checksum: %s\n", updated.Meta.CS[:16]+"...")
		fmt.Printf("Previous: %s\n", updated.Meta.PrevCS[:16]+"...")
	} else {
		fmt.Println("Creating new configuration")

		// Create initial configuration
		config := map[string]interface{}{
			"app_name": "Viracochan Example",
			"version":  "1.0.0",
			"settings": map[string]interface{}{
				"debug":   false,
				"timeout": 30,
				"retries": 3,
			},
			"counter": 1,
		}

		cfg, err := manager.Create(ctx, configID, config)
		if err != nil {
			log.Fatal("Failed to create config:", err)
		}

		fmt.Printf("Created config version %d\n", cfg.Meta.Version)
		fmt.Printf("Checksum: %s\n", cfg.Meta.CS[:16]+"...")
		fmt.Printf("Signature: %s\n", cfg.Meta.Signature[:16]+"...")
	}

	// Show history
	fmt.Println("\nConfiguration history:")
	history, err := manager.GetHistory(ctx, configID)
	if err != nil {
		log.Fatal("Failed to get history:", err)
	}

	for _, cfg := range history {
		fmt.Printf("  v%d: %s (cs: %s)\n",
			cfg.Meta.Version,
			cfg.Meta.Time.Format("2006-01-02 15:04:05"),
			cfg.Meta.CS[:8]+"...")
	}

	// Validate chain
	if err := manager.ValidateChain(ctx, configID); err != nil {
		fmt.Println("\nChain validation failed:", err)
	} else {
		fmt.Println("\nChain validation successful")
	}

	// Export latest for backup
	exported, err := manager.Export(ctx, configID)
	if err != nil {
		log.Fatal("Failed to export:", err)
	}

	// Save to file
	exportFile := fmt.Sprintf("%s-export.json", configID)
	if err := os.WriteFile(exportFile, exported, 0o600); err != nil {
		log.Fatal("Failed to save export:", err)
	}

	fmt.Printf("\nExported to %s\n", exportFile)

	// Demonstrate reconstruction
	fmt.Println("\nReconstructing from journal...")
	reconstructed, err := manager.Reconstruct(ctx, configID)
	if err != nil {
		log.Fatal("Failed to reconstruct:", err)
	}

	fmt.Printf("Reconstructed version %d successfully\n", reconstructed.Meta.Version)
}

func getCounter(content map[string]interface{}) int {
	if v, ok := content["counter"]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
		if i, ok := v.(int); ok {
			return i
		}
	}
	return 0
}
