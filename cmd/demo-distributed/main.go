// Demo: Distributed Configuration Management
// Shows multi-node configuration synchronization with cryptographic signatures
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/source-c/viracochan"
)

type Node struct {
	ID      string
	Storage viracochan.Storage
	Manager *viracochan.Manager
	Signer  *viracochan.Signer
}

func main() {
	var (
		nodeCount = flag.Int("nodes", 3, "number of nodes to simulate")
		baseDir   = flag.String("dir", "./distributed-demo", "base directory for nodes")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*baseDir)

	fmt.Println("=== Distributed Configuration Management Demo ===")
	fmt.Printf("Simulating %d nodes with signature verification\n\n", *nodeCount)

	// Create master signer for the authority
	masterSigner, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal("Failed to create master signer:", err)
	}
	fmt.Printf("Master Public Key: %s\n\n", masterSigner.PublicKey()[:16]+"...")

	// Create nodes
	nodes := make([]*Node, *nodeCount)
	for i := 0; i < *nodeCount; i++ {
		node, err := createNode(ctx, *baseDir, i, masterSigner)
		if err != nil {
			log.Fatal("Failed to create node:", err)
		}
		nodes[i] = node
		fmt.Printf("Node %d initialized at %s\n", i, filepath.Join(*baseDir, node.ID))
	}

	// Initial configuration on master node
	fmt.Println("\n--- Creating Initial Configuration on Master Node ---")
	masterConfig := map[string]interface{}{
		"cluster": map[string]interface{}{
			"name":     "production",
			"region":   "us-east-1",
			"replicas": 3,
		},
		"database": map[string]interface{}{
			"host":      "db.example.com",
			"port":      5432,
			"pool_size": 20,
		},
		"features": map[string]bool{
			"cache":     true,
			"analytics": false,
			"beta":      false,
		},
	}

	cfg, err := nodes[0].Manager.Create(ctx, "cluster-config", masterConfig)
	if err != nil {
		log.Fatal("Failed to create config:", err)
	}
	fmt.Printf("Created v%d with signature %s\n", cfg.Meta.Version, cfg.Meta.Signature[:16]+"...")

	// Simulate configuration updates
	fmt.Println("\n--- Simulating Configuration Updates ---")
	for i := 1; i <= 3; i++ {
		time.Sleep(100 * time.Millisecond)

		// Update configuration
		var current map[string]interface{}
		if err := json.Unmarshal(cfg.Content, &current); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}

		// Modify based on iteration
		switch i {
		case 1:
			current["features"].(map[string]interface{})["analytics"] = true
			fmt.Println("Update 1: Enabling analytics feature")
		case 2:
			current["database"].(map[string]interface{})["pool_size"] = 50.0
			fmt.Println("Update 2: Increasing database pool size to 50")
		case 3:
			current["cluster"].(map[string]interface{})["replicas"] = 5.0
			current["features"].(map[string]interface{})["beta"] = true
			fmt.Println("Update 3: Scaling replicas to 5, enabling beta features")
		}

		cfg, err = nodes[0].Manager.Update(ctx, "cluster-config", current)
		if err != nil {
			log.Fatal("Failed to update:", err)
		}
		fmt.Printf("  → v%d created at %s\n", cfg.Meta.Version, cfg.Meta.Time.Format("15:04:05.000"))
	}

	// Export from master node
	fmt.Println("\n--- Exporting Configuration from Master ---")
	_, err = nodes[0].Manager.Export(ctx, "cluster-config")
	if err != nil {
		log.Fatal("Failed to export:", err)
	}

	// Save complete history
	history, err := nodes[0].Manager.GetHistory(ctx, "cluster-config")
	if err != nil {
		log.Fatal("Failed to get history:", err)
	}

	allVersions, err := json.Marshal(history)
	if err != nil {
		log.Fatal("Failed to marshal history:", err)
	}

	fmt.Printf("Exported %d versions (%d bytes)\n", len(history), len(allVersions))

	// Distribute to other nodes with verification
	fmt.Println("\n--- Distributing to Other Nodes ---")
	for i := 1; i < len(nodes); i++ {
		fmt.Printf("\nNode %d:\n", i)

		// Import the complete history
		var configs []*viracochan.Config
		if err := json.Unmarshal(allVersions, &configs); err != nil {
			log.Fatal("Failed to unmarshal:", err)
		}

		// Import each version in order
		for _, cfg := range configs {
			data, _ := json.Marshal(cfg)
			configID := fmt.Sprintf("cluster-config-v%d", cfg.Meta.Version)

			if err := nodes[i].Manager.Import(ctx, configID, data); err != nil {
				fmt.Printf("  ✗ Failed to import v%d: %v\n", cfg.Meta.Version, err)
				continue
			}

			// Verify signature
			if err := nodes[i].Manager.Verify(cfg, masterSigner.PublicKey()); err != nil {
				fmt.Printf("  ✗ v%d signature verification failed: %v\n", cfg.Meta.Version, err)
			} else {
				fmt.Printf("  ✓ v%d imported and verified (cs: %s)\n",
					cfg.Meta.Version, cfg.Meta.CS[:8]+"...")
			}
		}

		// Reconstruct the main config from imported versions
		lastVersion := configs[len(configs)-1]
		data, _ := json.Marshal(lastVersion)
		if err := nodes[i].Manager.Import(ctx, "cluster-config", data); err != nil {
			log.Fatal("Failed to import main config:", err)
		}
	}

	// Verify chain integrity on all nodes
	fmt.Println("\n--- Verifying Chain Integrity ---")
	for i, node := range nodes {
		fmt.Printf("Node %d: ", i)

		// Get the latest config
		latest, err := node.Manager.GetLatest(ctx, "cluster-config")
		if err != nil {
			fmt.Printf("✗ Failed to get latest: %v\n", err)
			continue
		}

		// Verify signature
		if err := node.Manager.Verify(latest, masterSigner.PublicKey()); err != nil {
			fmt.Printf("✗ Signature verification failed: %v\n", err)
		} else {
			fmt.Printf("✓ v%d verified (signature: %s)\n",
				latest.Meta.Version, latest.Meta.Signature[:8]+"...")
		}
	}

	// Simulate node recovery
	fmt.Println("\n--- Simulating Node Recovery ---")
	fmt.Println("Node 1 loses some data, attempting reconstruction...")

	// Delete some config files from node 1
	node1Dir := filepath.Join(*baseDir, nodes[1].ID, "configs", "cluster-config")
	files, _ := filepath.Glob(filepath.Join(node1Dir, "v*.json"))
	if len(files) > 2 {
		// Delete middle versions to simulate partial data loss
		for i := 1; i < len(files)-1; i++ {
			os.Remove(files[i])
		}
		fmt.Printf("Deleted %d intermediate versions\n", len(files)-2)
	}

	// Attempt reconstruction
	reconstructed, err := nodes[1].Manager.Reconstruct(ctx, "cluster-config")
	if err != nil {
		fmt.Printf("✗ Reconstruction failed: %v\n", err)
	} else {
		fmt.Printf("✓ Reconstructed to v%d from journal\n", reconstructed.Meta.Version)

		// Verify reconstructed config
		if err := nodes[1].Manager.Verify(reconstructed, masterSigner.PublicKey()); err != nil {
			fmt.Printf("✗ Reconstructed config signature invalid: %v\n", err)
		} else {
			fmt.Printf("✓ Reconstructed config signature valid\n")
		}
	}

	// Demonstrate watch functionality
	fmt.Println("\n--- Setting up Configuration Watch ---")
	watchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Start watching on last node
	watchNode := nodes[len(nodes)-1]
	ch, err := watchNode.Manager.Watch(watchCtx, "cluster-config", 500*time.Millisecond)
	if err != nil {
		log.Printf("Failed to setup watch: %v", err)
		cancel()
		return
	}

	fmt.Printf("%s watching for changes...\n", watchNode.ID)

	// Make an update on master after a delay
	go func() {
		time.Sleep(1 * time.Second)
		fmt.Println("Master node making emergency update...")

		var current map[string]interface{}
		latest, _ := nodes[0].Manager.GetLatest(ctx, "cluster-config")
		if err := json.Unmarshal(latest.Content, &current); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}

		current["emergency"] = map[string]interface{}{
			"maintenance": true,
			"reason":      "security patch",
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}

		if _, err := nodes[0].Manager.Update(ctx, "cluster-config", current); err != nil {
			log.Printf("Failed to update cluster config: %v", err)
		}
	}()

	// Wait for update
	select {
	case updated := <-ch:
		fmt.Printf("✓ %s detected update to v%d\n", watchNode.ID, updated.Meta.Version)

		var content map[string]interface{}
		if err := json.Unmarshal(updated.Content, &content); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}
		if emergency, ok := content["emergency"]; ok {
			fmt.Printf("  Emergency update: %v\n", emergency)
		}
	case <-watchCtx.Done():
		fmt.Println("Watch timeout")
	}

	// Final statistics
	fmt.Println("\n=== Final Statistics ===")
	for i, node := range nodes {
		entries, _ := node.Manager.GetHistory(ctx, "cluster-config")

		journalPath := filepath.Join(*baseDir, node.ID, "journal.jsonl")
		journalInfo, _ := os.Stat(journalPath)
		journalSize := int64(0)
		if journalInfo != nil {
			journalSize = journalInfo.Size()
		}

		fmt.Printf("Node %d: %d versions, journal size: %d bytes\n",
			i, len(entries), journalSize)
	}

	fmt.Println("\n✓ Distributed configuration demo completed successfully")
}

func createNode(ctx context.Context, baseDir string, index int, signer *viracochan.Signer) (*Node, error) {
	nodeID := fmt.Sprintf("node-%d", index)
	nodeDir := filepath.Join(baseDir, nodeID)

	storage, err := viracochan.NewFileStorage(nodeDir)
	if err != nil {
		return nil, err
	}

	// All nodes use the same signer for this demo (representing a single authority)
	// In production, each node might have its own signer for local operations
	manager, err := viracochan.NewManager(
		storage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		return nil, err
	}

	return &Node{
		ID:      nodeID,
		Storage: storage,
		Manager: manager,
		Signer:  signer,
	}, nil
}
