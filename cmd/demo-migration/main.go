// Demo: Storage Migration and Multi-Backend Support
// Shows migration between different storage backends with validation
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/source-c/viracochan"
)

// S3Storage simulates cloud storage with latency and potential failures
type S3Storage struct {
	viracochan.Storage
	latency     time.Duration
	failureRate float64
	mu          sync.RWMutex
	metrics     struct {
		reads    int
		writes   int
		failures int
	}
}

func NewS3Storage(base viracochan.Storage, latency time.Duration) *S3Storage {
	return &S3Storage{
		Storage:     base,
		latency:     latency,
		failureRate: 0.05, // 5% failure rate for demo
	}
}

func (s *S3Storage) Read(ctx context.Context, path string) ([]byte, error) {
	s.mu.Lock()
	s.metrics.reads++
	s.mu.Unlock()

	// Simulate network latency
	time.Sleep(s.latency)

	// Simulate occasional failures
	if time.Now().UnixNano()%20 == 0 {
		s.mu.Lock()
		s.metrics.failures++
		s.mu.Unlock()
		return nil, fmt.Errorf("S3 read timeout")
	}

	return s.Storage.Read(ctx, path)
}

func (s *S3Storage) Write(ctx context.Context, path string, data []byte) error {
	s.mu.Lock()
	s.metrics.writes++
	s.mu.Unlock()

	// Simulate network latency
	time.Sleep(s.latency * 2) // Writes are slower

	// Simulate occasional failures
	if time.Now().UnixNano()%25 == 0 {
		s.mu.Lock()
		s.metrics.failures++
		s.mu.Unlock()
		return fmt.Errorf("S3 write failed: service unavailable")
	}

	return s.Storage.Write(ctx, path, data)
}

func (s *S3Storage) GetMetrics() (reads, writes, failures int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.metrics.reads, s.metrics.writes, s.metrics.failures
}

// CachedStorage adds a caching layer
type CachedStorage struct {
	primary viracochan.Storage
	cache   *viracochan.MemoryStorage
	mu      sync.RWMutex
	hits    int
	misses  int
}

func NewCachedStorage(primary viracochan.Storage) *CachedStorage {
	return &CachedStorage{
		primary: primary,
		cache:   viracochan.NewMemoryStorage(),
	}
}

func (c *CachedStorage) Read(ctx context.Context, path string) ([]byte, error) {
	// Try cache first
	data, err := c.cache.Read(ctx, path)
	if err == nil {
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return data, nil
	}

	// Cache miss - read from primary
	c.mu.Lock()
	c.misses++
	c.mu.Unlock()

	data, err = c.primary.Read(ctx, path)
	if err != nil {
		return nil, err
	}

	// Update cache
	c.cache.Write(ctx, path, data)
	return data, nil
}

func (c *CachedStorage) Write(ctx context.Context, path string, data []byte) error {
	// Write through to both cache and primary
	if err := c.primary.Write(ctx, path, data); err != nil {
		return err
	}
	return c.cache.Write(ctx, path, data)
}

func (c *CachedStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return c.primary.List(ctx, prefix)
}

func (c *CachedStorage) Delete(ctx context.Context, path string) error {
	c.cache.Delete(ctx, path)
	return c.primary.Delete(ctx, path)
}

func (c *CachedStorage) Exists(ctx context.Context, path string) (bool, error) {
	// Check cache first
	if exists, _ := c.cache.Exists(ctx, path); exists {
		return true, nil
	}
	return c.primary.Exists(ctx, path)
}

func (c *CachedStorage) GetMetrics() (hits, misses int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses
}

func main() {
	var (
		sourceDir = flag.String("source", "./migration-source", "source storage directory")
		targetDir = flag.String("target", "./migration-target", "target storage directory")
		s3Dir     = flag.String("s3", "./migration-s3", "simulated S3 storage directory")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*sourceDir)
	os.RemoveAll(*targetDir)
	os.RemoveAll(*s3Dir)

	fmt.Println("=== Storage Migration Demo ===")
	fmt.Println("Demonstrating migration between different storage backends\n")

	// Phase 1: Create initial configuration in file storage
	fmt.Println("--- Phase 1: Creating Initial Configuration ---")

	sourceStorage, err := viracochan.NewFileStorage(*sourceDir)
	if err != nil {
		log.Fatal("Failed to create source storage:", err)
	}

	signer, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal("Failed to create signer:", err)
	}

	sourceManager, err := viracochan.NewManager(
		sourceStorage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create source manager:", err)
	}

	// Create complex configuration with history
	configID := "production-config"
	configs := []map[string]interface{}{
		{
			"environment": "development",
			"api": map[string]interface{}{
				"endpoint": "http://localhost:8080",
				"timeout":  30,
			},
		},
		{
			"environment": "staging",
			"api": map[string]interface{}{
				"endpoint":  "https://staging.example.com",
				"timeout":   60,
				"rateLimit": 100,
			},
			"database": map[string]interface{}{
				"host": "staging-db.example.com",
				"port": 5432,
			},
		},
		{
			"environment": "production",
			"api": map[string]interface{}{
				"endpoint":  "https://api.example.com",
				"timeout":   30,
				"rateLimit": 1000,
				"cache":     true,
			},
			"database": map[string]interface{}{
				"host": "prod-db.example.com",
				"port": 5432,
				"replicas": []string{
					"replica1.example.com",
					"replica2.example.com",
				},
			},
			"features": map[string]bool{
				"newUI": true,
				"beta":  false,
			},
		},
	}

	fmt.Println("Creating configuration versions:")
	for i, config := range configs {
		var cfg *viracochan.Config
		if i == 0 {
			cfg, err = sourceManager.Create(ctx, configID, config)
		} else {
			cfg, err = sourceManager.Update(ctx, configID, config)
		}
		if err != nil {
			log.Fatal("Failed to create config:", err)
		}
		fmt.Printf("  v%d: %s environment (cs: %s)\n",
			cfg.Meta.Version,
			config["environment"],
			cfg.Meta.CS[:8]+"...")
	}

	// Also create a secondary config
	secondaryID := "feature-flags"
	featureFlags := map[string]interface{}{
		"flags": map[string]bool{
			"darkMode":     true,
			"newDashboard": false,
			"aiAssistant":  true,
		},
		"rollout": map[string]interface{}{
			"percentage": 10,
			"regions":    []string{"us-east", "eu-west"},
		},
	}

	secondary, err := sourceManager.Create(ctx, secondaryID, featureFlags)
	if err != nil {
		log.Fatal("Failed to create secondary config:", err)
	}
	fmt.Printf("\nCreated secondary config: %s v%d\n", secondaryID, secondary.Meta.Version)

	// Validate source
	if err := sourceManager.ValidateChain(ctx, configID); err != nil {
		log.Fatal("Source validation failed:", err)
	}
	fmt.Println("✓ Source configuration validated")

	// Phase 2: Migrate to memory storage (fast, testing)
	fmt.Println("\n--- Phase 2: Migration to Memory Storage ---")

	memStorage := viracochan.NewMemoryStorage()
	if err := migrateStorage(ctx, sourceStorage, memStorage, "memory"); err != nil {
		log.Fatal("Memory migration failed:", err)
	}

	// Verify migration
	memManager, err := viracochan.NewManager(
		memStorage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create memory manager:", err)
	}

	memConfig, err := memManager.GetLatest(ctx, configID)
	if err != nil {
		log.Fatal("Failed to read from memory:", err)
	}
	fmt.Printf("✓ Memory storage verified: v%d available\n", memConfig.Meta.Version)

	// Phase 3: Migrate to simulated S3 (with latency and failures)
	fmt.Println("\n--- Phase 3: Migration to Simulated S3 Storage ---")

	s3Base, err := viracochan.NewFileStorage(*s3Dir)
	if err != nil {
		log.Fatal("Failed to create S3 base:", err)
	}

	s3Storage := NewS3Storage(s3Base, 50*time.Millisecond)

	fmt.Println("Migrating with simulated network conditions...")
	startTime := time.Now()

	retryCount := 0
	for retryCount < 3 {
		if err := migrateStorage(ctx, memStorage, s3Storage, "S3"); err != nil {
			retryCount++
			fmt.Printf("  Retry %d/3 due to: %v\n", retryCount, err)
			time.Sleep(500 * time.Millisecond)
		} else {
			break
		}
	}

	elapsed := time.Since(startTime)
	reads, writes, failures := s3Storage.GetMetrics()
	fmt.Printf("S3 migration completed in %v\n", elapsed)
	fmt.Printf("  Operations: %d reads, %d writes, %d failures\n", reads, writes, failures)

	// Phase 4: Add caching layer
	fmt.Println("\n--- Phase 4: Adding Cache Layer ---")

	cachedS3 := NewCachedStorage(s3Storage)
	cachedManager, err := viracochan.NewManager(
		cachedS3,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create cached manager:", err)
	}

	// Perform multiple reads to demonstrate caching
	fmt.Println("Testing cache performance:")
	for i := 0; i < 5; i++ {
		start := time.Now()
		cfg, err := cachedManager.GetLatest(ctx, configID)
		if err != nil {
			fmt.Printf("  Read %d failed: %v\n", i+1, err)
		} else {
			fmt.Printf("  Read %d: v%d in %v\n", i+1, cfg.Meta.Version, time.Since(start))
		}
	}

	hits, misses := cachedS3.GetMetrics()
	fmt.Printf("Cache statistics: %d hits, %d misses (%.1f%% hit rate)\n",
		hits, misses, float64(hits)/float64(hits+misses)*100)

	// Phase 5: Migrate to file storage with validation
	fmt.Println("\n--- Phase 5: Final Migration to File Storage ---")

	targetStorage, err := viracochan.NewFileStorage(*targetDir)
	if err != nil {
		log.Fatal("Failed to create target storage:", err)
	}

	// Perform validated migration
	if err := validateAndMigrate(ctx, cachedS3, targetStorage, signer); err != nil {
		log.Fatal("Final migration failed:", err)
	}

	// Verify final storage
	targetManager, err := viracochan.NewManager(
		targetStorage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create target manager:", err)
	}

	// Validate all configurations
	fmt.Println("\n--- Final Validation ---")

	configIDs := []string{configID, secondaryID}
	for _, id := range configIDs {
		fmt.Printf("\nValidating %s:\n", id)

		// Check chain integrity
		if err := targetManager.ValidateChain(ctx, id); err != nil {
			fmt.Printf("  ✗ Chain validation failed: %v\n", err)
		} else {
			fmt.Printf("  ✓ Chain validated\n")
		}

		// Get history
		history, err := targetManager.GetHistory(ctx, id)
		if err != nil {
			fmt.Printf("  ✗ Failed to get history: %v\n", err)
		} else {
			fmt.Printf("  ✓ %d versions available\n", len(history))

			// Verify signatures
			validSigs := 0
			for _, cfg := range history {
				if cfg.Meta.Signature != "" {
					if err := targetManager.Verify(cfg, signer.PublicKey()); err == nil {
						validSigs++
					}
				}
			}
			fmt.Printf("  ✓ %d/%d signatures verified\n", validSigs, len(history))
		}

		// Show latest content
		latest, err := targetManager.GetLatest(ctx, id)
		if err != nil {
			fmt.Printf("  ✗ Failed to get latest: %v\n", err)
		} else {
			var content map[string]interface{}
			json.Unmarshal(latest.Content, &content)
			fmt.Printf("  ✓ Latest version %d loaded\n", latest.Meta.Version)
		}
	}

	// Phase 6: Cross-storage verification
	fmt.Println("\n--- Cross-Storage Verification ---")

	sourceLatest, _ := sourceManager.GetLatest(ctx, configID)
	targetLatest, _ := targetManager.GetLatest(ctx, configID)

	if sourceLatest.Meta.CS == targetLatest.Meta.CS {
		fmt.Println("✓ Source and target checksums match")
	} else {
		fmt.Println("✗ Checksum mismatch between source and target!")
	}

	// Storage statistics
	fmt.Println("\n=== Migration Statistics ===")

	sourceFiles := countStorageFiles(*sourceDir)
	s3Files := countStorageFiles(*s3Dir)
	targetFiles := countStorageFiles(*targetDir)

	fmt.Printf("Source storage: %d files\n", sourceFiles)
	fmt.Printf("Memory storage: in-memory\n")
	fmt.Printf("S3 storage: %d files\n", s3Files)
	fmt.Printf("Target storage: %d files\n", targetFiles)

	fmt.Println("\n✓ Storage migration demo completed successfully")
}

func migrateStorage(ctx context.Context, source, target viracochan.Storage, targetName string) error {
	fmt.Printf("Migrating to %s storage...\n", targetName)

	// List all files from source
	files, err := source.List(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to list source files: %w", err)
	}

	fmt.Printf("  Found %d files to migrate\n", len(files))

	// Copy each file
	migrated := 0
	for _, file := range files {
		data, err := source.Read(ctx, file)
		if err != nil {
			fmt.Printf("  ⚠ Failed to read %s: %v\n", file, err)
			continue
		}

		if err := target.Write(ctx, file, data); err != nil {
			fmt.Printf("  ⚠ Failed to write %s: %v\n", file, err)
			continue
		}

		migrated++
		if migrated%10 == 0 {
			fmt.Printf("  Migrated %d/%d files\n", migrated, len(files))
		}
	}

	fmt.Printf("  ✓ Migrated %d/%d files successfully\n", migrated, len(files))

	if migrated < len(files) {
		return fmt.Errorf("incomplete migration: %d/%d files", migrated, len(files))
	}

	return nil
}

func validateAndMigrate(ctx context.Context, source, target viracochan.Storage, signer *viracochan.Signer) error {
	fmt.Println("Performing validated migration...")

	// List all files
	files, err := source.List(ctx, "")
	if err != nil {
		return err
	}

	// Separate configs and journal entries
	var configs []string
	var journals []string
	for _, file := range files {
		if strings.Contains(file, "/configs/") {
			configs = append(configs, file)
		} else if strings.HasSuffix(file, ".jsonl") || strings.HasSuffix(file, ".journal") {
			journals = append(journals, file)
		}
	}

	fmt.Printf("  Found %d config files and %d journal files\n", len(configs), len(journals))

	// Migrate and validate configs
	validConfigs := 0
	for _, file := range configs {
		data, err := source.Read(ctx, file)
		if err != nil {
			continue
		}

		// Try to parse and validate
		var cfg viracochan.Config
		if err := json.Unmarshal(data, &cfg); err == nil {
			if err := cfg.Validate(); err == nil {
				if err := target.Write(ctx, file, data); err == nil {
					validConfigs++
				}
			}
		}
	}

	fmt.Printf("  ✓ Migrated %d valid configs\n", validConfigs)

	// Migrate journals
	for _, file := range journals {
		data, err := source.Read(ctx, file)
		if err != nil {
			continue
		}
		target.Write(ctx, file, data)
	}

	fmt.Printf("  ✓ Migrated %d journal files\n", len(journals))

	return nil
}

func countStorageFiles(dir string) int {
	count := 0
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			count++
		}
		return nil
	})
	return count
}
