// Demo: Concurrent Operations and Conflict Resolution
// Shows handling of concurrent updates, watches, and conflict resolution strategies
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/source-c/viracochan"
)

type Worker struct {
	ID        int
	Name      string
	Manager   *viracochan.Manager
	Signer    *viracochan.Signer
	Updates   int32
	Conflicts int32
	Resolved  int32
}

type ConflictResolver struct {
	strategy  string // "last-write-wins", "merge", "manual"
	mu        sync.Mutex
	conflicts []ConflictRecord
}

type ConflictRecord struct {
	Timestamp  time.Time
	Worker1    string
	Worker2    string
	Version1   uint64
	Version2   uint64
	Resolution string
}

func NewConflictResolver(strategy string) *ConflictResolver {
	return &ConflictResolver{
		strategy:  strategy,
		conflicts: []ConflictRecord{},
	}
}

func (cr *ConflictResolver) Resolve(w1, w2 *Worker, cfg1, cfg2 *viracochan.Config) (*viracochan.Config, string) {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	var resolution string
	var winner *viracochan.Config

	switch cr.strategy {
	case "last-write-wins":
		if cfg1.Meta.Time.After(cfg2.Meta.Time) {
			winner = cfg1
			resolution = fmt.Sprintf("%s wins (newer)", w1.Name)
		} else {
			winner = cfg2
			resolution = fmt.Sprintf("%s wins (newer)", w2.Name)
		}

	case "merge":
		// Simple merge strategy: combine both configs
		var content1, content2 map[string]interface{}
		if err := json.Unmarshal(cfg1.Content, &content1); err != nil {
			log.Printf("Failed to unmarshal cfg1 content: %v", err)
		}
		if err := json.Unmarshal(cfg2.Content, &content2); err != nil {
			log.Printf("Failed to unmarshal cfg2 content: %v", err)
		}

		// Merge content2 into content1
		for k, v := range content2 {
			content1[k] = v
		}

		// Create new config with merged content
		winner = &viracochan.Config{
			Meta:    cfg1.Meta,
			Content: mustMarshal(content1),
		}
		if err := winner.UpdateMeta(); err != nil {
			log.Printf("Failed to update meta: %v", err)
		}
		resolution = "Merged both changes"

	case "manual":
		// In real system, this would prompt user
		// For demo, randomly pick one
		// #nosec G404 - weak RNG is fine for demo conflict resolution
		if rand.Intn(2) == 0 {
			winner = cfg1
			resolution = fmt.Sprintf("%s selected (manual)", w1.Name)
		} else {
			winner = cfg2
			resolution = fmt.Sprintf("%s selected (manual)", w2.Name)
		}

	default:
		winner = cfg1
		resolution = "Default: first wins"
	}

	cr.conflicts = append(cr.conflicts, ConflictRecord{
		Timestamp:  time.Now(),
		Worker1:    w1.Name,
		Worker2:    w2.Name,
		Version1:   cfg1.Meta.Version,
		Version2:   cfg2.Meta.Version,
		Resolution: resolution,
	})

	return winner, resolution
}

func (cr *ConflictResolver) Report() {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	fmt.Printf("\n=== Conflict Resolution Report ===\n")
	fmt.Printf("Strategy: %s\n", cr.strategy)
	fmt.Printf("Total Conflicts: %d\n\n", len(cr.conflicts))

	for i, c := range cr.conflicts {
		fmt.Printf("Conflict %d:\n", i+1)
		fmt.Printf("  Time: %s\n", c.Timestamp.Format("15:04:05.000"))
		fmt.Printf("  Workers: %s (v%d) vs %s (v%d)\n",
			c.Worker1, c.Version1, c.Worker2, c.Version2)
		fmt.Printf("  Resolution: %s\n\n", c.Resolution)
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, _ := json.Marshal(v)
	return json.RawMessage(data)
}

func main() {
	var (
		dataDir    = flag.String("dir", "./concurrent-demo", "data directory")
		workers    = flag.Int("workers", 5, "number of concurrent workers")
		duration   = flag.Duration("duration", 10*time.Second, "test duration")
		strategy   = flag.String("strategy", "merge", "conflict resolution strategy")
		updateRate = flag.Duration("rate", 200*time.Millisecond, "update rate per worker")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*dataDir)

	fmt.Println("=== Concurrent Operations Demo ===")
	fmt.Printf("Workers: %d, Duration: %v, Strategy: %s\n\n",
		*workers, *duration, *strategy)

	// Initialize storage
	storage, err := viracochan.NewFileStorage(*dataDir)
	if err != nil {
		log.Fatal("Failed to create storage:", err)
	}

	// Create conflict resolver
	resolver := NewConflictResolver(*strategy)

	// Phase 1: Initialize workers
	fmt.Println("--- Phase 1: Initializing Workers ---")

	workerList := make([]*Worker, *workers)
	for i := 0; i < *workers; i++ {
		signer, err := viracochan.NewSigner()
		if err != nil {
			log.Fatal("Failed to create signer:", err)
		}

		manager, err := viracochan.NewManager(
			storage,
			viracochan.WithSigner(signer),
			viracochan.WithJournalPath(fmt.Sprintf("worker-%d.journal", i)),
		)
		if err != nil {
			log.Fatal("Failed to create manager:", err)
		}

		workerList[i] = &Worker{
			ID:      i,
			Name:    fmt.Sprintf("Worker-%d", i),
			Manager: manager,
			Signer:  signer,
		}

		fmt.Printf("  %s initialized (key: %s)\n",
			workerList[i].Name, signer.PublicKey()[:8]+"...")
	}

	// Phase 2: Create initial configuration
	fmt.Println("\n--- Phase 2: Initial Configuration ---")

	configID := "shared-config"
	initialConfig := map[string]interface{}{
		"version":   "1.0.0",
		"counters":  map[string]int{},
		"workers":   map[string]interface{}{},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Worker 0 creates initial config
	cfg, err := workerList[0].Manager.Create(ctx, configID, initialConfig)
	if err != nil {
		log.Fatal("Failed to create initial config:", err)
	}

	fmt.Printf("Initial config v%d created by %s\n", cfg.Meta.Version, workerList[0].Name)

	// Phase 3: Setup watchers
	fmt.Println("\n--- Phase 3: Setting Up Watchers ---")

	watchCtx, watchCancel := context.WithCancel(ctx)
	defer watchCancel()

	// Each worker watches for changes
	watchers := make([]<-chan *viracochan.Config, *workers)
	for i, worker := range workerList {
		ch, err := worker.Manager.Watch(watchCtx, configID, 100*time.Millisecond)
		if err != nil {
			log.Printf("Failed to setup watch: %v", err)
			watchCancel()
			return
		}
		watchers[i] = ch

		// Start watcher goroutine
		go func(w *Worker, ch <-chan *viracochan.Config) {
			for cfg := range ch {
				fmt.Printf("  [WATCH] %s detected update to v%d\n",
					w.Name, cfg.Meta.Version)
			}
		}(worker, ch)
	}

	fmt.Printf("✓ %d watchers active\n", *workers)

	// Phase 4: Concurrent updates
	fmt.Println("\n--- Phase 4: Concurrent Updates ---")

	updateCtx, updateCancel := context.WithTimeout(ctx, *duration)
	defer updateCancel()

	var wg sync.WaitGroup
	conflictChan := make(chan struct{}, 100)

	// Start worker goroutines
	for _, worker := range workerList {
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()

			ticker := time.NewTicker(*updateRate)
			defer ticker.Stop()

			for {
				select {
				case <-updateCtx.Done():
					return
				case <-ticker.C:
					// Attempt update
					if err := performUpdate(ctx, w, configID, conflictChan); err != nil {
						atomic.AddInt32(&w.Conflicts, 1)
					} else {
						atomic.AddInt32(&w.Updates, 1)
					}
				}
			}
		}(worker)
	}

	// Monitor conflicts
	go func() {
		for range conflictChan {
			// Count conflicts
		}
	}()

	// Progress monitor
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		start := time.Now()
		for {
			select {
			case <-updateCtx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(start)
				totalUpdates := int32(0)
				totalConflicts := int32(0)

				for _, w := range workerList {
					totalUpdates += atomic.LoadInt32(&w.Updates)
					totalConflicts += atomic.LoadInt32(&w.Conflicts)
				}

				fmt.Printf("[%s] Updates: %d, Conflicts: %d, Rate: %.1f/s\n",
					elapsed.Round(time.Second),
					totalUpdates,
					totalConflicts,
					float64(totalUpdates)/elapsed.Seconds())
			}
		}
	}()

	// Wait for completion
	wg.Wait()

	// Phase 5: Conflict resolution demonstration
	fmt.Println("\n--- Phase 5: Conflict Resolution ---")

	// Simulate direct conflict
	fmt.Println("\nSimulating direct conflict between Worker-0 and Worker-1...")

	// Both workers read current state
	current0, _ := workerList[0].Manager.GetLatest(ctx, configID)
	current1, _ := workerList[1].Manager.GetLatest(ctx, configID)

	// Both prepare updates
	var content0, content1 map[string]interface{}
	if err := json.Unmarshal(current0.Content, &content0); err != nil {
		log.Printf("Failed to unmarshal content0: %v", err)
	}
	if err := json.Unmarshal(current1.Content, &content1); err != nil {
		log.Printf("Failed to unmarshal content1: %v", err)
	}

	content0["conflict_test"] = "worker0_value"
	content1["conflict_test"] = "worker1_value"

	// Worker 0 updates first
	cfg0, err := workerList[0].Manager.Update(ctx, configID, content0)
	if err != nil {
		fmt.Printf("Worker-0 update failed: %v\n", err)
	} else {
		fmt.Printf("Worker-0 updated to v%d\n", cfg0.Meta.Version)
	}

	// Worker 1 tries to update (will fail due to version conflict)
	cfg1, err := workerList[1].Manager.Update(ctx, configID, content1)
	if err != nil {
		fmt.Printf("Worker-1 update failed (expected): %v\n", err)

		// Resolve conflict
		latest, _ := workerList[1].Manager.GetLatest(ctx, configID)
		resolved, resolution := resolver.Resolve(workerList[0], workerList[1], latest, &viracochan.Config{
			Meta:    current1.Meta,
			Content: mustMarshal(content1),
		})

		fmt.Printf("Conflict resolved: %s\n", resolution)

		// Apply resolution
		var resolvedContent map[string]interface{}
		if err := json.Unmarshal(resolved.Content, &resolvedContent); err != nil {
			log.Printf("Failed to unmarshal resolved content: %v", err)
		}
		cfg1, err = workerList[1].Manager.Update(ctx, configID, resolvedContent)
		if err == nil {
			fmt.Printf("Resolution applied as v%d\n", cfg1.Meta.Version)
			atomic.AddInt32(&workerList[1].Resolved, 1)
		}
	} else {
		fmt.Printf("Worker-1 updated to v%d\n", cfg1.Meta.Version)
	}

	// Phase 6: Consistency check
	fmt.Println("\n--- Phase 6: Consistency Verification ---")

	time.Sleep(500 * time.Millisecond) // Allow propagation

	fmt.Println("\nFinal state across workers:")
	versions := make(map[uint64]int)
	checksums := make(map[string]int)

	for _, worker := range workerList {
		latest, err := worker.Manager.GetLatest(ctx, configID)
		if err != nil {
			fmt.Printf("  %s: ERROR - %v\n", worker.Name, err)
			continue
		}

		versions[latest.Meta.Version]++
		checksums[latest.Meta.CS]++

		var content map[string]interface{}
		if err := json.Unmarshal(latest.Content, &content); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}

		// Count worker-specific updates
		workerKey := fmt.Sprintf("worker_%d", worker.ID)
		workerUpdates := 0
		if counters, ok := content["counters"].(map[string]interface{}); ok {
			if count, ok := counters[workerKey].(float64); ok {
				workerUpdates = int(count)
			}
		}

		fmt.Printf("  %s: v%d (cs: %s, updates: %d)\n",
			worker.Name,
			latest.Meta.Version,
			latest.Meta.CS[:8]+"...",
			workerUpdates)
	}

	// Check consistency
	fmt.Println("\nConsistency Analysis:")
	if len(versions) == 1 {
		fmt.Printf("✓ All workers on same version\n")
	} else {
		fmt.Printf("⚠ Version divergence detected: %d different versions\n", len(versions))
		for v, count := range versions {
			fmt.Printf("  v%d: %d workers\n", v, count)
		}
	}

	if len(checksums) == 1 {
		fmt.Printf("✓ All workers have same checksum\n")
	} else {
		fmt.Printf("⚠ Checksum divergence detected: %d different checksums\n", len(checksums))
	}

	// Phase 7: Chain validation
	fmt.Println("\n--- Phase 7: Chain Validation ---")

	for i, worker := range workerList {
		err := worker.Manager.ValidateChain(ctx, configID)
		if err != nil {
			fmt.Printf("  %s: ✗ Chain invalid - %v\n", worker.Name, err)
		} else {
			fmt.Printf("  %s: ✓ Chain valid\n", worker.Name)
		}

		if i == 0 {
			// Show chain for first worker
			history, _ := worker.Manager.GetHistory(ctx, configID)
			fmt.Printf("    Chain length: %d versions\n", len(history))
		}
	}

	// Phase 8: Statistics
	fmt.Println("\n=== Final Statistics ===")

	totalUpdates := int32(0)
	totalConflicts := int32(0)
	totalResolved := int32(0)

	for _, w := range workerList {
		updates := atomic.LoadInt32(&w.Updates)
		conflicts := atomic.LoadInt32(&w.Conflicts)
		resolved := atomic.LoadInt32(&w.Resolved)

		totalUpdates += updates
		totalConflicts += conflicts
		totalResolved += resolved

		fmt.Printf("%s: %d updates, %d conflicts, %d resolved\n",
			w.Name, updates, conflicts, resolved)
	}

	fmt.Printf("\nTotals:\n")
	fmt.Printf("  Updates: %d\n", totalUpdates)
	fmt.Printf("  Conflicts: %d\n", totalConflicts)
	fmt.Printf("  Resolved: %d\n", totalResolved)
	fmt.Printf("  Success Rate: %.1f%%\n",
		float64(totalUpdates)/float64(totalUpdates+totalConflicts)*100)

	// Show conflict resolution report
	resolver.Report()

	// Cancel watchers
	watchCancel()
	time.Sleep(200 * time.Millisecond) // Allow goroutines to clean up

	fmt.Println("\n✓ Concurrent operations demo completed")
}

func performUpdate(ctx context.Context, w *Worker, configID string, conflictChan chan<- struct{}) error {
	// Get current config
	current, err := w.Manager.GetLatest(ctx, configID)
	if err != nil {
		return err
	}

	// Parse content
	var content map[string]interface{}
	if err := json.Unmarshal(current.Content, &content); err != nil {
		return err
	}

	// Update worker-specific counter
	if content["counters"] == nil {
		content["counters"] = make(map[string]interface{})
	}
	counters := content["counters"].(map[string]interface{})

	workerKey := fmt.Sprintf("worker_%d", w.ID)
	currentCount := float64(0)
	if v, ok := counters[workerKey]; ok {
		if f, ok := v.(float64); ok {
			currentCount = f
		}
	}
	counters[workerKey] = currentCount + 1

	// Add worker-specific data
	if content["workers"] == nil {
		content["workers"] = make(map[string]interface{})
	}
	workers := content["workers"].(map[string]interface{})
	workers[w.Name] = map[string]interface{}{
		"last_update":  time.Now().UTC().Format(time.RFC3339),
		"update_count": counters[workerKey],
		"pid":          os.Getpid(),
	}

	// Add some random data to increase chance of conflicts
	// #nosec G404 - weak RNG is fine for demo data generation
	if rand.Float32() < 0.3 {
		// #nosec G404 - weak RNG is fine for demo data generation
		content["random"] = rand.Intn(100)
	}

	// Update timestamp
	content["last_modified"] = time.Now().UTC().Format(time.RFC3339)
	content["modified_by"] = w.Name

	// Attempt update
	_, err = w.Manager.Update(ctx, configID, content)
	if err != nil {
		select {
		case conflictChan <- struct{}{}:
		default:
		}
		return err
	}

	return nil
}
