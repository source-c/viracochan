// Demo: Encrypted Storage Layer
// Shows custom storage implementation with encryption, compression, and integrity checks
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/source-c/viracochan"
)

// EncryptedStorage wraps any storage backend with encryption
type EncryptedStorage struct {
	backend  viracochan.Storage
	cipher   cipher.AEAD
	compress bool
	mu       sync.RWMutex
	stats    EncryptionStats
}

type EncryptionStats struct {
	Encryptions     int64
	Decryptions     int64
	Compressions    int64
	BytesOriginal   int64
	BytesEncrypted  int64
	BytesCompressed int64
}

// NewEncryptedStorage creates encrypted storage wrapper
func NewEncryptedStorage(backend viracochan.Storage, key []byte, compress bool) (*EncryptedStorage, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &EncryptedStorage{
		backend:  backend,
		cipher:   aead,
		compress: compress,
	}, nil
}

func (es *EncryptedStorage) Read(ctx context.Context, path string) ([]byte, error) {
	// Read encrypted data
	encryptedData, err := es.backend.Read(ctx, path)
	if err != nil {
		return nil, err
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %w", err)
	}

	// Extract nonce
	if len(ciphertext) < es.cipher.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:es.cipher.NonceSize()]
	ciphertext = ciphertext[es.cipher.NonceSize():]

	// Decrypt
	plaintext, err := es.cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	es.mu.Lock()
	es.stats.Decryptions++
	es.mu.Unlock()

	// Decompress if needed
	if es.compress && len(plaintext) > 0 {
		reader, err := gzip.NewReader(bytes.NewReader(plaintext))
		if err != nil {
			return nil, fmt.Errorf("decompression failed: %w", err)
		}
		defer reader.Close()

		decompressed, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("decompression read failed: %w", err)
		}

		return decompressed, nil
	}

	return plaintext, nil
}

func (es *EncryptedStorage) Write(ctx context.Context, path string, data []byte) error {
	es.mu.Lock()
	es.stats.BytesOriginal += int64(len(data))
	es.mu.Unlock()

	plaintext := data

	// Compress if enabled
	if es.compress && len(data) > 0 {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(data); err != nil {
			return fmt.Errorf("compression failed: %w", err)
		}
		if err := writer.Close(); err != nil {
			return fmt.Errorf("compression close failed: %w", err)
		}
		plaintext = buf.Bytes()

		es.mu.Lock()
		es.stats.Compressions++
		es.stats.BytesCompressed += int64(len(plaintext))
		es.mu.Unlock()
	}

	// Generate nonce
	nonce := make([]byte, es.cipher.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt
	ciphertext := es.cipher.Seal(nonce, nonce, plaintext, nil)

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	es.mu.Lock()
	es.stats.Encryptions++
	es.stats.BytesEncrypted += int64(len(encoded))
	es.mu.Unlock()

	// Write to backend
	return es.backend.Write(ctx, path, []byte(encoded))
}

func (es *EncryptedStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return es.backend.List(ctx, prefix)
}

func (es *EncryptedStorage) Delete(ctx context.Context, path string) error {
	return es.backend.Delete(ctx, path)
}

func (es *EncryptedStorage) Exists(ctx context.Context, path string) (bool, error) {
	return es.backend.Exists(ctx, path)
}

func (es *EncryptedStorage) GetStats() EncryptionStats {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return es.stats
}

// IntegrityStorage adds integrity checking layer
type IntegrityStorage struct {
	backend   viracochan.Storage
	mu        sync.RWMutex
	checksums map[string]string
}

func NewIntegrityStorage(backend viracochan.Storage) *IntegrityStorage {
	return &IntegrityStorage{
		backend:   backend,
		checksums: make(map[string]string),
	}
}

func (is *IntegrityStorage) Read(ctx context.Context, path string) ([]byte, error) {
	// Read data with checksum
	rawData, err := is.backend.Read(ctx, path)
	if err != nil {
		return nil, err
	}

	// Split data and checksum
	parts := strings.SplitN(string(rawData), "\n---CHECKSUM---\n", 2)
	if len(parts) != 2 {
		return nil, errors.New("integrity check failed: no checksum found")
	}

	data := []byte(parts[0])
	storedChecksum := parts[1]

	// Verify checksum
	hash := sha256.Sum256(data)
	computedChecksum := hex.EncodeToString(hash[:])

	if storedChecksum != computedChecksum {
		return nil, fmt.Errorf("integrity check failed: checksum mismatch")
	}

	is.mu.Lock()
	is.checksums[path] = computedChecksum
	is.mu.Unlock()

	return data, nil
}

func (is *IntegrityStorage) Write(ctx context.Context, path string, data []byte) error {
	// Compute checksum
	hash := sha256.Sum256(data)
	checksum := hex.EncodeToString(hash[:])

	// Combine data with checksum
	combined := append(data, []byte("\n---CHECKSUM---\n"+checksum)...) //nolint:gocritic // appendAssign is intended here

	is.mu.Lock()
	is.checksums[path] = checksum
	is.mu.Unlock()

	return is.backend.Write(ctx, path, combined)
}

func (is *IntegrityStorage) List(ctx context.Context, prefix string) ([]string, error) {
	return is.backend.List(ctx, prefix)
}

func (is *IntegrityStorage) Delete(ctx context.Context, path string) error {
	is.mu.Lock()
	delete(is.checksums, path)
	is.mu.Unlock()

	return is.backend.Delete(ctx, path)
}

func (is *IntegrityStorage) Exists(ctx context.Context, path string) (bool, error) {
	return is.backend.Exists(ctx, path)
}

func (is *IntegrityStorage) VerifyAll(ctx context.Context) (int, int, error) {
	files, err := is.backend.List(ctx, "")
	if err != nil {
		return 0, 0, err
	}

	valid := 0
	invalid := 0

	for _, file := range files {
		_, err := is.Read(ctx, file)
		if err != nil {
			invalid++
			fmt.Printf("  ✗ %s: %v\n", file, err)
		} else {
			valid++
		}
	}

	return valid, invalid, nil
}

func main() {
	var (
		dataDir  = flag.String("dir", "./encryption-demo", "data directory")
		keyStr   = flag.String("key", "", "32-byte encryption key (hex)")
		compress = flag.Bool("compress", true, "enable compression")
	)
	flag.Parse()

	ctx := context.Background()

	// Clean up previous runs
	os.RemoveAll(*dataDir)

	fmt.Println("=== Encrypted Storage Demo ===")
	fmt.Println("Demonstrating encryption, compression, and integrity layers")

	// Generate or parse encryption key
	var encKey []byte
	if *keyStr != "" {
		var err error
		encKey, err = hex.DecodeString(*keyStr)
		if err != nil || len(encKey) != 32 {
			log.Fatal("Invalid encryption key: must be 64 hex characters (32 bytes)")
		}
		fmt.Println("Using provided encryption key")
	} else {
		encKey = make([]byte, 32)
		if _, err := rand.Read(encKey); err != nil {
			log.Fatal("Failed to generate encryption key:", err)
		}
		fmt.Printf("Generated encryption key: %s\n", hex.EncodeToString(encKey))
	}

	// Phase 1: Setup layered storage
	fmt.Println("\n--- Phase 1: Storage Layer Setup ---")

	// Base file storage
	baseStorage, err := viracochan.NewFileStorage(*dataDir)
	if err != nil {
		log.Fatal("Failed to create base storage:", err)
	}
	fmt.Println("✓ Base file storage initialized")

	// Add integrity layer
	integrityStorage := NewIntegrityStorage(baseStorage)
	fmt.Println("✓ Integrity checking layer added")

	// Add encryption layer
	encryptedStorage, err := NewEncryptedStorage(integrityStorage, encKey, *compress)
	if err != nil {
		log.Fatal("Failed to create encrypted storage:", err)
	}
	fmt.Printf("✓ Encryption layer added (compression: %v)\n", *compress)

	// Phase 2: Create configuration with sensitive data
	fmt.Println("\n--- Phase 2: Storing Sensitive Configuration ---")

	signer, err := viracochan.NewSigner()
	if err != nil {
		log.Fatal("Failed to create signer:", err)
	}

	manager, err := viracochan.NewManager(
		encryptedStorage,
		viracochan.WithSigner(signer),
	)
	if err != nil {
		log.Fatal("Failed to create manager:", err)
	}

	// Create configuration with sensitive data
	configID := "sensitive-config"
	sensitiveData := map[string]interface{}{
		"credentials": map[string]interface{}{
			"api_key":           "sk-1234567890abcdef",
			"api_secret":        "super-secret-value-that-should-be-encrypted",
			"database_password": "P@ssw0rd123!",
		},
		"payment": map[string]interface{}{
			"stripe_key":     "sk_live_abcdef123456",
			"webhook_secret": "whsec_1234567890",
		},
		"personal_data": map[string]interface{}{
			"users": []map[string]interface{}{
				{
					"id":    "user-001",
					"email": "alice@example.com",
					"ssn":   "123-45-6789",
				},
				{
					"id":    "user-002",
					"email": "bob@example.com",
					"ssn":   "987-65-4321",
				},
			},
		},
		"encryption_test": strings.Repeat("A", 1000), // Test compression
	}

	cfg, err := manager.Create(ctx, configID, sensitiveData)
	if err != nil {
		log.Fatal("Failed to create config:", err)
	}

	fmt.Printf("✓ Created sensitive config v%d\n", cfg.Meta.Version)
	fmt.Printf("  Original size: ~%d bytes\n", len(mustMarshal(sensitiveData)))

	// Phase 3: Verify encryption
	fmt.Println("\n--- Phase 3: Encryption Verification ---")

	// Try to read raw files (should be encrypted)
	fmt.Println("\nAttempting to read raw files:")

	configPath := fmt.Sprintf("configs/%s/v%d.json", configID, cfg.Meta.Version)
	rawData, err := baseStorage.Read(ctx, configPath)
	if err != nil {
		fmt.Printf("✗ Failed to read raw file: %v\n", err)
	} else {
		fmt.Printf("✓ Raw file size: %d bytes\n", len(rawData))

		// Check if data appears encrypted
		if strings.Contains(string(rawData), "api_key") ||
			strings.Contains(string(rawData), "password") {
			fmt.Println("⚠ WARNING: Sensitive data found in raw file!")
		} else {
			fmt.Println("✓ No sensitive data visible in raw file")
		}

		// Show sample of raw data
		sample := string(rawData)
		if len(sample) > 100 {
			sample = sample[:100] + "..."
		}
		fmt.Printf("  Raw data sample: %s\n", sample)
	}

	// Phase 4: Test integrity protection
	fmt.Println("\n--- Phase 4: Integrity Protection ---")

	fmt.Println("\nCorrupting a file to test integrity checks...")

	// Create another config
	testConfig := map[string]interface{}{
		"test": "integrity check",
		"data": "should be protected",
	}

	testCfg, err := manager.Create(ctx, "test-config", testConfig)
	if err != nil {
		log.Fatal("Failed to create test config:", err)
	}

	// Corrupt the file
	testPath := fmt.Sprintf("configs/test-config/v%d.json", testCfg.Meta.Version)
	corruptedData := []byte("CORRUPTED DATA HERE")

	// Write corrupted data directly to base storage
	if err := baseStorage.Write(ctx, testPath, corruptedData); err != nil {
		fmt.Printf("Failed to corrupt file: %v\n", err)
	} else {
		fmt.Println("✓ File corrupted")
	}

	// Try to read corrupted file
	_, err = manager.Get(ctx, "test-config", testCfg.Meta.Version)
	if err != nil {
		fmt.Printf("✓ Integrity check caught corruption: %v\n", err)
	} else {
		fmt.Println("⚠ Corruption not detected!")
	}

	// Phase 5: Performance comparison
	fmt.Println("\n--- Phase 5: Performance Analysis ---")

	// Create configs with different sizes
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		data := map[string]interface{}{
			"size_test": size,
			"data":      strings.Repeat("X", size),
		}

		start := time.Now()
		perfCfg, err := manager.Create(ctx, fmt.Sprintf("perf-%d", size), data)
		if err != nil {
			fmt.Printf("✗ Failed to create %d byte config: %v\n", size, err)
			continue
		}
		elapsed := time.Since(start)

		// Measure read time
		readStart := time.Now()
		_, err = manager.Get(ctx, fmt.Sprintf("perf-%d", size), perfCfg.Meta.Version)
		readElapsed := time.Since(readStart)

		if err != nil {
			fmt.Printf("✗ Failed to read %d byte config: %v\n", size, err)
		} else {
			fmt.Printf("Size %6d: Write %6.2fms, Read %6.2fms\n",
				size, elapsed.Seconds()*1000, readElapsed.Seconds()*1000)
		}
	}

	// Phase 6: Multi-version with encryption
	fmt.Println("\n--- Phase 6: Version History with Encryption ---")

	// Create multiple versions
	for i := 1; i <= 3; i++ {
		var current map[string]interface{}
		latest, _ := manager.GetLatest(ctx, configID)
		if err := json.Unmarshal(latest.Content, &current); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}

		current["version"] = fmt.Sprintf("1.0.%d", i)
		current["updated_at"] = time.Now().UTC().Format(time.RFC3339)

		updated, err := manager.Update(ctx, configID, current)
		if err != nil {
			fmt.Printf("✗ Failed to update to v%d: %v\n", i+1, err)
		} else {
			fmt.Printf("✓ Updated to v%d\n", updated.Meta.Version)
		}
	}

	// Verify all versions are encrypted
	fmt.Println("\nVerifying encryption of all versions:")
	history, err := manager.GetHistory(ctx, configID)
	if err != nil {
		fmt.Printf("✗ Failed to get history: %v\n", err)
	} else {
		for _, h := range history {
			// Try to read raw
			path := fmt.Sprintf("configs/%s/v%d.json", configID, h.Meta.Version)
			raw, _ := baseStorage.Read(ctx, path)

			encrypted := !strings.Contains(string(raw), "api_key")
			if encrypted {
				fmt.Printf("  v%d: ✓ Encrypted\n", h.Meta.Version)
			} else {
				fmt.Printf("  v%d: ✗ NOT ENCRYPTED!\n", h.Meta.Version)
			}
		}
	}

	// Phase 7: Statistics
	fmt.Println("\n--- Phase 7: Encryption Statistics ---")

	stats := encryptedStorage.GetStats()

	fmt.Println("\nEncryption Layer Statistics:")
	fmt.Printf("  Encryptions:     %d\n", stats.Encryptions)
	fmt.Printf("  Decryptions:     %d\n", stats.Decryptions)
	fmt.Printf("  Compressions:    %d\n", stats.Compressions)
	fmt.Printf("  Original bytes:  %d\n", stats.BytesOriginal)
	fmt.Printf("  Compressed:      %d\n", stats.BytesCompressed)
	fmt.Printf("  Encrypted:       %d\n", stats.BytesEncrypted)

	if stats.BytesOriginal > 0 && stats.BytesCompressed > 0 {
		compressionRatio := float64(stats.BytesOriginal-stats.BytesCompressed) / float64(stats.BytesOriginal) * 100
		fmt.Printf("  Compression:     %.1f%%\n", compressionRatio)
	}

	if stats.BytesOriginal > 0 && stats.BytesEncrypted > 0 {
		overhead := float64(stats.BytesEncrypted-stats.BytesOriginal) / float64(stats.BytesOriginal) * 100
		fmt.Printf("  Encryption overhead: %.1f%%\n", overhead)
	}

	// Phase 8: Integrity verification
	fmt.Println("\n--- Phase 8: Full Integrity Scan ---")

	fmt.Println("\nScanning all files for integrity...")
	valid, invalid, err := integrityStorage.VerifyAll(ctx)
	if err != nil {
		fmt.Printf("✗ Scan failed: %v\n", err)
	} else {
		fmt.Printf("✓ Scan complete: %d valid, %d invalid\n", valid, invalid)

		if invalid > 0 {
			fmt.Println("⚠ Some files failed integrity checks")
		} else {
			fmt.Println("✓ All files passed integrity checks")
		}
	}

	// Final validation
	fmt.Println("\n=== Final Validation ===")

	// Validate chain through encrypted storage
	if err := manager.ValidateChain(ctx, configID); err != nil {
		fmt.Printf("✗ Chain validation failed: %v\n", err)
	} else {
		fmt.Println("✓ Chain validated through encrypted storage")
	}

	// Verify we can still read sensitive data when properly decrypted
	finalCfg, err := manager.GetLatest(ctx, configID)
	if err != nil {
		fmt.Printf("✗ Failed to read final config: %v\n", err)
	} else {
		var content map[string]interface{}
		if err := json.Unmarshal(finalCfg.Content, &content); err != nil {
			log.Printf("Failed to unmarshal content: %v", err)
		}

		if creds, ok := content["credentials"].(map[string]interface{}); ok {
			if apiKey, ok := creds["api_key"].(string); ok && apiKey == "sk-1234567890abcdef" {
				fmt.Println("✓ Sensitive data correctly decrypted and accessible")
			} else {
				fmt.Println("✗ Sensitive data not properly decrypted")
			}
		}
	}

	fmt.Println("\n✓ Encrypted storage demo completed successfully")
}

func mustMarshal(v interface{}) []byte {
	data, _ := json.Marshal(v)
	return data
}
