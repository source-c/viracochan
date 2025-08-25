package viracochan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMemoryStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()

	testData := []byte("test content")
	path := "test/file.txt"

	// Test Write
	if err := storage.Write(ctx, path, testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Test Exists
	exists, err := storage.Exists(ctx, path)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("File should exist after write")
	}

	// Test Read
	read, err := storage.Read(ctx, path)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(read) != string(testData) {
		t.Errorf("Read data mismatch: expected %s, got %s", testData, read)
	}

	// Test List
	files, err := storage.List(ctx, "test")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 1 || files[0] != path {
		t.Errorf("List mismatch: expected [%s], got %v", path, files)
	}

	// Test Delete
	if err := storage.Delete(ctx, path); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	exists, _ = storage.Exists(ctx, path)
	if exists {
		t.Error("File should not exist after delete")
	}
}

func TestFileStorage(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	storage, err := NewFileStorage(tempDir)
	if err != nil {
		t.Fatalf("NewFileStorage failed: %v", err)
	}

	testData := []byte("file content")
	path := "subdir/file.txt"

	// Test Write (with subdirectory creation)
	if err := storage.Write(ctx, path, testData); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Verify file exists on disk
	fullPath := filepath.Join(tempDir, path)
	if _, err := os.Stat(fullPath); err != nil {
		t.Errorf("File not created on disk: %v", err)
	}

	// Test Read
	read, err := storage.Read(ctx, path)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(read) != string(testData) {
		t.Errorf("Read data mismatch")
	}

	// Test List
	files, err := storage.List(ctx, "subdir")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d", len(files))
	}

	// Test Delete
	if err := storage.Delete(ctx, path); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		t.Error("File should not exist after delete")
	}
}

func TestConfigStorage(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	configStore := NewConfigStorage(storage, "configs")

	cfg := &Config{
		Content: json.RawMessage(`{"test": "data"}`),
	}
	cfg.UpdateMeta()

	// Test Save
	if err := configStore.Save(ctx, "test-id", cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Test Load
	loaded, err := configStore.Load(ctx, "test-id", cfg.Meta.Version)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Meta.CS != cfg.Meta.CS {
		t.Error("Checksum mismatch after load")
	}

	// Compare JSON content semantically, not byte-for-byte
	var origContent, loadedContent interface{}
	json.Unmarshal(cfg.Content, &origContent)
	json.Unmarshal(loaded.Content, &loadedContent)

	if !reflect.DeepEqual(origContent, loadedContent) {
		t.Errorf("Content mismatch after load:\nOriginal: %v\nLoaded:   %v",
			origContent, loadedContent)
	}

	// Test ListVersions
	cfg2 := &Config{
		Meta:    cfg.Meta,
		Content: json.RawMessage(`{"test": "data2"}`),
	}
	cfg2.UpdateMeta()
	configStore.Save(ctx, "test-id", cfg2)

	versions, err := configStore.ListVersions(ctx, "test-id")
	if err != nil {
		t.Fatalf("ListVersions failed: %v", err)
	}

	if len(versions) != 2 {
		t.Errorf("Expected 2 versions, got %d", len(versions))
	}

	// Test LoadLatest
	latest, err := configStore.LoadLatest(ctx, "test-id")
	if err != nil {
		t.Fatalf("LoadLatest failed: %v", err)
	}

	if latest.Meta.Version != cfg2.Meta.Version {
		t.Errorf("LoadLatest returned wrong version: expected %d, got %d",
			cfg2.Meta.Version, latest.Meta.Version)
	}
}

func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()

	done := make(chan bool, 10)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(n int) {
			path := fmt.Sprintf("file%d.txt", n)
			data := []byte(fmt.Sprintf("content %d", n))
			if err := storage.Write(ctx, path, data); err != nil {
				t.Errorf("Concurrent write %d failed: %v", n, err)
			}
			done <- true
		}(i)
	}

	// Wait for all writes
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all files exist
	files, err := storage.List(ctx, "")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if len(files) != 10 {
		t.Errorf("Expected 10 files, got %d", len(files))
	}

	// Concurrent reads
	for i := 0; i < 10; i++ {
		go func(n int) {
			path := fmt.Sprintf("file%d.txt", n)
			expected := fmt.Sprintf("content %d", n)
			data, err := storage.Read(ctx, path)
			if err != nil {
				t.Errorf("Concurrent read %d failed: %v", n, err)
			}
			if string(data) != expected {
				t.Errorf("Read %d mismatch: expected %s, got %s", n, expected, data)
			}
			done <- true
		}(i)
	}

	// Wait for all reads
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestStorageEdgeCases(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()

	// Test read non-existent file
	_, err := storage.Read(ctx, "nonexistent.txt")
	if err == nil {
		t.Error("Expected error reading non-existent file")
	}

	// Test exists for non-existent file
	exists, err := storage.Exists(ctx, "nonexistent.txt")
	if err != nil {
		t.Errorf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Non-existent file reported as existing")
	}

	// Test delete non-existent file (should not error)
	if err := storage.Delete(ctx, "nonexistent.txt"); err != nil {
		t.Logf("Delete non-existent file returned error: %v", err)
	}

	// Test empty write
	if err := storage.Write(ctx, "empty.txt", []byte{}); err != nil {
		t.Errorf("Failed to write empty file: %v", err)
	}

	data, err := storage.Read(ctx, "empty.txt")
	if err != nil {
		t.Errorf("Failed to read empty file: %v", err)
	}
	if len(data) != 0 {
		t.Error("Empty file should have zero length")
	}

	// Test overwrite
	if err := storage.Write(ctx, "test.txt", []byte("initial")); err != nil {
		t.Fatalf("Initial write failed: %v", err)
	}

	if err := storage.Write(ctx, "test.txt", []byte("overwritten")); err != nil {
		t.Fatalf("Overwrite failed: %v", err)
	}

	data, err = storage.Read(ctx, "test.txt")
	if err != nil {
		t.Fatalf("Read after overwrite failed: %v", err)
	}
	if string(data) != "overwritten" {
		t.Error("Overwrite did not update content")
	}
}
