package viracochan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Storage defines interface for filesystem-like operations
type Storage interface {
	Read(ctx context.Context, path string) ([]byte, error)
	Write(ctx context.Context, path string, data []byte) error
	List(ctx context.Context, prefix string) ([]string, error)
	Delete(ctx context.Context, path string) error
	Exists(ctx context.Context, path string) (bool, error)
}

// FileStorage implements Storage using local filesystem
type FileStorage struct {
	root string
	mu   sync.RWMutex
}

// NewFileStorage creates new filesystem storage
func NewFileStorage(root string) (*FileStorage, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, err
	}
	return &FileStorage{root: abs}, nil
}

func (fs *FileStorage) Read(ctx context.Context, path string) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	fullPath := filepath.Join(fs.root, path)
	// Validate path to prevent directory traversal
	if !strings.HasPrefix(filepath.Clean(fullPath), fs.root) {
		return nil, fmt.Errorf("invalid path: potential directory traversal")
	}
	return os.ReadFile(fullPath) // #nosec G304 - path is validated above
}

func (fs *FileStorage) Write(ctx context.Context, path string, data []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fullPath := filepath.Join(fs.root, path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0o600)
}

func (fs *FileStorage) List(ctx context.Context, prefix string) ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	searchPath := filepath.Join(fs.root, prefix)
	var paths []string

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			rel, err := filepath.Rel(fs.root, path)
			if err != nil {
				return err
			}
			paths = append(paths, rel)
		}
		return nil
	})

	return paths, err
}

func (fs *FileStorage) Delete(ctx context.Context, path string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fullPath := filepath.Join(fs.root, path)
	return os.Remove(fullPath)
}

func (fs *FileStorage) Exists(ctx context.Context, path string) (bool, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	fullPath := filepath.Join(fs.root, path)
	_, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// MemoryStorage implements Storage in memory
type MemoryStorage struct {
	data map[string][]byte
	mu   sync.RWMutex
}

// NewMemoryStorage creates new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		data: make(map[string][]byte),
	}
}

func (ms *MemoryStorage) Read(ctx context.Context, path string) ([]byte, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	data, ok := ms.data[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), data...), nil
}

func (ms *MemoryStorage) Write(ctx context.Context, path string, data []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.data[path] = append([]byte(nil), data...)
	return nil
}

func (ms *MemoryStorage) List(ctx context.Context, prefix string) ([]string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var paths []string
	for path := range ms.data {
		if strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}
	return paths, nil
}

func (ms *MemoryStorage) Delete(ctx context.Context, path string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.data, path)
	return nil
}

func (ms *MemoryStorage) Exists(ctx context.Context, path string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	_, ok := ms.data[path]
	return ok, nil
}

// ConfigStorage wraps Storage with Config-specific operations
type ConfigStorage struct {
	storage Storage
	prefix  string
}

// NewConfigStorage creates storage wrapper for configs
func NewConfigStorage(storage Storage, prefix string) *ConfigStorage {
	return &ConfigStorage{
		storage: storage,
		prefix:  prefix,
	}
}

func (cs *ConfigStorage) makeKey(id string, version uint64) string {
	return filepath.Join(cs.prefix, id, fmt.Sprintf("v%d.json", version))
}

func (cs *ConfigStorage) Save(ctx context.Context, id string, cfg *Config) error {
	key := cs.makeKey(id, cfg.Meta.Version)
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return cs.storage.Write(ctx, key, data)
}

func (cs *ConfigStorage) Load(ctx context.Context, id string, version uint64) (*Config, error) {
	key := cs.makeKey(id, version)
	data, err := cs.storage.Read(ctx, key)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Only validate if checksum is present
	if cfg.Meta.CS != "" {
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("invalid config: %w", err)
		}
	}

	return &cfg, nil
}

func (cs *ConfigStorage) ListVersions(ctx context.Context, id string) ([]uint64, error) {
	prefix := filepath.Join(cs.prefix, id)
	paths, err := cs.storage.List(ctx, prefix)
	if err != nil {
		return nil, err
	}

	var versions []uint64
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasPrefix(base, "v") && strings.HasSuffix(base, ".json") {
			var v uint64
			if _, err := fmt.Sscanf(base, "v%d.json", &v); err == nil {
				versions = append(versions, v)
			}
		}
	}
	return versions, nil
}

func (cs *ConfigStorage) LoadLatest(ctx context.Context, id string) (*Config, error) {
	versions, err := cs.ListVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(versions) == 0 {
		return nil, os.ErrNotExist
	}

	maxVersion := versions[0]
	for _, v := range versions[1:] {
		if v > maxVersion {
			maxVersion = v
		}
	}

	return cs.Load(ctx, id, maxVersion)
}

// StorageWriter wraps Storage as io.Writer for specific path
type StorageWriter struct {
	storage Storage
	path    string
	ctx     context.Context
	buffer  []byte
}

func (sw *StorageWriter) Write(p []byte) (int, error) {
	sw.buffer = append(sw.buffer, p...)
	return len(p), nil
}

func (sw *StorageWriter) Close() error {
	return sw.storage.Write(sw.ctx, sw.path, sw.buffer)
}

// StorageReader wraps Storage as io.Reader for specific path
type StorageReader struct {
	data   []byte
	offset int
}

func (sr *StorageReader) Read(p []byte) (int, error) {
	if sr.offset >= len(sr.data) {
		return 0, io.EOF
	}

	n := copy(p, sr.data[sr.offset:])
	sr.offset += n
	return n, nil
}

func (sr *StorageReader) Close() error {
	return nil
}
