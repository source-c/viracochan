package viracochan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Manager provides high-level configuration management
type Manager struct {
	storage    Storage
	journal    *Journal
	configStore *ConfigStorage
	signer     *Signer
	mu         sync.RWMutex
	cache      map[string]*Config
}

// NewManager creates new configuration manager
func NewManager(storage Storage, opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		storage:     storage,
		journal:     NewJournal(storage, "journal.jsonl"),
		configStore: NewConfigStorage(storage, "configs"),
		cache:       make(map[string]*Config),
	}
	
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}
	
	return m, nil
}

// ManagerOption configures Manager
type ManagerOption func(*Manager) error

// WithSigner adds signing capability
func WithSigner(signer *Signer) ManagerOption {
	return func(m *Manager) error {
		m.signer = signer
		return nil
	}
}

// WithJournalPath sets custom journal path
func WithJournalPath(path string) ManagerOption {
	return func(m *Manager) error {
		m.journal = NewJournal(m.storage, path)
		return nil
	}
}

// Create creates new configuration
func (m *Manager) Create(ctx context.Context, id string, content interface{}) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	data, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	cfg := &Config{
		Meta: Meta{
			Version: 0,
		},
		Content: json.RawMessage(data),
	}
	
	if err := cfg.UpdateMeta(); err != nil {
		return nil, err
	}
	
	if m.signer != nil {
		if err := m.signer.Sign(cfg); err != nil {
			return nil, err
		}
	}
	
	if err := m.configStore.Save(ctx, id, cfg); err != nil {
		return nil, err
	}
	
	entry := &JournalEntry{
		ID:        id,
		Version:   cfg.Meta.Version,
		CS:        cfg.Meta.CS,
		PrevCS:    cfg.Meta.PrevCS,
		Time:      cfg.Meta.Time,
		Operation: "create",
		Config:    cfg,
	}
	
	if err := m.journal.Append(ctx, entry); err != nil {
		return nil, err
	}
	
	m.cache[id] = cfg
	return cfg, nil
}

// Update updates existing configuration
func (m *Manager) Update(ctx context.Context, id string, content interface{}) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	current, err := m.getLatest(ctx, id)
	if err != nil {
		return nil, err
	}
	
	data, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	
	newCfg := &Config{
		Meta:    current.Meta,
		Content: json.RawMessage(data),
	}
	
	if err := newCfg.UpdateMeta(); err != nil {
		return nil, err
	}
	
	if m.signer != nil {
		if err := m.signer.Sign(newCfg); err != nil {
			return nil, err
		}
	}
	
	if err := m.configStore.Save(ctx, id, newCfg); err != nil {
		return nil, err
	}
	
	entry := &JournalEntry{
		ID:        id,
		Version:   newCfg.Meta.Version,
		CS:        newCfg.Meta.CS,
		PrevCS:    newCfg.Meta.PrevCS,
		Time:      newCfg.Meta.Time,
		Operation: "update",
		Config:    newCfg,
	}
	
	if err := m.journal.Append(ctx, entry); err != nil {
		return nil, err
	}
	
	m.cache[id] = newCfg
	return newCfg, nil
}

// Get retrieves specific version of configuration
func (m *Manager) Get(ctx context.Context, id string, version uint64) (*Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return m.configStore.Load(ctx, id, version)
}

// GetLatest retrieves latest version of configuration
func (m *Manager) GetLatest(ctx context.Context, id string) (*Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	return m.getLatest(ctx, id)
}

func (m *Manager) getLatest(ctx context.Context, id string) (*Config, error) {
	if cfg, ok := m.cache[id]; ok {
		return cfg, nil
	}
	
	cfg, err := m.journal.Reconstruct(ctx, id, m.storage)
	if err != nil {
		return nil, err
	}
	
	m.cache[id] = cfg
	return cfg, nil
}

// GetHistory retrieves configuration history
func (m *Manager) GetHistory(ctx context.Context, id string) ([]*Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	versions, err := m.configStore.ListVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	
	// Sort versions to ensure correct order
	sort.Slice(versions, func(i, j int) bool {
		return versions[i] < versions[j]
	})
	
	configs := make([]*Config, 0, len(versions))
	for _, v := range versions {
		cfg, err := m.configStore.Load(ctx, id, v)
		if err != nil {
			continue
		}
		configs = append(configs, cfg)
	}
	
	return configs, nil
}

// ValidateChain validates configuration chain integrity
func (m *Manager) ValidateChain(ctx context.Context, id string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	entries, err := m.journal.FindByID(ctx, id)
	if err != nil {
		return err
	}
	
	if len(entries) == 0 {
		return nil
	}
	
	ordered, err := m.journal.Resequence(entries)
	if err != nil {
		return err
	}
	
	return m.journal.ValidateChain(ordered)
}

// Reconstruct rebuilds state from journal and scattered files
func (m *Manager) Reconstruct(ctx context.Context, id string) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	cfg, err := m.journal.Reconstruct(ctx, id, m.storage)
	if err != nil {
		return nil, err
	}
	
	m.cache[id] = cfg
	return cfg, nil
}

// Export exports configuration to writer
func (m *Manager) Export(ctx context.Context, id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	cfg, err := m.getLatest(ctx, id)
	if err != nil {
		return nil, err
	}
	
	return json.MarshalIndent(cfg, "", "  ")
}

// Import imports configuration from reader
func (m *Manager) Import(ctx context.Context, id string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	if err := m.configStore.Save(ctx, id, &cfg); err != nil {
		return err
	}
	
	entry := &JournalEntry{
		ID:        id,
		Version:   cfg.Meta.Version,
		CS:        cfg.Meta.CS,
		PrevCS:    cfg.Meta.PrevCS,
		Time:      cfg.Meta.Time,
		Operation: "import",
		Config:    &cfg,
	}
	
	if err := m.journal.Append(ctx, entry); err != nil {
		return err
	}
	
	m.cache[id] = &cfg
	return nil
}

// Compact compacts journal to reduce size
func (m *Manager) Compact(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	return m.journal.Compact(ctx)
}

// List lists all configuration IDs
func (m *Manager) List(ctx context.Context) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	entries, err := m.journal.ReadAll(ctx)
	if err != nil {
		return nil, err
	}
	
	seen := make(map[string]bool)
	var ids []string
	
	for _, entry := range entries {
		if !seen[entry.ID] {
			seen[entry.ID] = true
			ids = append(ids, entry.ID)
		}
	}
	
	return ids, nil
}

// Verify verifies configuration signature
func (m *Manager) Verify(cfg *Config, publicKey string) error {
	if m.signer == nil {
		return errors.New("no signer configured")
	}
	
	return m.signer.Verify(cfg, publicKey)
}

// Watch watches for configuration changes
func (m *Manager) Watch(ctx context.Context, id string, interval time.Duration) (<-chan *Config, error) {
	ch := make(chan *Config, 1)
	
	// Get initial version to avoid sending current state
	initialCfg, err := m.GetLatest(ctx, id)
	if err != nil {
		// If config doesn't exist yet, start from 0
		initialCfg = &Config{Meta: Meta{Version: 0}}
	}
	
	go func() {
		defer close(ch)
		
		lastVersion := initialCfg.Meta.Version
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cfg, err := m.GetLatest(ctx, id)
				if err != nil {
					continue
				}
				
				if cfg.Meta.Version > lastVersion {
					lastVersion = cfg.Meta.Version
					select {
					case ch <- cfg:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	
	return ch, nil
}

// Rollback rolls back to specific version
func (m *Manager) Rollback(ctx context.Context, id string, version uint64) (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	// Get the content from the target version
	targetCfg, err := m.configStore.Load(ctx, id, version)
	if err != nil {
		return nil, err
	}
	
	// Get the latest version to continue the chain
	latestCfg, err := m.getLatest(ctx, id)
	if err != nil {
		return nil, err
	}
	
	// Create new config with rolled back content but continuing from latest version
	newCfg := &Config{
		Meta:    latestCfg.Meta,
		Content: targetCfg.Content,
	}
	
	if err := newCfg.UpdateMeta(); err != nil {
		return nil, err
	}
	
	if m.signer != nil {
		if err := m.signer.Sign(newCfg); err != nil {
			return nil, err
		}
	}
	
	if err := m.configStore.Save(ctx, id, newCfg); err != nil {
		return nil, err
	}
	
	entry := &JournalEntry{
		ID:        id,
		Version:   newCfg.Meta.Version,
		CS:        newCfg.Meta.CS,
		PrevCS:    newCfg.Meta.PrevCS,
		Time:      newCfg.Meta.Time,
		Operation: fmt.Sprintf("rollback_to_v%d", version),
		Config:    newCfg,
	}
	
	if err := m.journal.Append(ctx, entry); err != nil {
		return nil, err
	}
	
	m.cache[id] = newCfg
	return newCfg, nil
}