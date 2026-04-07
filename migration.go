package viracochan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// SignatureMigrationOptions controls legacy signature migration behavior.
type SignatureMigrationOptions struct {
	// DryRun reports what would change without writing any files.
	DryRun bool
}

// SignatureMigrationReport summarizes a legacy signature migration run.
type SignatureMigrationReport struct {
	ConfigFilesScanned        int // Total config files examined.
	ConfigFilesMigrated       int // Config files re-signed with the v2 format.
	ConfigFilesAlreadyCurrent int // Config files that already have a valid v2 signature.
	ConfigFilesUnsigned       int // Config files with no signature.
	JournalEntriesScanned     int // Total journal entries examined.
	JournalEntriesMigrated    int // Journal entries re-signed with the v2 format.
	JournalEntriesCurrent     int // Journal entries that already have a valid v2 signature.
	JournalEntriesUnsigned    int // Journal entries with no signature.
}

// MigrateLegacyConfig upgrades a legacy v0.1.x signature to the v0.2.0 native
// signature format after validating the config's checksum-backed integrity.
//
// The legacy nostr-event signature is NOT verified here because the event's
// CreatedAt timestamp (used to derive the signed event ID) was never persisted
// alongside the config, making the old signature unverifiable at rest.
// Integrity is assured through the checksum chain instead.
func MigrateLegacyConfig(cfg *Config, signer *Signer) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if signer == nil {
		return errors.New("signer is nil")
	}
	if cfg.Meta.Signature == "" {
		return nil
	}
	if cfg.Meta.SigAlg == SignatureAlgorithmV2 {
		return nil
	}
	if cfg.Meta.SigAlg != "" {
		return fmt.Errorf("%w: %q", ErrUnsupportedSignatureAlgorithm, cfg.Meta.SigAlg)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	return signer.Sign(cfg)
}

// MigrateLegacySignatures upgrades legacy signatures in the manager's config
// store and journal to the v0.2.0 native signing scheme.
func (m *Manager) MigrateLegacySignatures(ctx context.Context, opts SignatureMigrationOptions) (*SignatureMigrationReport, error) {
	if m.signer == nil {
		return nil, errors.New("no signer configured")
	}

	report := &SignatureMigrationReport{}
	migratedByCS := make(map[string]Meta)

	paths, err := m.storage.List(ctx, m.configStore.prefix)
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)

	configFiles := make([]migrationConfigFile, 0, len(paths))
	for _, path := range paths {
		if filepath.Ext(path) != ".json" {
			continue
		}

		configFile, err := loadMigrationConfigFile(ctx, m.storage, m.configStore.prefix, path)
		if err != nil {
			return nil, fmt.Errorf("load config %s: %w", path, err)
		}
		configFiles = append(configFiles, configFile)
	}

	if err := validateMigrationConfigChains(configFiles); err != nil {
		return nil, err
	}

	for _, configFile := range configFiles {
		report.ConfigFilesScanned++

		status, err := migrateConfigStatus(configFile.cfg, m.signer)
		if err != nil {
			return nil, fmt.Errorf("migrate config %s: %w", configFile.path, err)
		}

		switch status {
		case migrationStatusUnsigned:
			report.ConfigFilesUnsigned++
		case migrationStatusCurrent:
			report.ConfigFilesAlreadyCurrent++
			migratedByCS[configFile.cfg.Meta.CS] = configFile.cfg.Meta
		case migrationStatusMigrated:
			report.ConfigFilesMigrated++
			migratedByCS[configFile.cfg.Meta.CS] = configFile.cfg.Meta
			if !opts.DryRun {
				if err := writeConfigAtPath(ctx, m.storage, configFile.path, configFile.cfg); err != nil {
					return nil, fmt.Errorf("write config %s: %w", configFile.path, err)
				}
			}
		}
	}

	entries, err := m.journal.ReadAll(ctx)
	if err != nil {
		return nil, err
	}
	report.JournalEntriesScanned = len(entries)

	journalChanged := false
	for _, entry := range entries {
		if entry.Config == nil {
			continue
		}

		status, err := migrateJournalEntry(entry, m.signer, migratedByCS)
		if err != nil {
			return nil, fmt.Errorf("migrate journal entry %s v%d: %w", entry.ID, entry.Version, err)
		}

		switch status {
		case migrationStatusUnsigned:
			report.JournalEntriesUnsigned++
		case migrationStatusCurrent:
			report.JournalEntriesCurrent++
		case migrationStatusMigrated:
			report.JournalEntriesMigrated++
			if !opts.DryRun {
				journalChanged = true
			}
		}
	}

	if journalChanged {
		if err := m.journal.Rewrite(ctx, entries); err != nil {
			return nil, err
		}
	}

	if !opts.DryRun {
		m.cache = make(map[string]*Config)
	}

	return report, nil
}

type migrationStatus int

type migrationConfigFile struct {
	path string
	id   string
	cfg  *Config
}

const (
	migrationStatusUnsigned migrationStatus = iota
	migrationStatusCurrent
	migrationStatusMigrated
)

// migrateConfigStatus classifies a config's signature state. When a non-nil
// error is returned the status value is meaningless — callers treat errors as
// fatal and never inspect the status.
func migrateConfigStatus(cfg *Config, signer *Signer) (migrationStatus, error) {
	if cfg.Meta.Signature == "" {
		return migrationStatusUnsigned, nil
	}
	if cfg.Meta.SigAlg == SignatureAlgorithmV2 {
		if err := signer.Verify(cfg, signer.PublicKey()); err != nil {
			return 0, fmt.Errorf("current signature invalid: %w", err)
		}
		return migrationStatusCurrent, nil
	}
	if cfg.Meta.SigAlg != "" {
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedSignatureAlgorithm, cfg.Meta.SigAlg)
	}

	if err := MigrateLegacyConfig(cfg, signer); err != nil {
		return migrationStatusUnsigned, err
	}

	return migrationStatusMigrated, nil
}

func migrateJournalEntry(entry *JournalEntry, signer *Signer, migratedByCS map[string]Meta) (migrationStatus, error) {
	cfg := entry.Config
	if cfg.Meta.Signature == "" {
		return migrationStatusUnsigned, nil
	}
	if cfg.Meta.SigAlg == SignatureAlgorithmV2 {
		if err := signer.Verify(cfg, signer.PublicKey()); err != nil {
			return 0, fmt.Errorf("current signature invalid: %w", err)
		}
		return migrationStatusCurrent, nil
	}
	if cfg.Meta.SigAlg != "" {
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedSignatureAlgorithm, cfg.Meta.SigAlg)
	}

	if meta, ok := migratedByCS[cfg.Meta.CS]; ok {
		cfg.Meta.Signature = meta.Signature
		cfg.Meta.SigAlg = meta.SigAlg
		return migrationStatusMigrated, nil
	}

	clone := cloneConfig(cfg)
	if err := MigrateLegacyConfig(clone, signer); err != nil {
		return migrationStatusUnsigned, err
	}

	cfg.Meta.Signature = clone.Meta.Signature
	cfg.Meta.SigAlg = clone.Meta.SigAlg
	migratedByCS[cfg.Meta.CS] = cfg.Meta

	return migrationStatusMigrated, nil
}

func loadMigrationConfigFile(ctx context.Context, storage Storage, prefix, path string) (migrationConfigFile, error) {
	cfg, err := loadConfigAtPath(ctx, storage, path)
	if err != nil {
		return migrationConfigFile{}, err
	}

	id, version, err := parseMigrationConfigPath(prefix, path)
	if err != nil {
		return migrationConfigFile{}, err
	}
	if cfg.Meta.Version != version {
		return migrationConfigFile{}, fmt.Errorf("path version mismatch: file has v%d, config metadata has v%d", version, cfg.Meta.Version)
	}

	return migrationConfigFile{
		path: path,
		id:   id,
		cfg:  cfg,
	}, nil
}

func parseMigrationConfigPath(prefix, path string) (string, uint64, error) {
	relDir, err := filepath.Rel(prefix, filepath.Dir(path))
	if err != nil {
		return "", 0, err
	}
	if relDir == "." || relDir == "" {
		return "", 0, fmt.Errorf("invalid config path: missing config id")
	}

	base := filepath.Base(path)
	var version uint64
	if _, err := fmt.Sscanf(base, "v%d.json", &version); err != nil {
		return "", 0, fmt.Errorf("invalid config filename %q", base)
	}

	return relDir, version, nil
}

func validateMigrationConfigChains(configFiles []migrationConfigFile) error {
	if len(configFiles) == 0 {
		return nil
	}

	byID := make(map[string][]migrationConfigFile)
	for _, configFile := range configFiles {
		byID[configFile.id] = append(byID[configFile.id], configFile)
	}

	for id, files := range byID {
		sort.Slice(files, func(i, j int) bool {
			return files[i].cfg.Meta.Version < files[j].cfg.Meta.Version
		})

		for i, file := range files {
			if err := file.cfg.Validate(); err != nil {
				return fmt.Errorf("config chain %q invalid at %s: %w", id, file.path, err)
			}

			if i == 0 {
				if file.cfg.Meta.Version != 1 {
					return fmt.Errorf("config chain %q must start at version 1, found version %d in %s", id, file.cfg.Meta.Version, file.path)
				}
				if file.cfg.Meta.PrevCS != "" {
					return fmt.Errorf("config chain %q has non-empty prev_cs at head in %s", id, file.path)
				}
				continue
			}

			prev := files[i-1]
			if err := file.cfg.NextOf(prev.cfg); err != nil {
				return fmt.Errorf("config chain %q invalid between %s and %s: %w", id, prev.path, file.path, err)
			}
		}
	}

	return nil
}

func loadConfigAtPath(ctx context.Context, storage Storage, path string) (*Config, error) {
	data, err := storage.Read(ctx, path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func writeConfigAtPath(ctx context.Context, storage Storage, path string, cfg *Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	return storage.Write(ctx, path, data)
}

func cloneConfig(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}

	clone := *cfg
	if cfg.Content != nil {
		clone.Content = bytes.Clone(cfg.Content)
	}

	return &clone
}

func formatMigrationReport(report *SignatureMigrationReport) string {
	if report == nil {
		return "no migration report"
	}

	return strings.Join([]string{
		fmt.Sprintf("config files scanned: %d", report.ConfigFilesScanned),
		fmt.Sprintf("config files migrated: %d", report.ConfigFilesMigrated),
		fmt.Sprintf("config files already current: %d", report.ConfigFilesAlreadyCurrent),
		fmt.Sprintf("config files unsigned: %d", report.ConfigFilesUnsigned),
		fmt.Sprintf("journal entries scanned: %d", report.JournalEntriesScanned),
		fmt.Sprintf("journal entries migrated: %d", report.JournalEntriesMigrated),
		fmt.Sprintf("journal entries already current: %d", report.JournalEntriesCurrent),
		fmt.Sprintf("journal entries unsigned: %d", report.JournalEntriesUnsigned),
	}, "\n")
}

// String formats the migration report for human-readable output.
func (r *SignatureMigrationReport) String() string {
	return formatMigrationReport(r)
}
