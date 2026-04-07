package viracochan

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMigrateLegacyConfig(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"legacy":true}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signLegacyFixture(cfg, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}

	legacySig := cfg.Meta.Signature
	if err := MigrateLegacyConfig(cfg, signer); err != nil {
		t.Fatalf("MigrateLegacyConfig failed: %v", err)
	}

	if cfg.Meta.SigAlg != SignatureAlgorithmV2 {
		t.Fatalf("expected sig_alg %q, got %q", SignatureAlgorithmV2, cfg.Meta.SigAlg)
	}
	if cfg.Meta.Signature == legacySig {
		t.Fatal("expected migrated signature to differ from legacy signature")
	}
	if err := signer.Verify(cfg, signer.PublicKey()); err != nil {
		t.Fatalf("migrated signature verification failed: %v", err)
	}
}

func TestManagerMigrateLegacySignatures(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	manager, err := NewManager(storage, WithSigner(signer))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"version":1}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signLegacyFixture(cfg, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}
	if err := manager.configStore.Save(ctx, "legacy-config", cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	entry := &JournalEntry{
		ID:        "legacy-config",
		Version:   cfg.Meta.Version,
		CS:        cfg.Meta.CS,
		PrevCS:    cfg.Meta.PrevCS,
		Time:      cfg.Meta.Time,
		Operation: "create",
		Config:    cloneConfig(cfg),
	}
	if err := manager.journal.Append(ctx, entry); err != nil {
		t.Fatalf("Append failed: %v", err)
	}

	report, err := manager.MigrateLegacySignatures(ctx, SignatureMigrationOptions{})
	if err != nil {
		t.Fatalf("MigrateLegacySignatures failed: %v", err)
	}

	if report.ConfigFilesMigrated != 1 {
		t.Fatalf("expected 1 migrated config file, got %+v", report)
	}
	if report.JournalEntriesMigrated != 1 {
		t.Fatalf("expected 1 migrated journal entry, got %+v", report)
	}

	loaded, err := manager.configStore.Load(ctx, "legacy-config", cfg.Meta.Version)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Meta.SigAlg != SignatureAlgorithmV2 {
		t.Fatalf("expected config sig_alg %q, got %q", SignatureAlgorithmV2, loaded.Meta.SigAlg)
	}
	if err := signer.Verify(loaded, signer.PublicKey()); err != nil {
		t.Fatalf("migrated config verification failed: %v", err)
	}

	entries, err := manager.journal.ReadAll(ctx)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 journal entry, got %d", len(entries))
	}
	if entries[0].Config == nil {
		t.Fatal("expected journal entry config to be present")
	}
	if entries[0].Config.Meta.SigAlg != SignatureAlgorithmV2 {
		t.Fatalf("expected journal sig_alg %q, got %q", SignatureAlgorithmV2, entries[0].Config.Meta.SigAlg)
	}
	if err := signer.Verify(entries[0].Config, signer.PublicKey()); err != nil {
		t.Fatalf("migrated journal entry verification failed: %v", err)
	}
}

func TestManagerMigrateLegacySignaturesDryRun(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	manager, err := NewManager(storage, WithSigner(signer))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"version":1}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signLegacyFixture(cfg, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}
	if err := manager.configStore.Save(ctx, "legacy-config", cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	report, err := manager.MigrateLegacySignatures(ctx, SignatureMigrationOptions{DryRun: true})
	if err != nil {
		t.Fatalf("MigrateLegacySignatures dry-run failed: %v", err)
	}
	if report.ConfigFilesMigrated != 1 {
		t.Fatalf("expected 1 migrated config file in dry-run, got %+v", report)
	}

	loaded, err := manager.configStore.Load(ctx, "legacy-config", cfg.Meta.Version)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Meta.SigAlg != "" {
		t.Fatalf("expected legacy config to remain unchanged in dry-run, got %q", loaded.Meta.SigAlg)
	}
}

func TestManagerMigrateLegacySignaturesRejectsBrokenChain(t *testing.T) {
	ctx := context.Background()
	storage := NewMemoryStorage()
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	manager, err := NewManager(storage, WithSigner(signer))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	cfg1 := &Config{
		Content: json.RawMessage(`{"version":1}`),
	}
	if err := cfg1.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signLegacyFixture(cfg1, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}
	if err := manager.configStore.Save(ctx, "broken-chain", cfg1); err != nil {
		t.Fatalf("Save cfg1 failed: %v", err)
	}

	cfgBroken := &Config{
		Meta:    cfg1.Meta,
		Content: json.RawMessage(`{"version":3}`),
	}
	if err := cfgBroken.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	cfgBroken.Meta.Version = 3
	cs, err := computeChecksum(cfgBroken)
	if err != nil {
		t.Fatalf("computeChecksum failed: %v", err)
	}
	cfgBroken.Meta.CS = cs
	if err := signLegacyFixture(cfgBroken, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}
	if err := manager.configStore.Save(ctx, "broken-chain", cfgBroken); err != nil {
		t.Fatalf("Save cfgBroken failed: %v", err)
	}

	if _, err := manager.MigrateLegacySignatures(ctx, SignatureMigrationOptions{}); err == nil {
		t.Fatal("expected migration to reject broken chain")
	}

	loaded1, err := manager.configStore.Load(ctx, "broken-chain", 1)
	if err != nil {
		t.Fatalf("Load cfg1 failed: %v", err)
	}
	if loaded1.Meta.SigAlg != "" {
		t.Fatalf("expected cfg1 to remain unmigrated, got %q", loaded1.Meta.SigAlg)
	}

	loadedBroken, err := loadConfigAtPath(ctx, manager.storage, manager.configStore.makeKey("broken-chain", 3))
	if err != nil {
		t.Fatalf("Load cfgBroken failed: %v", err)
	}
	if loadedBroken.Meta.SigAlg != "" {
		t.Fatalf("expected broken config to remain unmigrated, got %q", loadedBroken.Meta.SigAlg)
	}
}
