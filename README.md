# Viracochan

A Go library for versioned configuration management with cryptographic integrity, journaling, and state reconstruction capabilities.

## Features

- **Versioned Configurations**: Every change creates a new immutable version
- **Cryptographic Integrity**: SHA-256 checksums ensure data integrity
- **Chain Validation**: Each version links to its predecessor via checksums
- **Journaling**: All changes are recorded in an append-only journal
- **State Reconstruction**: Rebuild state from scattered data sources
- **Optional Signing**: Nostr-style secp256k1 signatures for authenticity
- **Storage Abstraction**: Works with any filesystem-like storage backend
- **Deterministic Checksums**: Canonical JSON ensures reproducible checksums

## Installation

```bash
go get github.com/source-c/viracochan
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    "github.com/source-c/viracochan"
)

func main() {
    ctx := context.Background()

    // Create storage backend
    storage := viracochan.NewMemoryStorage()

    // Create manager
    manager, err := viracochan.NewManager(storage)
    if err != nil {
        log.Fatal(err)
    }

    // Create configuration
    config := map[string]interface{}{
        "database": map[string]interface{}{
            "host": "localhost",
            "port": 5432,
        },
    }

    cfg, err := manager.Create(ctx, "app-config", config)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Created config version %d", cfg.Meta.Version)
}
```

## Core Concepts

### Configuration Metadata

Every configuration has metadata that ensures integrity and tracks history:

```go
type Meta struct {
    Version   uint64    `json:"v"`                 // Auto-incremented version
    Time      time.Time `json:"t"`                 // UTC timestamp
    PrevCS    string    `json:"prev_cs,omitempty"` // Previous version's checksum
    CS        string    `json:"cs"`                // Current checksum
    Signature string    `json:"sig,omitempty"`     // Optional cryptographic signature
}
```

### Chain Validation

Configurations form a chain where each version:
- Has a version number exactly 1 higher than its predecessor
- Contains the checksum of the previous version
- Has a timestamp >= its predecessor
- Has a valid checksum of its canonical content

### Journaling

All operations are recorded in a journal that enables:
- Audit trail of all changes
- State reconstruction from journal entries
- Recovery from scattered or incomplete data

### State Reconstruction

The library can reconstruct the latest state from various sources:
- Complete journal entries
- Scattered configuration files
- Out-of-order entries (using the `Resequence` algorithm)

## Storage Backends

### Memory Storage (Testing)

```go
storage := viracochan.NewMemoryStorage()
```

### File Storage (Production)

```go
storage, err := viracochan.NewFileStorage("/var/lib/myapp/configs")
```

### Custom Storage

Implement the `Storage` interface:

```go
type Storage interface {
    Read(ctx context.Context, path string) ([]byte, error)
    Write(ctx context.Context, path string, data []byte) error
    List(ctx context.Context, prefix string) ([]string, error)
    Delete(ctx context.Context, path string) error
    Exists(ctx context.Context, path string) (bool, error)
}
```

## Cryptographic Signing

Enable Nostr-style secp256k1 signatures for authentication:

```go
// Create signer
signer, err := viracochan.NewSigner()

// Or use existing private key
signer, err := viracochan.NewSignerFromKey(privateKey)

// Create manager with signing
manager, err := viracochan.NewManager(
    storage,
    viracochan.WithSigner(signer),
)

// Verify signatures
err = manager.Verify(cfg, signer.PublicKey())
```

## Advanced Usage

### Configuration History

```go
// Get all versions
history, err := manager.GetHistory(ctx, "config-id")

// Get specific version
cfg, err := manager.Get(ctx, "config-id", 3)

// Get latest version
latest, err := manager.GetLatest(ctx, "config-id")
```

### Rollback

```go
// Rollback to version 3 (creates new version with old content)
rolled, err := manager.Rollback(ctx, "config-id", 3)
```

### State Reconstruction

```go
// Reconstruct from journal and scattered files
cfg, err := manager.Reconstruct(ctx, "config-id")

// Resequence out-of-order journal entries
journal := viracochan.NewJournal(storage, "journal.jsonl")
entries, _ := journal.ReadAll(ctx)
ordered, err := journal.Resequence(entries)
```

### Import/Export

```go
// Export configuration
data, err := manager.Export(ctx, "config-id")

// Import configuration
err = manager.Import(ctx, "new-id", data)
```

### Watch for Changes

```go
// Watch for configuration updates
ch, err := manager.Watch(ctx, "config-id", 1*time.Second)

for cfg := range ch {
    log.Printf("Config updated to version %d", cfg.Meta.Version)
}
```

### Journal Compaction

```go
// Compact journal to reduce size (keeps recent entries)
err = manager.Compact(ctx)
```

## Validation

The library provides comprehensive validation:

```go
// Validate single configuration
err = cfg.Validate()

// Validate chain continuity
err = cfg2.NextOf(cfg1)

// Validate entire chain
err = manager.ValidateChain(ctx, "config-id")

// Verify signatures in chain
configs, _ := manager.GetHistory(ctx, "config-id")
err = viracochan.VerifyChainSignatures(configs, publicKey)
```

## Design Philosophy

Viracochan follows these principles:

1. **Immutability**: Once created, versions never change
2. **Determinism**: Same content always produces same checksum
3. **Forward Linking**: Each version knows its predecessor
4. **Self-Validation**: Configurations validate their own integrity
5. **Reconstruction**: State can be rebuilt from any combination of valid data

## Implementation Details

### Canonical JSON

The library uses canonical JSON for deterministic checksums:
- Keys are sorted alphabetically
- Timestamps use RFC3339 with microsecond precision
- Consistent handling of empty/nil values
- No unnecessary whitespace

### Checksum Calculation

```
checksum = SHA256(canonical_json_without_cs + timestamp_string)
```

### Version Chain

```
v1 (cs: abc...) → v2 (prev_cs: abc..., cs: def...) → v3 (prev_cs: def..., cs: ghi...)
```

## Testing

Run the comprehensive test suite:

```bash
go test ./...
```

Run with race detection:

```bash
go test -race ./...
```

