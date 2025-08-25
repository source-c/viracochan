# Viracochan Demo Applications

This directory contains sophisticated demonstration applications that showcase the full range of Viracochan's features and capabilities. Each demo covers specific advanced use cases and implementation patterns.

## Demo Applications

### 1. `demo-distributed` - Distributed Configuration Management
**Features demonstrated:**
- Multi-node configuration synchronization
- Cryptographic signature verification across nodes
- Configuration distribution and replication
- Node recovery and reconstruction
- Real-time configuration watching
- Emergency updates propagation

**Run:** `go run ./cmd/demo-distributed`

**Flags:**
- `-nodes`: Number of nodes to simulate (default: 3)
- `-dir`: Base directory for node storage (default: ./distributed-demo)

---

### 2. `demo-disaster-recovery` - Disaster Recovery & State Reconstruction
**Features demonstrated:**
- Recovery from corrupted journal entries
- Reconstruction from scattered configuration files
- Handling out-of-order journal entries
- Fork detection and resolution
- Partial recovery strategies
- Journal rebuilding from fragments

**Run:** `go run ./cmd/demo-disaster-recovery`

**Flags:**
- `-dir`: Data directory (default: ./disaster-recovery-demo)
- `-chaos`: Enable chaos mode for testing (default: true)

---

### 3. `demo-migration` - Storage Migration & Multi-Backend Support
**Features demonstrated:**
- Migration between different storage backends
- Custom storage implementation (S3 simulation)
- Caching layer implementation
- Network latency and failure simulation
- Validated migration with integrity checks
- Cross-storage verification

**Run:** `go run ./cmd/demo-migration`

**Flags:**
- `-source`: Source storage directory (default: ./migration-source)
- `-target`: Target storage directory (default: ./migration-target)
- `-s3`: Simulated S3 storage directory (default: ./migration-s3)

---

### 4. `demo-audit-trail` - Audit Trail & Compliance
**Features demonstrated:**
- Comprehensive audit logging
- Multi-actor configuration management
- Signature chain verification
- Compliance rule checking
- Forensic analysis capabilities
- Activity timeline and pattern detection
- Rollback operations with audit trail

**Run:** `go run ./cmd/demo-audit-trail`

**Flags:**
- `-dir`: Data directory (default: ./audit-demo)
- `-actors`: Number of actors to simulate (default: 3)

---

### 5. `demo-concurrent` - Concurrent Operations & Conflict Resolution
**Features demonstrated:**
- Concurrent configuration updates
- Real-time change watching
- Conflict detection and resolution strategies
- Consistency verification across workers
- Performance monitoring
- Chain validation under concurrent load

**Run:** `go run ./cmd/demo-concurrent`

**Flags:**
- `-dir`: Data directory (default: ./concurrent-demo)
- `-workers`: Number of concurrent workers (default: 5)
- `-duration`: Test duration (default: 10s)
- `-strategy`: Conflict resolution strategy [merge|last-write-wins|manual] (default: merge)
- `-rate`: Update rate per worker (default: 200ms)

---

### 6. `demo-encryption` - Encrypted Storage Layer
**Features demonstrated:**
- Custom storage wrapper implementation
- AES-256-GCM encryption
- Compression layer
- Integrity checking with checksums
- Layered storage architecture
- Performance analysis with encryption overhead
- Key management

**Run:** `go run ./cmd/demo-encryption`

**Flags:**
- `-dir`: Data directory (default: ./encryption-demo)
- `-key`: 32-byte encryption key in hex (optional, generates if not provided)
- `-compress`: Enable compression (default: true)

---

### 7. `demo-simple` - Basic Usage Example
A simple example showing basic Viracochan operations:
- Configuration creation and updates
- Version history management
- Chain validation
- Export/import functionality
- Signature verification

**Run:** `go run ./cmd/demo-simple [storage-directory]`

## Running All Demos

To run all demos in sequence:

```bash
#!/bin/bash
for demo in demo-distributed demo-disaster-recovery demo-migration \
           demo-audit-trail demo-concurrent demo-encryption; do
    echo "Running $demo..."
    go run ./cmd/$demo -duration 5s 2>&1 | tee $demo.log
    echo "---"
    sleep 2
done
```

## Key Concepts Demonstrated

### Cryptographic Integrity
- All demos showcase SHA-256 checksums for data integrity
- Signature verification using secp256k1 (Nostr-style)
- Chain validation ensuring version continuity

### Storage Abstraction
- File storage, memory storage, and custom implementations
- Storage migration between backends
- Encryption and compression layers
- Integrity checking wrappers

### Distributed Systems
- Multi-node synchronization
- Conflict resolution strategies
- Eventual consistency patterns
- Watch mechanisms for real-time updates

### Resilience & Recovery
- Reconstruction from partial data
- Journal resequencing algorithms
- Fork detection and handling
- Corruption recovery

### Compliance & Auditing
- Complete audit trails
- Multi-actor attribution
- Compliance rule validation
- Forensic analysis capabilities

## Architecture Patterns

Each demo illustrates production-ready patterns:

1. **Layered Storage**: Demos show how to wrap storage with additional capabilities (encryption, caching, integrity)
2. **Event Sourcing**: Journal-based architecture for audit and reconstruction
3. **Chain of Trust**: Cryptographic linking of versions
4. **Optimistic Concurrency**: Conflict detection and resolution
5. **Disaster Recovery**: Multiple recovery strategies from various failure modes

## Performance Considerations

The demos include performance monitoring:
- Operation timing and throughput metrics
- Cache hit rates and optimization
- Encryption overhead analysis
- Concurrent operation statistics

## Security Features

Security aspects demonstrated:
- End-to-end encryption of sensitive data
- Signature-based authentication
- Integrity verification at multiple layers
- Audit logging for compliance

## Extending the Demos

Each demo can be extended for specific use cases:
- Add custom storage backends
- Implement different conflict resolution strategies
- Create specialized compliance rules
- Add monitoring and metrics collection
- Integrate with external systems

## Testing & Validation

The demos include comprehensive validation:
- Chain integrity verification
- Signature validation
- Cross-storage consistency checks
- Performance benchmarking
- Failure injection and recovery

## Production Considerations

When adapting these demos for production:
1. Implement proper error handling and logging
2. Add metrics and monitoring
3. Configure appropriate timeouts and retries
4. Implement backup and restore procedures
5. Add rate limiting and resource management
6. Consider security hardening for key management
7. Implement proper access control
