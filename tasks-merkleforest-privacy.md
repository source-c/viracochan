# MerkleForest Privacy Implementation Plan (v3 — verified)

**Goal:** Evolve Viracochan from a transparent versioned-config chain (SHA-256 checksums) into the full MerkleForest privacy architecture — hiding commitments, per-chain Incremental Merkle Trees, cross-chain forest root, ZK proof circuits, and selective disclosure.

**Architecture:** Five layered phases. Each phase is backward-compatible — existing SHA-256 chains continue to validate; new privacy features are opt-in via `ManagerOption`s. The commitment layer (Poseidon) forms a self-referential chain parallel to the existing CS chain: each commitment links to its predecessor via `PrevCommit`, not `PrevCS`. Native Poseidon and in-circuit Poseidon use the **same two-field-element input format** to guarantee proof compatibility.

**Tech Stack:** Go 1.22+, `github.com/consensys/gnark-crypto` (native Poseidon/BN254), `github.com/consensys/gnark` (ZK circuits, PLONK), `lukechampine.com/blake3` (chain ordering), `github.com/btcsuite/btcd/btcec/v2` (existing Schnorr signatures).

---

## Key Design Decisions (derived from article)

These resolve the issues found in plan v1. Every item traces to the article.

### D1: Two-stage Poseidon commitment

The ZK circuit operates on exactly two field elements: `Poseidon(transcriptHash, blinding)`. The native code must produce the same output. Therefore:

```
transcriptHash = Poseidon(bytesToFieldElements(transcript)...)   // variable-length → 1 field element
commitment     = Poseidon(transcriptHash, blindingFieldElement)  // always exactly 2 inputs
```

The circuit proves knowledge of `(transcriptHash, blinding)` such that `Poseidon(transcriptHash, blinding) == Commit`. This is the binding property.

### D2: Self-referential commitment chain

The article specifies `"prev:" || PrevCommit_bytes` in the transcript — the previous version's **commitment**, not its SHA-256 checksum. This means:
- `Meta` gets a `PrevCommit` field
- The commitment chain is self-linking: `PrevCommit → Commit`, parallel to `PrevCS → CS`
- `UpdateMeta` must clear `Commit`, `CommitAlg`, `PrevCommit`, `IMTRoot`

### D3: BLAKE3 chain ordering

The article specifies `BLAKE3(ChainPubKey)` for deterministic chain ordering in the forest. We use `BLAKE3(chainID)` as a stepping stone (per-chain keys are a Phase 6 extension), but use the correct hash function now.

### D4: Bulletin stores only ForestRoot

The article says "digest of all chain roots." The bulletin stores only `ForestRoot` and a signed `ChainRootsDigest` — not the individual chain roots. Disclosure includes a **forest inclusion proof** for the specific chain.

### D5: Fixed-depth IMT with frontier and zero hashes

The article's pseudocode shows a frontier-based append. However, that pseudocode is a sketch — the returned `node` is NOT the Merkle root for non-power-of-2 leaf counts. A real implementation needs a **fixed-depth balanced tree with pre-computed zero hashes** so that `Root()` and membership proofs agree on the tree structure.

The IMT uses:
- A configurable `depth` (default 32, supporting up to 2^32 leaves)
- Pre-computed `zeros[level] = Poseidon(zeros[level-1], zeros[level-1])` for empty subtrees
- A `frontier[level]` array tracking the most recent filled node at each level
- `Append` walks levels bottom-up, combining with frontier or zeros (O(log n))
- `Root()` walks frontier top-down, combining with zeros for unfilled positions
- `BuildMembershipProof` uses the same zero-padded balanced tree structure

The article's frontier pattern is preserved for O(log n) append; the depth/zeros system ensures Root() and proofs produce consistent roots.

Leaves are canonicalized before insertion: `leaf_i = Poseidon("leaf", i, commitment_i, prevCommit_i)`. This binds the position into the leaf hash (preventing reordering attacks) and separates the leaf domain from internal nodes (preventing leaf/node confusion).

Membership proof generation requires all canonical leaves (reconstructed from journal commitment entries on demand), not stored in the IMT struct.

### D6: Forest uses balanced Merkle tree (improvement over article)

The article's `BuildForestRoot` uses a sequential fold: `node = hashPair(node, r)` for each chain root. This produces a different root than a balanced Merkle tree, and proving a single chain's inclusion in a sequential fold requires O(n) work.

We use a balanced Merkle tree of chain roots (BLAKE3-ordered, zero-padded to power of 2) instead. This enables O(log n) forest inclusion proofs, which are essential for disclosure — the verifier can confirm a chain is in the forest without seeing all chain roots.

### D7: Two-stage Poseidon (necessary adaptation)

The article's `poseidon.Hash(append(message, r[:]))` is pseudocode — Poseidon operates on field elements, not byte arrays. Our adaptation:
- **Stage 1**: compress variable-length transcript to one field element: `transcriptHash = Poseidon(bytesToFieldElements(transcript)...)`
- **Stage 2**: commit with blinding: `Poseidon(transcriptHash, blindingFieldElement)`

This ensures the ZK circuit (which takes exactly two field element inputs) matches the native computation exactly.

**Poseidon variant pinning:** Both native (`gnark-crypto/ecc/bn254/fr/poseidon`) and circuit (`gnark/std/hash/poseidon`) must use the same Poseidon parameterization (same round constants, same number of rounds). Pin both `gnark-crypto` and `gnark` versions in `go.mod` to a known-compatible pair. The `TestCommitmentCircuit_MatchesNative` cross-test catches mismatches, but version drift is the #1 source of silent failures in gnark projects. Add a constant documenting the pinned versions:
```go
const PoseidonVariant = "gnark-crypto/poseidon-bn254 (gnark-crypto v0.14.x, gnark v0.11.x)"
```

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `commitment.go` | Two-stage Poseidon commitment, blinding factors, domain-separated transcript |
| `commitment_test.go` | Tests including native/circuit alignment verification |
| `imt.go` | Frontier-only IMT: append, root. Separate proof generation from stored leaves. |
| `imt_test.go` | Tests including Append-return vs Root() consistency |
| `forest.go` | Forest as Merkle tree of chain roots (BLAKE3-ordered), bulletins, forest inclusion proofs |
| `forest_test.go` | Tests |
| `circuits/circuits.go` | Shared types, PLONK setup wrappers |
| `circuits/commitment.go` | Commitment correctness circuit (2 field elements) |
| `circuits/inclusion.go` | Merkle inclusion circuit |
| `circuits/transition.go` | Transition predicate circuit |
| `circuits/circuits_test.go` | Prove/verify round-trips, native/circuit consistency |
| `disclosure.go` | Content disclosure + ZK disclosure, verifier API |
| `disclosure_test.go` | Tests for both disclosure modes |
| `privacy_integration_test.go` | End-to-end tests |

### Modified Files

| File | Changes |
|------|---------|
| `meta.go` | `Meta` gains `Commit`, `CommitAlg`, `PrevCommit`, `IMTRoot` fields. `computeChecksum` and `UpdateMeta` exclude/clear them. |
| `journal.go` | `JournalEntry` gains `Commit`, `PrevCommit` fields. `ValidateChain` loads from config store in privacy mode. |
| `manager.go` | `Manager` gains `blindingStore`, `imts`, `imtDepth`, `forest`. New options: `WithCommitment()`, `WithIMT()`, `WithForest()`. `NewManager` accepts `ctx` for init. |
| `storage.go` | `BlindingStore` interface + `MemoryBlindingStore`. |
| `go.mod` | Add `gnark-crypto`, `gnark`, `lukechampine.com/blake3`. |

---

## Phase 1: Poseidon Commitments & Blinding Factors

### Task 1.1: Dependencies and two-stage Poseidon primitive

**Files:**
- Modify: `go.mod`
- Create: `commitment.go`
- Create: `commitment_test.go`

- [ ] **Step 1: Add dependencies**

```bash
go get github.com/consensys/gnark-crypto@latest && go get lukechampine.com/blake3@latest
```

- [ ] **Step 2: Write failing tests**

```go
// commitment_test.go
package viracochan

import (
    "math/big"
    "testing"

    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

func TestTwoStagePoseidon_Deterministic(t *testing.T) {
    msg := []byte("test-message")
    blind := make([]byte, 32)
    for i := range blind {
        blind[i] = byte(i)
    }

    c1, err := poseidonCommit(msg, blind)
    if err != nil {
        t.Fatal(err)
    }
    c2, err := poseidonCommit(msg, blind)
    if err != nil {
        t.Fatal(err)
    }
    if c1 != c2 {
        t.Errorf("not deterministic: %s != %s", c1, c2)
    }
}

func TestTwoStagePoseidon_BlindingChangesOutput(t *testing.T) {
    msg := []byte("test-message")
    b1 := make([]byte, 32)
    b2 := make([]byte, 32)
    b2[0] = 1

    c1, _ := poseidonCommit(msg, b1)
    c2, _ := poseidonCommit(msg, b2)
    if c1 == c2 {
        t.Error("different blindings produced same commitment")
    }
}

func TestFieldElementHex_RoundTrip(t *testing.T) {
    // Verify fieldElementToHex/hexToFieldElement are inverse operations.
    // If Marshal() uses Montgomery form and SetBigInt expects standard form,
    // this test catches the mismatch.
    var original fr.Element
    original.SetInt64(123456789)

    hex := fieldElementToHex(original)
    restored, err := hexToFieldElement(hex)
    if err != nil {
        t.Fatal(err)
    }
    if original != restored {
        t.Errorf("round-trip failed: original=%v restored=%v", original, restored)
    }

    // Also test with a Poseidon output (may have different bit patterns)
    var a, b fr.Element
    a.SetInt64(42)
    b.SetInt64(99)
    digest := poseidon.Sum(a, b)
    hex2 := fieldElementToHex(digest)
    restored2, _ := hexToFieldElement(hex2)
    if digest != restored2 {
        t.Error("round-trip failed for Poseidon output")
    }
}

func TestTwoStagePoseidon_MatchesCircuitFormat(t *testing.T) {
    // Verify that poseidonCommit(msg, blind) == Poseidon(Poseidon(chunks...), blindElem)
    // by manually constructing the two-stage computation.
    msg := []byte("hello-world-transcript")
    blind := make([]byte, 32)
    blind[0] = 99

    commit, err := poseidonCommit(msg, blind)
    if err != nil {
        t.Fatal(err)
    }

    // Stage 1: hash message chunks to one field element
    chunks, _ := bytesToFieldElements(msg)
    transcriptHash := poseidon.Sum(chunks...)

    // Stage 2: Poseidon(transcriptHash, blindElem) — exactly 2 inputs
    var blindElem fr.Element
    blindElem.SetBigInt(new(big.Int).SetBytes(blind))
    expected := poseidon.Sum(transcriptHash, blindElem)

    expectedHex := fieldElementToHex(expected)
    if commit != expectedHex {
        t.Errorf("poseidonCommit does not match two-stage manual computation\ngot:  %s\nwant: %s", commit, expectedHex)
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test -run "TestTwoStagePoseidon" -v
```

- [ ] **Step 4: Implement two-stage poseidonCommit**

```go
// commitment.go
package viracochan

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "math/big"

    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

const (
    CommitAlgPoseidonV1 = "vc-poseidon-bn254-v1"
    BlindingSize        = 32
)

var (
    ErrInvalidBlinding    = errors.New("invalid blinding factor")
    ErrCommitmentMismatch = errors.New("commitment mismatch")
)

// poseidonCommit computes a two-stage Poseidon commitment over BN254:
//   Stage 1: transcriptHash = Poseidon(bytesToFieldElements(msg)...)
//   Stage 2: commitment = Poseidon(transcriptHash, blindingFieldElement)
// This matches the ZK circuit's two-field-element input format exactly.
func poseidonCommit(msg, blind []byte) (string, error) {
    if len(blind) != BlindingSize {
        return "", fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidBlinding, BlindingSize, len(blind))
    }

    // Stage 1: compress variable-length transcript into one field element
    chunks, err := bytesToFieldElements(msg)
    if err != nil {
        return "", err
    }
    transcriptHash := poseidon.Sum(chunks...)

    // Stage 2: Poseidon(transcriptHash, blinding) — exactly 2 field elements
    var blindElem fr.Element
    blindElem.SetBigInt(new(big.Int).SetBytes(blind))

    commit := poseidon.Sum(transcriptHash, blindElem)
    return fieldElementToHex(commit), nil
}

func generateBlinding() ([]byte, error) {
    blind := make([]byte, BlindingSize)
    if _, err := rand.Read(blind); err != nil {
        return nil, err
    }
    return blind, nil
}

// bytesToFieldElements encodes a byte slice as BN254 field elements with a
// length prefix to prevent ambiguity. Without the prefix, trailing-zero
// differences (e.g. [0x01] vs [0x01,0x00]) collapse to the same element,
// breaking the binding property for those input pairs.
func bytesToFieldElements(data []byte) ([]fr.Element, error) {
    const chunkSize = 31 // < BN254 modulus size

    // Length prefix: first element encodes the byte length of data.
    var lenElem fr.Element
    lenElem.SetUint64(uint64(len(data)))
    elems := []fr.Element{lenElem}

    for i := 0; i < len(data); i += chunkSize {
        end := i + chunkSize
        if end > len(data) {
            end = len(data)
        }
        var e fr.Element
        e.SetBigInt(new(big.Int).SetBytes(data[i:end]))
        elems = append(elems, e)
    }
    return elems, nil
}

func fieldElementToHex(e fr.Element) string {
    return hex.EncodeToString(e.Marshal())
}

func hexToFieldElement(h string) (fr.Element, error) {
    b, err := hex.DecodeString(h)
    if err != nil {
        return fr.Element{}, err
    }
    var e fr.Element
    // SetBytesCanonical matches Marshal() — both use the same encoding.
    // No fallback: if this fails, the gnark-crypto version must be pinned
    // to one that supports SetBytesCanonical. A silent fallback to SetBigInt
    // would break the round-trip invariant and corrupt every hash comparison.
    if err := e.SetBytesCanonical(b); err != nil {
        return fr.Element{}, fmt.Errorf("non-canonical field element: %w", err)
    }
    return e, nil
}
```

- [ ] **Step 5: Run tests**

```bash
go test -run "TestTwoStagePoseidon" -v
```

---

### Task 1.2: Domain-separated transcript with PrevCommit

**Files:**
- Modify: `meta.go:22-29` (add PrevCommit, Commit, CommitAlg, IMTRoot to Meta)
- Modify: `meta.go:38-57` (exclude new fields from computeChecksum)
- Modify: `meta.go:95-109` (UpdateMeta clears new fields)
- Modify: `commitment.go`
- Modify: `commitment_test.go`

- [ ] **Step 1: Extend Meta struct**

```go
// meta.go
type Meta struct {
    Version    uint64    `json:"v"`
    Time       time.Time `json:"t"`
    PrevCS     string    `json:"prev_cs,omitempty"`
    CS         string    `json:"cs"`
    Signature  string    `json:"sig,omitempty"`
    SigAlg     string    `json:"sig_alg,omitempty"`
    PrevCommit string    `json:"prev_commit,omitempty"`
    Commit     string    `json:"commit,omitempty"`
    CommitAlg  string    `json:"commit_alg,omitempty"`
    IMTRoot    string    `json:"imt_root,omitempty"`
}
```

- [ ] **Step 2: Update computeChecksum to exclude all privacy fields**

```go
func computeChecksum(c *Config) (string, error) {
    tmp := *c
    tmp.Meta.CS = ""
    tmp.Meta.Signature = ""
    tmp.Meta.SigAlg = ""
    tmp.Meta.PrevCommit = ""
    tmp.Meta.Commit = ""
    tmp.Meta.CommitAlg = ""
    tmp.Meta.IMTRoot = ""
    // ... rest unchanged (canonicalJSON, timestamp append, SHA-256)
```

- [ ] **Step 3: Update UpdateMeta to clear privacy fields**

```go
func (c *Config) UpdateMeta() error {
    c.Meta.Time = time.Now().UTC().Truncate(time.Microsecond)
    c.Meta.Version++
    c.Meta.PrevCS = c.Meta.CS
    c.Meta.CS = ""
    c.Meta.Signature = ""
    c.Meta.SigAlg = ""
    // Carry forward previous commitment for the commitment chain
    c.Meta.PrevCommit = c.Meta.Commit
    c.Meta.Commit = ""
    c.Meta.CommitAlg = ""
    c.Meta.IMTRoot = ""

    cs, err := computeChecksum(c)
    if err != nil {
        return err
    }
    c.Meta.CS = cs
    return nil
}
```

The key line: `c.Meta.PrevCommit = c.Meta.Commit` — this carries the previous version's commitment into PrevCommit, forming the self-referential commitment chain per the article's `"prev:" || PrevCommit_bytes`.

- [ ] **Step 4: Write failing tests for buildTranscript**

```go
// commitment_test.go (add)

func TestBuildTranscript_UsesPrevCommit(t *testing.T) {
    cfg := &Config{
        Meta: Meta{
            Version:    3,
            Time:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
            PrevCommit: "deadbeef01234567",
            PrevCS:     "should-not-appear",
        },
        Content: json.RawMessage(`{"key":"value"}`),
    }

    transcript, err := buildTranscript(cfg)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.HasPrefix(transcript, []byte("MVPCHAIN|v2")) {
        t.Error("missing domain prefix")
    }
    if !bytes.Contains(transcript, []byte("prev:deadbeef01234567")) {
        t.Error("transcript should use PrevCommit, not PrevCS")
    }
    if bytes.Contains(transcript, []byte("should-not-appear")) {
        t.Error("transcript must NOT use PrevCS")
    }
}

func TestBuildTranscript_V1_EmptyPrevCommit(t *testing.T) {
    cfg := &Config{
        Meta: Meta{
            Version: 1,
            Time:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
        },
        Content: json.RawMessage(`{"v":1}`),
    }

    transcript, err := buildTranscript(cfg)
    if err != nil {
        t.Fatal(err)
    }

    if !bytes.Contains(transcript, []byte("prev:")) {
        t.Error("prev: tag should always be present")
    }
}

func TestBuildTranscript_Deterministic(t *testing.T) {
    cfg := &Config{
        Meta: Meta{Version: 1, Time: time.Date(2025, 6, 15, 12, 0, 0, 123000, time.UTC)},
        Content: json.RawMessage(`{"b":2,"a":1}`),
    }

    t1, _ := buildTranscript(cfg)
    t2, _ := buildTranscript(cfg)
    if !bytes.Equal(t1, t2) {
        t.Error("not deterministic")
    }
}
```

- [ ] **Step 5: Implement buildTranscript using PrevCommit**

```go
// commitment.go (add)

import (
    "encoding/binary"
    "time"
)

const transcriptDomain = "MVPCHAIN|v2"

// buildTranscript produces the domain-separated canonical bytes.
// Per the article: "prev:" field uses PrevCommit (commitment chain), NOT PrevCS (checksum chain).
func buildTranscript(cfg *Config) ([]byte, error) {
    ts := cfg.Meta.Time.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)

    var verBytes [8]byte
    binary.BigEndian.PutUint64(verBytes[:], cfg.Meta.Version)

    body, err := canonicalJSON(cfg.Content)
    if err != nil {
        return nil, err
    }

    var buf []byte
    buf = append(buf, []byte(transcriptDomain)...)
    buf = append(buf, []byte("time:")...)
    buf = append(buf, []byte(ts)...)
    buf = append(buf, []byte("ver:")...)
    buf = append(buf, verBytes[:]...)
    buf = append(buf, []byte("prev:")...)
    buf = append(buf, []byte(cfg.Meta.PrevCommit)...)  // PrevCommit, NOT PrevCS
    buf = append(buf, []byte("body:")...)
    buf = append(buf, body...)

    return buf, nil
}
```

- [ ] **Step 6: Run all tests (existing + new)**

```bash
go test ./... -v
```

All existing tests must pass — new Meta fields are `omitempty`, unused by legacy paths.

---

### Task 1.3: Config commitment and verification

**Files:**
- Modify: `commitment.go`
- Modify: `commitment_test.go`

- [ ] **Step 1: Write failing tests**

```go
// commitment_test.go (add)

func TestComputeConfigCommitment_RoundTrip(t *testing.T) {
    cfg := &Config{
        Meta: Meta{Version: 1, Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
        Content: json.RawMessage(`{"key":"value"}`),
    }

    commit, blind, err := computeCommitment(cfg)
    if err != nil {
        t.Fatal(err)
    }
    if commit == "" {
        t.Error("empty commitment")
    }
    if len(blind) != BlindingSize {
        t.Errorf("wrong blind size: %d", len(blind))
    }

    cfg.Meta.Commit = commit
    if err := verifyCommitment(cfg, blind); err != nil {
        t.Errorf("verification failed: %v", err)
    }
}

func TestVerifyCommitment_TamperedContent_Fails(t *testing.T) {
    cfg := &Config{
        Meta: Meta{Version: 1, Time: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
        Content: json.RawMessage(`{"key":"value"}`),
    }

    commit, blind, _ := computeCommitment(cfg)
    cfg.Meta.Commit = commit
    cfg.Content = json.RawMessage(`{"key":"tampered"}`)

    if err := verifyCommitment(cfg, blind); err == nil {
        t.Error("should fail with tampered content")
    }
}
```

- [ ] **Step 2: Implement computeCommitment and verifyCommitment**

```go
// commitment.go (add)

func computeCommitment(cfg *Config) (string, []byte, error) {
    transcript, err := buildTranscript(cfg)
    if err != nil {
        return "", nil, err
    }
    blind, err := generateBlinding()
    if err != nil {
        return "", nil, err
    }
    commit, err := poseidonCommit(transcript, blind)
    if err != nil {
        return "", nil, err
    }
    return commit, blind, nil
}

func verifyCommitment(cfg *Config, blind []byte) error {
    transcript, err := buildTranscript(cfg)
    if err != nil {
        return err
    }
    recomputed, err := poseidonCommit(transcript, blind)
    if err != nil {
        return err
    }
    if recomputed != cfg.Meta.Commit {
        return fmt.Errorf("%w: expected=%s computed=%s", ErrCommitmentMismatch, cfg.Meta.Commit, recomputed)
    }
    return nil
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./... -v
```

---

### Task 1.4: BlindingStore interface

**Files:**
- Modify: `storage.go`
- Modify: `storage_test.go`

- [ ] **Step 1: Write failing tests**

```go
// storage_test.go (add)

func TestMemoryBlindingStore_RoundTrip(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryBlindingStore()
    blind := []byte("0123456789abcdef0123456789abcdef")
    if err := store.SaveBlinding(ctx, "cfg-1", 1, blind); err != nil {
        t.Fatal(err)
    }
    got, err := store.LoadBlinding(ctx, "cfg-1", 1)
    if err != nil {
        t.Fatal(err)
    }
    if !bytes.Equal(got, blind) {
        t.Error("round-trip mismatch")
    }
}

func TestMemoryBlindingStore_NotFound(t *testing.T) {
    ctx := context.Background()
    store := NewMemoryBlindingStore()
    _, err := store.LoadBlinding(ctx, "missing", 1)
    if err == nil {
        t.Error("expected error for missing blinding")
    }
}
```

- [ ] **Step 2: Implement BlindingStore interface and MemoryBlindingStore**

```go
// storage.go (add)

type BlindingStore interface {
    SaveBlinding(ctx context.Context, id string, version uint64, blind []byte) error
    LoadBlinding(ctx context.Context, id string, version uint64) ([]byte, error)
    DeleteBlinding(ctx context.Context, id string, version uint64) error
}

type MemoryBlindingStore struct {
    data map[string][]byte
    mu   sync.RWMutex
}

func NewMemoryBlindingStore() *MemoryBlindingStore {
    return &MemoryBlindingStore{data: make(map[string][]byte)}
}

func blindingKey(id string, version uint64) string {
    return fmt.Sprintf("%s/v%d.blind", id, version)
}

func (bs *MemoryBlindingStore) SaveBlinding(ctx context.Context, id string, version uint64, blind []byte) error {
    bs.mu.Lock()
    defer bs.mu.Unlock()
    bs.data[blindingKey(id, version)] = append([]byte(nil), blind...)
    return nil
}

func (bs *MemoryBlindingStore) LoadBlinding(ctx context.Context, id string, version uint64) ([]byte, error) {
    bs.mu.RLock()
    defer bs.mu.RUnlock()
    b, ok := bs.data[blindingKey(id, version)]
    if !ok {
        return nil, os.ErrNotExist
    }
    return append([]byte(nil), b...), nil
}

func (bs *MemoryBlindingStore) DeleteBlinding(ctx context.Context, id string, version uint64) error {
    bs.mu.Lock()
    defer bs.mu.Unlock()
    delete(bs.data, blindingKey(id, version))
    return nil
}
```

- [ ] **Step 3: Run tests**

```bash
go test -run TestMemoryBlindingStore -v
```

---

### Task 1.5: Manager integration with PrevCommit chain

**Files:**
- Modify: `manager.go`
- Modify: `manager_test.go`

The critical correction: the Manager must carry forward the previous version's `Commit` into `PrevCommit` before calling `UpdateMeta`. But `UpdateMeta` now does this automatically (`c.Meta.PrevCommit = c.Meta.Commit`), so as long as the new Config is initialized from `current.Meta` (as `Update` already does), the chain propagates correctly.

For `Create` (v1, no predecessor): `Meta.PrevCommit` starts empty. Correct.

For `Update`: `newCfg.Meta = current.Meta` copies `current.Meta.Commit` into the new config. Then `UpdateMeta()` moves it to `PrevCommit`. Correct.

- [ ] **Step 1: Add field and option**

```go
// manager.go
type Manager struct {
    storage       Storage
    journal       *Journal
    configStore   *ConfigStorage
    signer        *Signer
    blindingStore BlindingStore
    imts          map[string]*IMT
    imtDepth      int
    forest        *Forest
    mu            sync.RWMutex
    cache         map[string]*Config
}
```

- [ ] **Step 2: Write failing test — commitment chain integrity**

```go
// manager_test.go (add)

func TestManager_CommitmentChain_PrevCommitLinks(t *testing.T) {
    ctx := context.Background()
    storage := NewMemoryStorage()
    bs := NewMemoryBlindingStore()

    manager, _ := NewManager(ctx, storage, WithCommitment(bs))

    cfg1, _ := manager.Create(ctx, "test", map[string]interface{}{"v": 1})
    cfg2, _ := manager.Update(ctx, "test", map[string]interface{}{"v": 2})
    cfg3, _ := manager.Update(ctx, "test", map[string]interface{}{"v": 3})

    // v1 has no predecessor
    if cfg1.Meta.PrevCommit != "" {
        t.Error("v1 PrevCommit should be empty")
    }

    // v2.PrevCommit == v1.Commit
    if cfg2.Meta.PrevCommit != cfg1.Meta.Commit {
        t.Errorf("v2.PrevCommit=%s != v1.Commit=%s", cfg2.Meta.PrevCommit, cfg1.Meta.Commit)
    }

    // v3.PrevCommit == v2.Commit
    if cfg3.Meta.PrevCommit != cfg2.Meta.Commit {
        t.Errorf("v3.PrevCommit=%s != v2.Commit=%s", cfg3.Meta.PrevCommit, cfg2.Meta.Commit)
    }

    // All commitments are distinct
    seen := map[string]bool{}
    for _, c := range []*Config{cfg1, cfg2, cfg3} {
        if seen[c.Meta.Commit] {
            t.Errorf("duplicate commitment: %s", c.Meta.Commit)
        }
        seen[c.Meta.Commit] = true
    }
}
```

- [ ] **Step 3: Implement commitment block in Create/Update/Rollback**

In each mutating method, between `UpdateMeta()` and signing:

```go
    if m.blindingStore != nil {
        commit, blind, err := computeCommitment(cfg)
        if err != nil {
            return nil, fmt.Errorf("commitment: %w", err)
        }
        cfg.Meta.Commit = commit
        cfg.Meta.CommitAlg = CommitAlgPoseidonV1
        if err := m.blindingStore.SaveBlinding(ctx, id, cfg.Meta.Version, blind); err != nil {
            return nil, fmt.Errorf("save blinding: %w", err)
        }
    }
```

The PrevCommit is already set by `UpdateMeta()` (which copies old Commit to PrevCommit before clearing Commit).

- [ ] **Step 4: Update NewManager to accept ctx**

```go
func NewManager(ctx context.Context, storage Storage, opts ...ManagerOption) (*Manager, error) {
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
    if err := m.rebuildIMTs(ctx); err != nil {
        return nil, fmt.Errorf("rebuild IMTs: %w", err)
    }
    return m, nil
}
```

Update all call sites to pass `ctx` (or `context.Background()` in tests).

- [ ] **Step 5: Update journal entry creation for privacy mode**

In Create/Update/Rollback:

```go
    entry := &JournalEntry{
        ID:         id,
        Version:    cfg.Meta.Version,
        CS:         cfg.Meta.CS,
        PrevCS:     cfg.Meta.PrevCS,
        Time:       cfg.Meta.Time,
        Operation:  "create",
        Commit:     cfg.Meta.Commit,
        PrevCommit: cfg.Meta.PrevCommit,
    }
    if m.blindingStore == nil {
        entry.Config = cfg
    }
```

- [ ] **Step 6: Run all tests**

```bash
go test ./... -v -race
```

---

### Task 1.6: Freeze test vectors

**Files:**
- Create: `testdata/commitment_vectors.json`
- Create: `testdata/imt_vectors.json` (populated after Phase 2)
- Modify: `commitment_test.go`

Freeze a small set of known-good `(transcript, blinding) → (transcriptHash, commit)` tuples as JSON. These catch silent Poseidon parameterization changes across gnark-crypto upgrades and let reviewers reproduce by hand.

- [ ] **Step 1: Generate and freeze vectors**

After all Phase 1 tests pass, run a one-off script that prints deterministic test vectors:

```go
func TestGenerateCommitmentVectors(t *testing.T) {
    vectors := []struct {
        Transcript string `json:"transcript"`
        Blinding   string `json:"blinding"`
        Commit     string `json:"commit"`
    }{
        // Use fixed inputs — never random
    }

    transcript := []byte("MVPCHAIN|v2time:2025-01-01T00:00:00Zver:\x00\x00\x00\x00\x00\x00\x00\x01prev:body:{\"v\":1}")
    blind := make([]byte, 32)
    blind[0] = 0x42

    commit, _ := poseidonCommit(transcript, blind)
    vectors = append(vectors, struct {
        Transcript string `json:"transcript"`
        Blinding   string `json:"blinding"`
        Commit     string `json:"commit"`
    }{
        Transcript: hex.EncodeToString(transcript),
        Blinding:   hex.EncodeToString(blind),
        Commit:     commit,
    })

    data, _ := json.MarshalIndent(vectors, "", "  ")
    os.WriteFile("testdata/commitment_vectors.json", data, 0o644)
}
```

- [ ] **Step 2: Add vector-based regression test**

```go
func TestCommitmentVectors_Regression(t *testing.T) {
    data, err := os.ReadFile("testdata/commitment_vectors.json")
    if err != nil {
        t.Skip("no vectors file yet")
    }
    var vectors []struct {
        Transcript string `json:"transcript"`
        Blinding   string `json:"blinding"`
        Commit     string `json:"commit"`
    }
    json.Unmarshal(data, &vectors)

    for i, v := range vectors {
        transcript, _ := hex.DecodeString(v.Transcript)
        blind, _ := hex.DecodeString(v.Blinding)
        got, err := poseidonCommit(transcript, blind)
        if err != nil {
            t.Fatal(err)
        }
        if got != v.Commit {
            t.Errorf("vector %d: got %s, want %s", i, got, v.Commit)
        }
    }
}
```

- [ ] **Step 3: Prepare testdata**

```bash
mkdir -p testdata
```

---

## Phase 2: Incremental Merkle Tree

### Task 2.1: Fixed-depth IMT with frontier and zero hashes

**Files:**
- Create: `imt.go`
- Create: `imt_test.go`

The article's frontier pattern is preserved for O(log n) append, but within a fixed-depth balanced tree with pre-computed zero hashes. This ensures `Root()` and `BuildMembershipProof` agree on the tree structure for any leaf count (not just powers of 2).

- [ ] **Step 1: Write failing tests**

```go
// imt_test.go
package viracochan

import (
    "fmt"
    "testing"
)

func TestIMT_EmptyRoot(t *testing.T) {
    tree := NewIMT(32)
    if tree.Root() == "" {
        t.Error("empty tree should have zero root")
    }
}

func TestIMT_AppendChangesRoot(t *testing.T) {
    tree := NewIMT(32)
    r0 := tree.Root()
    r1, _ := tree.Append("aaa")
    r2, _ := tree.Append("bbb")
    if r0 == r1 || r1 == r2 {
        t.Error("root should change on each append")
    }
}

func TestIMT_Deterministic(t *testing.T) {
    leaves := []string{"a1", "b2", "c3"}
    t1 := NewIMT(32)
    t2 := NewIMT(32)
    for _, l := range leaves {
        t1.Append(l)
        t2.Append(l)
    }
    if t1.Root() != t2.Root() {
        t.Error("same leaves must produce same root")
    }
}

func TestIMT_AppendReturnMatchesRoot(t *testing.T) {
    tree := NewIMT(8)
    for i := 0; i < 17; i++ {
        returned, _ := tree.Append(fmt.Sprintf("leaf-%d", i))
        computed := tree.Root()
        if returned != computed {
            t.Errorf("at leaf %d: Append returned %s but Root() is %s", i, returned, computed)
        }
    }
}

func TestIMT_Size(t *testing.T) {
    tree := NewIMT(32)
    tree.Append("x")
    tree.Append("y")
    if tree.Size() != 2 {
        t.Errorf("expected 2, got %d", tree.Size())
    }
}

func TestIMT_RootMatchesMembershipProofRoot(t *testing.T) {
    // THE CRITICAL TEST: Root() and BuildMembershipProof must agree for
    // non-power-of-2 leaf counts.
    for _, n := range []int{1, 2, 3, 5, 7, 8, 9, 15, 16, 17} {
        tree := NewIMT(8)
        leaves := make([]string, n)
        for i := 0; i < n; i++ {
            leaves[i] = fmt.Sprintf("leaf-%d", i)
            tree.Append(leaves[i])
        }

        for idx := 0; idx < n; idx++ {
            proof, err := BuildMembershipProof(leaves, 8, idx)
            if err != nil {
                t.Fatalf("n=%d idx=%d: %v", n, idx, err)
            }
            if !VerifyMembershipProof(leaves[idx], proof, tree.Root()) {
                t.Errorf("n=%d idx=%d: valid proof rejected", n, idx)
            }
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test -run TestIMT -v
```

- [ ] **Step 3: Implement fixed-depth IMT (Tornado Cash / Semaphore algorithm)**

The well-known algorithm: `Append` always walks ALL levels to the root (no early return). `Root()` returns the stored value.

```go
// imt.go
package viracochan

import (
    "errors"
    "fmt"

    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

var zeroHash = fieldElementToHex(fr.Element{})

// IMT is an append-only Incremental Merkle Tree with fixed depth.
// Uses filledSubtrees (O(log n) space) for efficient append.
// Algorithm follows the widely-deployed Semaphore / Tornado Cash pattern.
type IMT struct {
    depth          int
    zeros          []string // zeros[i] = hash of empty subtree at level i
    filledSubtrees []string // filledSubtrees[i] = last completed left-child hash at level i
    currentRoot    string
    size           int
}

const DefaultIMTDepth = 32

func NewIMT(depth int) *IMT {
    zeros := make([]string, depth+1)
    zeros[0] = zeroHash
    for i := 1; i <= depth; i++ {
        zeros[i] = poseidonHashPair(zeros[i-1], zeros[i-1])
    }
    filledSubtrees := make([]string, depth)
    copy(filledSubtrees, zeros[:depth])

    return &IMT{
        depth:          depth,
        zeros:          zeros,
        filledSubtrees: filledSubtrees,
        currentRoot:    zeros[depth], // root of fully empty tree
    }
}

// Append adds a leaf and returns the new root. O(depth) always.
// Walks ALL levels to the top — no early return.
func (t *IMT) Append(leaf string) (string, error) {
    if t.size >= (1 << t.depth) {
        return "", errors.New("tree is full")
    }
    currentIndex := t.size
    current := leaf
    for level := 0; level < t.depth; level++ {
        if currentIndex%2 == 0 {
            // Left child at this level: store it, pair with zero
            t.filledSubtrees[level] = current
            current = poseidonHashPair(current, t.zeros[level])
        } else {
            // Right child: pair with stored left sibling
            current = poseidonHashPair(t.filledSubtrees[level], current)
        }
        currentIndex /= 2
    }
    t.size++
    t.currentRoot = current
    return current, nil
}

// Root returns the current Merkle root. O(1).
func (t *IMT) Root() string {
    return t.currentRoot
}

func (t *IMT) Size() int { return t.size }

func (t *IMT) Depth() int { return t.depth }

func (t *IMT) Zeros() []string { return t.zeros }

// CanonicalLeaf computes the domain-separated leaf hash:
//   leaf = Poseidon("leaf", index, commitment, prevCommit)
// Position binding prevents reordering; the "leaf" tag prevents leaf/node confusion.
func CanonicalLeaf(index int, commitment, prevCommit string) string {
    var tag, idx, comm, prev fr.Element
    tag.SetUint64(0x6c656166) // "leaf" as uint64
    idx.SetUint64(uint64(index))
    comm, _ = hexToFieldElement(commitment)
    if prevCommit != "" {
        prev, _ = hexToFieldElement(prevCommit)
    }
    digest := poseidon.Sum(tag, idx, comm, prev)
    return fieldElementToHex(digest)
}

// poseidonHashPair hashes two hex-encoded field elements with Poseidon.
func poseidonHashPair(left, right string) string {
    l, _ := hexToFieldElement(left)
    r, _ := hexToFieldElement(right)
    digest := poseidon.Sum(l, r)
    return fieldElementToHex(digest)
}
```

Key properties:
- `Append` always walks all `depth` levels — no early return, no separate `Root()` recomputation
- `Root()` is O(1) — returns stored value
- `filledSubtrees[level]` stores the last left-child hash at each level
- For left children: store in filledSubtrees, combine with zero (right sibling empty)
- For right children: combine with stored left sibling from filledSubtrees
- This is the exact algorithm deployed in Semaphore and Tornado Cash (battle-tested)

- [ ] **Step 4: Run tests**

```bash
go test -run TestIMT -v
```

---

### Task 2.2: Membership proofs (depth-aware, separate from IMT)

**Files:**
- Modify: `imt.go`
- Modify: `imt_test.go`

Proof generation requires all leaves (reconstructed from journal on demand) and the tree's depth + zeros to pad correctly. `BuildMembershipProof` uses the SAME zero-padded balanced tree structure as the IMT's `Append`/`Root`, ensuring roots match.

- [ ] **Step 1: Write failing tests**

```go
// imt_test.go (add)

func TestMembershipProof_ValidLeaf(t *testing.T) {
    depth := 8
    leaves := []string{"a", "b", "c", "d"}
    tree := NewIMT(depth)
    for _, l := range leaves {
        tree.Append(l)
    }

    proof, err := BuildMembershipProof(leaves, depth, 2)
    if err != nil {
        t.Fatal(err)
    }

    if !VerifyMembershipProof(leaves[2], proof, tree.Root()) {
        t.Error("valid proof rejected")
    }
}

func TestMembershipProof_TamperedLeaf(t *testing.T) {
    depth := 8
    leaves := []string{"a", "b", "c", "d"}
    tree := NewIMT(depth)
    for _, l := range leaves {
        tree.Append(l)
    }

    proof, _ := BuildMembershipProof(leaves, depth, 2)
    if VerifyMembershipProof("tampered", proof, tree.Root()) {
        t.Error("tampered proof accepted")
    }
}

func TestMembershipProof_NonPowerOf2_Leaves(t *testing.T) {
    depth := 8
    leaves := []string{"a", "b", "c"} // 3 leaves — NOT a power of 2
    tree := NewIMT(depth)
    for _, l := range leaves {
        tree.Append(l)
    }

    for idx := 0; idx < len(leaves); idx++ {
        proof, err := BuildMembershipProof(leaves, depth, idx)
        if err != nil {
            t.Fatal(err)
        }
        if !VerifyMembershipProof(leaves[idx], proof, tree.Root()) {
            t.Errorf("proof for index %d rejected with %d leaves", idx, len(leaves))
        }
    }
}
```

- [ ] **Step 2: Implement BuildMembershipProof and VerifyMembershipProof**

```go
// imt.go (add)

type MembershipProof struct {
    Siblings []string `json:"siblings"`
    Index    int      `json:"index"`
}

// BuildMembershipProof constructs a depth-aware inclusion proof.
// Uses the same zero hashes as the IMT to ensure root consistency.
// The leaf list is reconstructed from journal commitment entries on demand.
func BuildMembershipProof(leaves []string, depth, index int) (*MembershipProof, error) {
    if index < 0 || index >= len(leaves) {
        return nil, fmt.Errorf("index %d out of range [0, %d)", index, len(leaves))
    }

    // Compute zeros matching the IMT
    zeros := make([]string, depth+1)
    zeros[0] = zeroHash
    for i := 1; i <= depth; i++ {
        zeros[i] = poseidonHashPair(zeros[i-1], zeros[i-1])
    }

    // Pad leaves to 2^depth with zero[0]
    fullSize := 1 << depth
    nodes := make([]string, fullSize)
    copy(nodes, leaves)
    for i := len(leaves); i < fullSize; i++ {
        nodes[i] = zeros[0]
    }

    siblings := make([]string, depth)
    idx := index
    for level := 0; level < depth; level++ {
        if idx%2 == 0 {
            siblings[level] = nodes[idx+1]
        } else {
            siblings[level] = nodes[idx-1]
        }
        next := make([]string, len(nodes)/2)
        for i := 0; i < len(nodes); i += 2 {
            next[i/2] = poseidonHashPair(nodes[i], nodes[i+1])
        }
        nodes = next
        idx /= 2
    }

    return &MembershipProof{Siblings: siblings, Index: index}, nil
}

func VerifyMembershipProof(leaf string, proof *MembershipProof, root string) bool {
    current := leaf
    idx := proof.Index
    for _, sibling := range proof.Siblings {
        if idx%2 == 0 {
            current = poseidonHashPair(current, sibling)
        } else {
            current = poseidonHashPair(sibling, current)
        }
        idx /= 2
    }
    return current == root
}
```

Key difference from plan v1/v2: `BuildMembershipProof` accepts `depth` and pads to `2^depth` (not "next power of 2"). This matches the IMT's fixed-depth structure exactly.

- [ ] **Step 3: Run tests**

```bash
go test -run TestMembershipProof -v
```

---

### Task 2.3: IMT persistence

Serialize `filledSubtrees`, `currentRoot`, `size`, and `depth`. Zeros are recomputed on unmarshal.

```go
type imtState struct {
    Depth          int      `json:"depth"`
    FilledSubtrees []string `json:"filled_subtrees"`
    CurrentRoot    string   `json:"current_root"`
    Size           int      `json:"size"`
}

func (t *IMT) Marshal() ([]byte, error) {
    return json.Marshal(imtState{
        Depth:          t.depth,
        FilledSubtrees: t.filledSubtrees,
        CurrentRoot:    t.currentRoot,
        Size:           t.size,
    })
}

func UnmarshalIMT(data []byte) (*IMT, error) {
    var s imtState
    if err := json.Unmarshal(data, &s); err != nil {
        return nil, err
    }
    // Recompute zeros from depth
    zeros := make([]string, s.Depth+1)
    zeros[0] = zeroHash
    for i := 1; i <= s.Depth; i++ {
        zeros[i] = poseidonHashPair(zeros[i-1], zeros[i-1])
    }
    return &IMT{
        depth:          s.Depth,
        zeros:          zeros,
        filledSubtrees: s.FilledSubtrees,
        currentRoot:    s.CurrentRoot,
        size:           s.Size,
    }, nil
}
```

---

### Task 2.4: IMT + Manager integration

**Files:**
- Modify: `manager.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Add IMT fields and WithIMT option**

```go
// manager.go

func WithIMT(depth int) ManagerOption {
    return func(m *Manager) error {
        if depth < 1 || depth > 64 {
            return fmt.Errorf("IMT depth must be 1..64, got %d", depth)
        }
        m.imtDepth = depth
        m.imts = make(map[string]*IMT)
        return nil
    }
}
```

- [ ] **Step 2: Add IMT append to Create/Update/Rollback**

After the commitment block and before signing:

```go
    if m.imtDepth > 0 && cfg.Meta.Commit != "" {
        imt, ok := m.imts[id]
        if !ok {
            imt = NewIMT(m.imtDepth)
            m.imts[id] = imt
        }
        leaf := CanonicalLeaf(imt.Size(), cfg.Meta.Commit, cfg.Meta.PrevCommit)
        root, err := imt.Append(leaf)
        if err != nil {
            return nil, fmt.Errorf("IMT append: %w", err)
        }
        cfg.Meta.IMTRoot = root
    }
```

- [ ] **Step 3: Implement rebuildIMTs**

```go
func (m *Manager) rebuildIMTs(ctx context.Context) error {
    if m.imtDepth == 0 {
        return nil
    }
    entries, err := m.journal.ReadAll(ctx)
    if err != nil {
        return err
    }
    for _, entry := range entries {
        commit := entry.Commit
        prevCommit := entry.PrevCommit
        if commit == "" && entry.Config != nil {
            commit = entry.Config.Meta.Commit
            prevCommit = entry.Config.Meta.PrevCommit
        }
        if commit == "" {
            continue
        }
        imt, ok := m.imts[entry.ID]
        if !ok {
            imt = NewIMT(m.imtDepth)
            m.imts[entry.ID] = imt
        }
        leaf := CanonicalLeaf(imt.Size(), commit, prevCommit)
        if _, err := imt.Append(leaf); err != nil {
            return fmt.Errorf("rebuild IMT for %s v%d: %w", entry.ID, entry.Version, err)
        }
    }
    return nil
}
```

- [ ] **Step 4: Implement collectChainLeaves for disclosure**

When generating a disclosure proof, the Manager needs all commitment leaves for a chain to build the membership proof:

```go
func (m *Manager) collectChainLeaves(ctx context.Context, id string) ([]string, error) {
    entries, err := m.journal.FindByID(ctx, id)
    if err != nil {
        return nil, err
    }
    var leaves []string
    for i, entry := range entries {
        commit := entry.Commit
        prevCommit := entry.PrevCommit
        if commit == "" && entry.Config != nil {
            commit = entry.Config.Meta.Commit
            prevCommit = entry.Config.Meta.PrevCommit
        }
        if commit != "" {
            leaves = append(leaves, CanonicalLeaf(i, commit, prevCommit))
        }
    }
    return leaves, nil
}
```

- [ ] **Step 5: Write tests**

```go
func TestManager_IMT_Integration(t *testing.T) {
    ctx := context.Background()
    storage := NewMemoryStorage()
    bs := NewMemoryBlindingStore()

    m, _ := NewManager(ctx, storage, WithCommitment(bs), WithIMT(DefaultIMTDepth))
    cfg1, _ := m.Create(ctx, "test", map[string]interface{}{"v": 1})
    cfg2, _ := m.Update(ctx, "test", map[string]interface{}{"v": 2})

    if cfg1.Meta.IMTRoot == "" || cfg2.Meta.IMTRoot == "" {
        t.Error("IMT root should be set")
    }
    if cfg1.Meta.IMTRoot == cfg2.Meta.IMTRoot {
        t.Error("IMT root should change on update")
    }
}

func TestManager_IMT_SurvivesRestart(t *testing.T) {
    ctx := context.Background()
    storage := NewMemoryStorage()
    bs := NewMemoryBlindingStore()

    m1, _ := NewManager(ctx, storage, WithCommitment(bs), WithIMT(DefaultIMTDepth))
    m1.Create(ctx, "test", map[string]interface{}{"v": 1})
    m1.Update(ctx, "test", map[string]interface{}{"v": 2})
    latest1, _ := m1.GetLatest(ctx, "test")

    m2, _ := NewManager(ctx, storage, WithCommitment(bs), WithIMT(DefaultIMTDepth))
    cfg3, err := m2.Update(ctx, "test", map[string]interface{}{"v": 3})
    if err != nil {
        t.Fatal(err)
    }
    if cfg3.Meta.IMTRoot == latest1.Meta.IMTRoot {
        t.Error("IMT root should change after restart+update")
    }
}
```

- [ ] **Step 6: Run all tests**

```bash
go test ./... -v -race
```

---

## Phase 3: Forest Aggregation & Epochs

### Task 3.1: Forest root with BLAKE3 ordering and forest inclusion proofs

**Files:**
- Create: `forest.go`
- Create: `forest_test.go`

The forest is built as a balanced Merkle tree over the chain roots, ordered by `BLAKE3(chainID)`. This produces both a forest root and per-chain O(log n) inclusion proofs.

**Deviation from article:** The article uses a sequential fold (`node = hashPair(node, r)`). We use a balanced Merkle tree instead, because a sequential fold would require O(n) work to prove a single chain's inclusion. The balanced tree enables O(log n) forest inclusion proofs, which are essential for the disclosure path (see D6).

- [ ] **Step 1: Write failing tests**

```go
// forest_test.go
package viracochan

import "testing"

func TestForest_Deterministic(t *testing.T) {
    chains := map[string]string{"a": "root_a", "b": "root_b"}
    f1 := BuildForest(chains)
    f2 := BuildForest(chains)
    if f1.Root != f2.Root {
        t.Error("not deterministic")
    }
}

func TestForest_OrderIndependent(t *testing.T) {
    c1 := map[string]string{"a": "root_a", "b": "root_b"}
    c2 := map[string]string{"b": "root_b", "a": "root_a"}
    if BuildForest(c1).Root != BuildForest(c2).Root {
        t.Error("order-dependent")
    }
}

func TestForest_InclusionProof(t *testing.T) {
    chains := map[string]string{
        "chain-a": "root_a", "chain-b": "root_b", "chain-c": "root_c",
    }
    f := BuildForest(chains)

    proof, err := f.InclusionProof("chain-b")
    if err != nil {
        t.Fatal(err)
    }

    if !VerifyForestInclusion("root_b", proof, f.Root) {
        t.Error("valid forest inclusion proof rejected")
    }
}
```

- [ ] **Step 2: Implement Forest with BLAKE3 ordering**

```go
// forest.go
package viracochan

import (
    "fmt"
    "sort"

    "lukechampine.com/blake3"
)

type ForestState struct {
    Root       string
    OrderedIDs []string
    Leaves     []string // chain roots in BLAKE3(chainID) order
    Depth      int      // tree depth (ceil(log2(len(Leaves))))
}

// BuildForest constructs a Merkle tree of chain roots ordered by BLAKE3(chainID).
// Forest depth is dynamic (ceil(log2(chainCount))), unlike the IMT which uses a
// fixed depth (default 32). The forest is small (one leaf per chain), so dynamic
// depth avoids wasting 32 levels for a handful of chains.
func BuildForest(chainRoots map[string]string) *ForestState {
    if len(chainRoots) == 0 {
        return &ForestState{Root: zeroHash}
    }

    type item struct {
        sortKey [32]byte
        id      string
        root    string
    }

    items := make([]item, 0, len(chainRoots))
    for id, root := range chainRoots {
        items = append(items, item{
            sortKey: blake3.Sum256([]byte(id)),
            id:      id,
            root:    root,
        })
    }
    sort.Slice(items, func(i, j int) bool {
        for k := 0; k < 32; k++ {
            if items[i].sortKey[k] != items[j].sortKey[k] {
                return items[i].sortKey[k] < items[j].sortKey[k]
            }
        }
        return false
    })

    ids := make([]string, len(items))
    leaves := make([]string, len(items))
    for i, it := range items {
        ids[i] = it.id
        leaves[i] = it.root
    }

    // Build balanced Merkle tree with depth-aware padding.
    // Must use the same padding as BuildMembershipProof so inclusion proofs verify.
    forestDepth := 0
    for (1 << forestDepth) < len(leaves) {
        forestDepth++
    }
    fullSize := 1 << forestDepth
    if fullSize == 0 {
        fullSize = 1
    }
    nodes := make([]string, fullSize)
    copy(nodes, leaves)
    for i := len(leaves); i < fullSize; i++ {
        nodes[i] = zeroHash
    }
    layer := nodes
    for len(layer) > 1 {
        next := make([]string, len(layer)/2)
        for i := 0; i < len(layer); i += 2 {
            next[i/2] = poseidonHashPair(layer[i], layer[i+1])
        }
        layer = next
    }

    return &ForestState{Root: layer[0], OrderedIDs: ids, Leaves: leaves, Depth: forestDepth}
}

type ForestInclusionProof struct {
    Siblings []string `json:"siblings"`
    Index    int      `json:"index"`
}

func (f *ForestState) InclusionProof(chainID string) (*ForestInclusionProof, error) {
    idx := -1
    for i, id := range f.OrderedIDs {
        if id == chainID {
            idx = i
            break
        }
    }
    if idx < 0 {
        return nil, fmt.Errorf("chain %q not in forest", chainID)
    }

    proof, err := BuildMembershipProof(f.Leaves, f.Depth, idx)
    if err != nil {
        return nil, err
    }
    return &ForestInclusionProof{Siblings: proof.Siblings, Index: proof.Index}, nil
}

func VerifyForestInclusion(chainRoot string, proof *ForestInclusionProof, forestRoot string) bool {
    return VerifyMembershipProof(chainRoot, &MembershipProof{
        Siblings: proof.Siblings,
        Index:    proof.Index,
    }, forestRoot)
}
```

- [ ] **Step 3: Run tests**

```bash
go test -run TestForest -v
```

---

### Task 3.2: Epoch bulletins (ForestRoot only, no individual chain roots)

**Files:**
- Modify: `forest.go`
- Modify: `forest_test.go`

Per the article, the bulletin stores the forest root and a digest — NOT individual chain roots.

- [ ] **Step 1: Write failing tests**

```go
// forest_test.go (add)

func TestEpochBulletin_Create(t *testing.T) {
    signer, _ := NewSigner()
    chains := map[string]string{"chain-a": "root_a", "chain-b": "root_b"}
    forest := BuildForest(chains)

    bulletin, err := NewEpochBulletin(1, forest, signer)
    if err != nil {
        t.Fatal(err)
    }
    if bulletin.Epoch != 1 {
        t.Errorf("expected epoch 1, got %d", bulletin.Epoch)
    }
    if bulletin.ForestRoot != forest.Root {
        t.Error("forest root mismatch")
    }
    if bulletin.Signature == "" {
        t.Error("missing signature")
    }
    if bulletin.ChainCount != 2 {
        t.Errorf("expected 2 chains, got %d", bulletin.ChainCount)
    }
}

func TestEpochBulletin_Verify(t *testing.T) {
    signer, _ := NewSigner()
    forest := BuildForest(map[string]string{"a": "root_a"})
    bulletin, _ := NewEpochBulletin(1, forest, signer)

    if err := bulletin.Verify(signer.PublicKey()); err != nil {
        t.Errorf("verification failed: %v", err)
    }
}

func TestEpochBulletin_NoChainRootsExposed(t *testing.T) {
    signer, _ := NewSigner()
    forest := BuildForest(map[string]string{"a": "root_a", "b": "root_b"})
    bulletin, _ := NewEpochBulletin(1, forest, signer)

    data, _ := json.Marshal(bulletin)
    if bytes.Contains(data, []byte("root_a")) || bytes.Contains(data, []byte("root_b")) {
        t.Error("bulletin should NOT expose individual chain roots")
    }
}
```

- [ ] **Step 2: Implement EpochBulletin**

```go
// forest.go (add)

import (
    "crypto/sha256"
    "time"
)

type EpochBulletin struct {
    Epoch            uint64    `json:"epoch"`
    Time             time.Time `json:"t"`
    ForestRoot       string    `json:"forest_root"`
    ChainRootsDigest string    `json:"chain_roots_digest"`
    ChainCount       int       `json:"chain_count"`
    Signature        string    `json:"sig"`
    SigAlg           string    `json:"sig_alg"`
}

func NewEpochBulletin(epoch uint64, forest *ForestState, signer *Signer) (*EpochBulletin, error) {
    if len(forest.Leaves) == 0 {
        return nil, errors.New("cannot publish epoch for empty forest (no chains)")
    }

    // Compute digest: Poseidon of all chain roots in BLAKE3 order
    var digest string
    if len(forest.Leaves) > 0 {
        elems := make([]fr.Element, len(forest.Leaves))
        for i, leaf := range forest.Leaves {
            elems[i], _ = hexToFieldElement(leaf)
        }
        d := poseidon.Sum(elems...)
        digest = fieldElementToHex(d)
    } else {
        digest = zeroHash
    }

    b := &EpochBulletin{
        Epoch:            epoch,
        Time:             time.Now().UTC().Truncate(time.Microsecond),
        ForestRoot:       forest.Root,
        ChainRootsDigest: digest,
        ChainCount:       len(forest.Leaves),
    }

    payload := bulletinSigningPayload(b)
    hash := sha256.Sum256(payload)
    sig, err := signer.signHash(hash[:])
    if err != nil {
        return nil, err
    }
    b.Signature = sig
    b.SigAlg = SignatureAlgorithmV2
    return b, nil
}

func (b *EpochBulletin) Verify(publicKey string) error {
    payload := bulletinSigningPayload(b)
    hash := sha256.Sum256(payload)
    return verifyHash(hash[:], b.Signature, publicKey)
}

// bulletinSigningPayload builds the domain-separated message that gets SHA-256
// hashed before Schnorr signing. The existing signer.signHash expects a 32-byte
// hash (it signs the hash directly, no internal re-hashing), so the caller
// computes sha256.Sum256(payload) before calling signHash. This matches the
// existing config signing pattern in makeSigningHashV2.
func bulletinSigningPayload(b *EpochBulletin) []byte {
    return []byte(fmt.Sprintf("viracochan:bulletin:v1:%d:%s:%s:%s:%d",
        b.Epoch,
        b.Time.UTC().Format(time.RFC3339Nano),
        b.ForestRoot,
        b.ChainRootsDigest,
        b.ChainCount))
}
```

- [ ] **Step 3: Run tests**

```bash
go test -run TestEpochBulletin -v
```

---

### Task 3.3: Forest + Manager integration

**Files:**
- Modify: `manager.go`
- Modify: `manager_test.go`

- [ ] **Step 1: Add Forest to Manager**

```go
// manager.go

type ForestCache struct {
    epoch     uint64
    state     *ForestState
    bulletins []*EpochBulletin
}

func WithForest() ManagerOption {
    return func(m *Manager) error {
        m.forest = &ForestCache{}
        return nil
    }
}
```

- [ ] **Step 2: Implement PublishEpoch**

```go
func (m *Manager) PublishEpoch(ctx context.Context) (*EpochBulletin, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    if m.forest == nil {
        return nil, errors.New("forest not configured")
    }
    if m.signer == nil {
        return nil, errors.New("signer required for epoch bulletins")
    }

    chainRoots := make(map[string]string)
    for id, imt := range m.imts {
        chainRoots[id] = imt.Root()
    }

    forestState := BuildForest(chainRoots)
    m.forest.epoch++
    m.forest.state = forestState

    bulletin, err := NewEpochBulletin(m.forest.epoch, forestState, m.signer)
    if err != nil {
        return nil, err
    }
    m.forest.bulletins = append(m.forest.bulletins, bulletin)

    data, _ := json.Marshal(bulletin)
    path := fmt.Sprintf("bulletins/epoch_%d.json", bulletin.Epoch)
    if err := m.storage.Write(ctx, path, data); err != nil {
        return nil, err
    }

    return bulletin, nil
}
```

- [ ] **Step 3: Write tests**

```go
func TestManager_PublishEpoch(t *testing.T) {
    ctx := context.Background()
    storage := NewMemoryStorage()
    bs := NewMemoryBlindingStore()
    signer, _ := NewSigner()

    m, _ := NewManager(ctx, storage,
        WithSigner(signer), WithCommitment(bs),
        WithIMT(DefaultIMTDepth), WithForest(),
    )

    m.Create(ctx, "chain-a", map[string]interface{}{"v": 1})
    m.Create(ctx, "chain-b", map[string]interface{}{"v": 1})

    bulletin, err := m.PublishEpoch(ctx)
    if err != nil {
        t.Fatal(err)
    }
    if bulletin.Epoch != 1 {
        t.Errorf("expected epoch 1, got %d", bulletin.Epoch)
    }
    if bulletin.ChainCount != 2 {
        t.Errorf("expected 2 chains, got %d", bulletin.ChainCount)
    }
    if err := bulletin.Verify(signer.PublicKey()); err != nil {
        t.Errorf("bulletin verification failed: %v", err)
    }
}
```

- [ ] **Step 4: Run all tests**

```bash
go test ./... -v -race
```

---

## Phase 4: ZK Circuits

### Task 4.1: Commitment correctness circuit (two field elements)

**Files:**
- Create: `circuits/circuits.go`, `circuits/commitment.go`, `circuits/circuits_test.go`

The circuit's inputs now **match the native two-stage Poseidon exactly**:

```go
// circuits/commitment.go
type CommitmentCircuit struct {
    Commit         frontend.Variable `gnark:",public"`
    TranscriptHash frontend.Variable  // Stage 1 output (private)
    Blinding       frontend.Variable  // blinding factor (private)
}

func (c *CommitmentCircuit) Define(api frontend.API) error {
    h := poseidon.NewPoseidon2(api)
    h.Write(c.TranscriptHash, c.Blinding)
    computed := h.Sum()
    api.AssertIsEqual(computed, c.Commit)
    return nil
}
```

The prover supplies `transcriptHash` (computed natively as `Poseidon(bytesToFieldElements(transcript)...)`) and `blinding`. The circuit verifies `Poseidon(transcriptHash, blinding) == Commit`.

The test MUST verify native/circuit alignment:

```go
func TestCommitmentCircuit_MatchesNative(t *testing.T) {
    // Compute natively
    transcript := []byte("test-transcript-data")
    blind := make([]byte, 32)
    blind[0] = 42

    nativeCommit, _ := poseidonCommit(transcript, blind)

    // Extract the two field elements the circuit needs
    chunks, _ := bytesToFieldElements(transcript)
    transcriptHash := poseidon.Sum(chunks...)
    var blindElem fr.Element
    blindElem.SetBigInt(new(big.Int).SetBytes(blind))

    nativeCommitElem, _ := hexToFieldElement(nativeCommit)

    // Prove in circuit
    ccs, pk, vk, _ := CompileAndSetup(&CommitmentCircuit{})
    assignment := &CommitmentCircuit{
        Commit:         nativeCommitElem,
        TranscriptHash: transcriptHash,
        Blinding:       blindElem,
    }
    witness, _ := frontend.NewWitness(assignment, Curve.ScalarField())
    proof, err := plonk.Prove(ccs, pk, witness)
    if err != nil {
        t.Fatalf("circuit rejected native commitment: %v", err)
    }
    pubWitness, _ := witness.Public()
    if err := plonk.Verify(proof, vk, pubWitness); err != nil {
        t.Fatalf("verification failed: %v", err)
    }
}
```

---

### Task 4.2: Inclusion proof circuit

**Files:**
- Create: `circuits/inclusion.go`
- Modify: `circuits/circuits_test.go`

- [ ] **Step 1: Define inclusion circuit**

```go
// circuits/inclusion.go
package circuits

import (
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/hash/poseidon"
)

// InclusionCircuit proves a leaf is in a Merkle tree at a given root.
// Path contains sibling hashes. Direction bits indicate left(0)/right(1).
type InclusionCircuit struct {
    Root      frontend.Variable   `gnark:",public"`
    Leaf      frontend.Variable
    Siblings  [DefaultIMTDepth]frontend.Variable
    Direction [DefaultIMTDepth]frontend.Variable // 0 or 1
}

const DefaultIMTDepth = 32

func (c *InclusionCircuit) Define(api frontend.API) error {
    current := c.Leaf
    for i := 0; i < DefaultIMTDepth; i++ {
        h := poseidon.NewPoseidon2(api)
        left := api.Select(c.Direction[i], c.Siblings[i], current)
        right := api.Select(c.Direction[i], current, c.Siblings[i])
        h.Write(left, right)
        current = h.Sum()
    }
    api.AssertIsEqual(current, c.Root)
    return nil
}
```

Note: the exact gnark `std/accumulator/merkle` API may provide a cleaner `VerifyProof` helper. If available, use it instead of the manual loop. The manual implementation above is a fallback that works with any gnark version.

- [ ] **Step 2: Write cross-test — native IMT proof verified in circuit**

```go
// circuits/circuits_test.go (add)

func TestInclusionCircuit_NativeProofInCircuit(t *testing.T) {
    // Build a native IMT and generate a proof
    depth := DefaultIMTDepth
    tree := viracochan.NewIMT(depth)
    leaves := make([]string, 5)
    for i := range leaves {
        var e fr.Element
        e.SetInt64(int64(i + 100))
        leaves[i] = viracochan.FieldElementToHex(e) // would need export
        tree.Append(leaves[i])
    }

    proof, _ := viracochan.BuildMembershipProof(leaves, depth, 2)
    root := tree.Root()

    // Convert to circuit witness
    rootElem, _ := viracochan.HexToFieldElement(root)
    leafElem, _ := viracochan.HexToFieldElement(leaves[2])

    var assignment InclusionCircuit
    assignment.Root = rootElem
    assignment.Leaf = leafElem
    idx := proof.Index
    for i, sib := range proof.Siblings {
        sibElem, _ := viracochan.HexToFieldElement(sib)
        assignment.Siblings[i] = sibElem
        if idx%2 == 0 {
            assignment.Direction[i] = 0
        } else {
            assignment.Direction[i] = 1
        }
        idx /= 2
    }
    // Zero remaining levels (proof may be shorter than depth)
    for i := len(proof.Siblings); i < depth; i++ {
        assignment.Siblings[i] = 0
        assignment.Direction[i] = 0
    }

    ccs, pk, vk, err := CompileAndSetup(&InclusionCircuit{})
    if err != nil {
        t.Fatal(err)
    }
    witness, _ := frontend.NewWitness(&assignment, Curve.ScalarField())
    p, err := plonk.Prove(ccs, pk, witness)
    if err != nil {
        t.Fatalf("circuit rejected native proof: %v", err)
    }
    pubWit, _ := witness.Public()
    if err := plonk.Verify(p, vk, pubWit); err != nil {
        t.Fatalf("verification failed: %v", err)
    }
}
```

This test catches any mismatch between native Poseidon (IMT) and circuit Poseidon (gnark). If the hashes differ, the circuit will reject the native proof.

- [ ] **Step 3: Run tests**

```bash
go test ./circuits/ -v -timeout 180s
```

---

### Task 4.3: Transition predicate circuit

**Files:**
- Create: `circuits/transition.go`
- Modify: `circuits/circuits_test.go`

Uses `TranscriptHash` (two-stage Poseidon) instead of raw `Message`.

- [ ] **Step 1: Define transition circuit**

```go
// circuits/transition.go
package circuits

import (
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/std/hash/poseidon"
)

// TransitionCircuit proves a valid state transition between two committed versions.
// Both commitments are verified via the two-stage Poseidon scheme.
//
// This is a TEMPLATE circuit. The predicate (PrevValue <= NextValue) demonstrates
// a monotonic-increase constraint. Real applications specialize this by replacing
// the predicate section with domain-specific constraints. The commitment openings
// prove that the claimed values actually correspond to the committed versions.
type TransitionCircuit struct {
    PrevCommit         frontend.Variable `gnark:",public"`
    NextCommit         frontend.Variable `gnark:",public"`
    PrevTranscriptHash frontend.Variable
    PrevBlinding       frontend.Variable
    NextTranscriptHash frontend.Variable
    NextBlinding       frontend.Variable
    PrevValue          frontend.Variable // application-specific: value extracted from prev state
    NextValue          frontend.Variable // application-specific: value extracted from next state
}

func (c *TransitionCircuit) Define(api frontend.API) error {
    h := poseidon.NewPoseidon2(api)

    h.Reset()
    h.Write(c.PrevTranscriptHash, c.PrevBlinding)
    api.AssertIsEqual(h.Sum(), c.PrevCommit)

    h.Reset()
    h.Write(c.NextTranscriptHash, c.NextBlinding)
    api.AssertIsEqual(h.Sum(), c.NextCommit)

    // Template predicate: monotonic increase (NextValue >= PrevValue).
    // Replace with domain-specific constraints for real applications.
    api.AssertIsLessOrEqual(c.PrevValue, c.NextValue)

    return nil
}
```

- [ ] **Step 2: Write test**

```go
// circuits/circuits_test.go (add)

func TestTransitionCircuit_ValidTransition(t *testing.T) {
    var prevHash, prevBlind, nextHash, nextBlind fr.Element
    prevHash.SetInt64(100)
    prevBlind.SetInt64(111)
    nextHash.SetInt64(200)
    nextBlind.SetInt64(222)

    prevCommit := gnark_poseidon.Sum(prevHash, prevBlind)
    nextCommit := gnark_poseidon.Sum(nextHash, nextBlind)

    ccs, pk, vk, err := CompileAndSetup(&TransitionCircuit{})
    if err != nil {
        t.Fatal(err)
    }

    assignment := &TransitionCircuit{
        PrevCommit:         prevCommit,
        NextCommit:         nextCommit,
        PrevTranscriptHash: prevHash,
        PrevBlinding:       prevBlind,
        NextTranscriptHash: nextHash,
        NextBlinding:       nextBlind,
        PrevValue:          100, // monotonic: 100 <= 200
        NextValue:          200,
    }

    witness, _ := frontend.NewWitness(assignment, Curve.ScalarField())
    proof, err := plonk.Prove(ccs, pk, witness)
    if err != nil {
        t.Fatal(err)
    }
    pubWitness, _ := witness.Public()
    if err := plonk.Verify(proof, vk, pubWitness); err != nil {
        t.Errorf("valid transition rejected: %v", err)
    }
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./circuits/ -v -timeout 180s
```

---

## Phase 5: Selective Disclosure & Integration

### Task 5.1: Content disclosure (verifier sees content)

**Files:**
- Create: `disclosure.go`
- Create: `disclosure_test.go`

The disclosure proof now includes a **forest inclusion proof**:

```go
type ContentDisclosure struct {
    Config               *Config               `json:"config"`
    Blinding             []byte                 `json:"blinding"`
    MembershipProof      *MembershipProof       `json:"membership_proof"`
    ChainID              string                 `json:"chain_id"`
    IMTRoot              string                 `json:"imt_root"`
    ForestInclusionProof *ForestInclusionProof  `json:"forest_inclusion_proof"`
    Bulletin             *EpochBulletin         `json:"bulletin"`
}
```

`VerifyContentDisclosure` checks:
1. Bulletin signature valid (operator pubkey)
2. Chain IMT root included in forest root (forest inclusion proof against `bulletin.ForestRoot`)
3. Commitment included in chain IMT (membership proof against `IMTRoot`)
4. Commitment matches config + blinding (`verifyCommitment`)
5. Config self-validates (SHA-256 checksum)

```go
func VerifyContentDisclosure(d *ContentDisclosure, operatorPubKey string) error {
    if err := d.Bulletin.Verify(operatorPubKey); err != nil {
        return fmt.Errorf("bulletin: %w", err)
    }
    if !VerifyForestInclusion(d.IMTRoot, d.ForestInclusionProof, d.Bulletin.ForestRoot) {
        return errors.New("chain not in forest")
    }
    if !VerifyMembershipProof(d.Config.Meta.Commit, d.MembershipProof, d.IMTRoot) {
        return errors.New("commitment not in chain")
    }
    if err := verifyCommitment(d.Config, d.Blinding); err != nil {
        return fmt.Errorf("commitment: %w", err)
    }
    if err := d.Config.Validate(); err != nil {
        return fmt.Errorf("integrity: %w", err)
    }
    return nil
}
```

---

### Task 5.2: ZK disclosure (verifier does NOT see content)

**Files:**
- Modify: `disclosure.go`
- Modify: `disclosure_test.go`

A ZK disclosure proves "a version exists in this chain in this forest that satisfies some property" without revealing content:

```go
type ZKDisclosure struct {
    CommitmentProof      []byte                `json:"commitment_proof"`      // PLONK proof bytes
    InclusionProof       []byte                `json:"inclusion_proof"`       // PLONK proof bytes
    Commit               string                `json:"commit"`               // public input
    IMTRoot              string                `json:"imt_root"`             // public input
    ChainID              string                `json:"chain_id"`
    ForestInclusionProof *ForestInclusionProof `json:"forest_inclusion_proof"`
    Bulletin             *EpochBulletin        `json:"bulletin"`
}
```

Verification:
1. Bulletin signature valid
2. Chain root in forest (forest inclusion proof)
3. Verify PLONK commitment proof (public input: Commit)
4. Verify PLONK inclusion proof (public inputs: Commit as leaf, IMTRoot)

The verifier learns only that *some* valid commitment exists in the chain — not the content, not the blinding factor.

---

### Task 5.3: Commitment chain validation

**Files:**
- Modify: `journal.go`

Add `ValidateCommitmentChain` that walks `PrevCommit → Commit` links, parallel to the existing CS chain validation. In privacy mode, this is the primary chain integrity check.

```go
func (j *Journal) ValidateCommitmentChain(entries []*JournalEntry) error {
    for i, entry := range entries {
        if i > 0 {
            prev := entries[i-1]
            if entry.PrevCommit != prev.Commit {
                return fmt.Errorf("commitment chain break at %d", i)
            }
        }
    }
    return nil
}
```

---

### Task 5.4: Privacy-aware ValidateChain

**Files:**
- Modify: `journal.go`
- Modify: `manager.go`

When `entry.Config == nil` (privacy mode), `ValidateChain` loads the config from the config store to perform integrity checks:

```go
// In ValidateChain, when entry.Config is nil:
if entry.Config == nil && storage != nil {
    cs := NewConfigStorage(storage, "configs")
    cfg, err := cs.Load(ctx, entry.ID, entry.Version)
    if err == nil {
        if err := cfg.Validate(); err != nil {
            return fmt.Errorf("entry %d config invalid: %w", i, err)
        }
    }
}
```

The Manager's `ValidateChain` passes its storage reference through.

---

### Task 5.5: Journal entry with PrevCommit + Compact interaction

**Files:**
- Modify: `journal.go`

```go
type JournalEntry struct {
    ID         string    `json:"id"`
    Version    uint64    `json:"v"`
    CS         string    `json:"cs"`
    PrevCS     string    `json:"prev_cs,omitempty"`
    Time       time.Time `json:"t"`
    Operation  string    `json:"op"`
    Config     *Config   `json:"config,omitempty"`
    Commit     string    `json:"commit,omitempty"`
    PrevCommit string    `json:"prev_commit,omitempty"`
}
```

**Compact interaction:** When `Compact` truncates to the last N entries, the surviving entries still have valid `PrevCS → CS` links among themselves, but the oldest surviving entry's `PrevCS` points to a now-deleted entry. The same applies to `PrevCommit`. This was always the case for `PrevCS` — compaction already breaks the link to pre-compaction entries. Document this: compaction preserves *recent* chain integrity, not *full* chain integrity. Full chain integrity requires the config store.

**IMT compaction is a separate, destructive operation.** Journal compaction removes old entries but the config store still holds all versions — a membership proof for a pre-compaction version can still be generated by collecting commitment entries from the config store. However, if the config store itself were pruned, those proofs would be lost. The IMT's frontier only supports appending; there is no "compact the tree" operation. The tree's root always reflects all appended leaves, including ones whose journal entries were compacted.

**Bulletin publication anchor (Phase 6 concern):** `PublishEpoch` writes to local storage (`bulletins/epoch_%d.json`). The article says bulletins should be published on "an immutable bulletin (blockchain anchor, time-stamping authority, or signed append-only log)." Local storage is not operator-immutable — the operator can rewrite history. Anchoring to an external immutable store is a Phase 6 extension.

---

### Task 5.6: End-to-end integration test

Tests both content disclosure and ZK disclosure paths. Verifies:
- Commitment chain links (`PrevCommit → Commit`)
- Forest inclusion proofs work
- Bulletin contains only ForestRoot (no individual chain roots)
- Content disclosure round-trips
- Journal in privacy mode has no embedded configs
- Backward compatibility: classic manager still works unchanged

---

## Dependency Graph

```
Phase 1 (Commitments)
  Task 1.1  Two-stage Poseidon primitive (circuit-aligned)
  Task 1.2  Domain-separated transcript with PrevCommit ← 1.1
  Task 1.3  Config commitment/verification ← 1.2
  Task 1.4  BlindingStore interface
  Task 1.5  Manager integration with PrevCommit chain ← 1.3, 1.4

Phase 2 (IMT) ← Phase 1
  Task 2.1  Frontier-only IMT (article's algorithm)
  Task 2.2  Membership proofs (from stored leaves)
  Task 2.3  IMT persistence (frontier serialization)
  Task 2.4  IMT + Manager integration ← 2.1, 2.2, 1.5

Phase 3 (Forest) ← Phase 2
  Task 3.1  Forest Merkle tree with BLAKE3 ordering + inclusion proofs
  Task 3.2  Epoch bulletins (ForestRoot only) ← 3.1
  Task 3.3  Forest + Manager integration ← 3.2, 2.4

Phase 4 (ZK Circuits) ← Phase 1 only (implementation parallelizable with 2 & 3; cross-tests in 4.2 need 2.2)
  Task 4.1  Two-element commitment circuit (matches native)
  Task 4.2  Inclusion proof circuit ← 4.1
  Task 4.3  Transition predicate circuit ← 4.1

Phase 5 (Disclosure) ← Phases 1-4
  Task 5.1  Content disclosure with forest inclusion proof
  Task 5.2  ZK disclosure (circuits wired in) ← 4.1, 4.2
  Task 5.3  Commitment chain validation
  Task 5.4  Privacy-aware ValidateChain
  Task 5.5  JournalEntry with PrevCommit + Compact notes
  Task 5.6  End-to-end integration ← 5.1-5.5
```

## Phase-Exit Criteria

| Phase | Done When |
|-------|-----------|
| 1 | Two-stage `poseidonCommit` matches circuit format (tested). PrevCommit chain links verified across Create/Update/Rollback. UpdateMeta clears all privacy fields. `bytesToFieldElements` uses length prefix. Test vectors frozen. All existing tests pass. Optional: fuzz targets for `poseidonCommit` and `bytesToFieldElements`. |
| 2 | Fixed-depth IMT (Semaphore algorithm): Append/Root consistent (tested). `CanonicalLeaf` binds position + commitment + prevCommit. `BuildMembershipProof` from canonical leaf list verifies against IMT root for all leaf counts. IMT survives Manager restart via journal rebuild. |
| 3 | `BuildForest` uses BLAKE3(chainID) ordering. Forest inclusion proofs verify. Bulletin stores only ForestRoot + digest. `PublishEpoch` produces verifiable bulletins. |
| 4 | Commitment circuit uses `(TranscriptHash, Blinding)` — two elements matching native. Native commitment accepted by circuit (cross-test). Inclusion and transition circuits compile, prove, verify. |
| 5 | Content disclosure: bulletin → forest inclusion → IMT inclusion → commitment → integrity. ZK disclosure: same chain but with PLONK proofs instead of revealed content. Commitment chain validation walks PrevCommit→Commit. Privacy-mode ValidateChain loads from config store. Full integration test passes. |
