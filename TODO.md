# MerkleForest Privacy — Action Plan

Evolve Viracochan from a transparent versioned-config chain into the full
[MerkleForest](https://canny.substack.com/p/merkleforest-privacy) privacy
architecture. Detailed implementation plan with code:
[`tasks-merkleforest-privacy.md`](tasks-merkleforest-privacy.md) (v3.1, verified).

## Current state

SHA-256 checksum chain, Schnorr signatures, canonical JSON, append-only
journal, state reconstruction. All tests pass (`go test -race ./...`).

## Target state

Hiding Poseidon commitments, per-chain Incremental Merkle Trees, cross-chain
forest root with epoch bulletins, PLONK zero-knowledge circuits, and selective
disclosure — all opt-in alongside the existing checksum chain.

## Phases

### Phase 1 — Poseidon Commitments & Blinding Factors

- [ ] 1.1 Add `gnark-crypto` + `blake3` deps; two-stage `poseidonCommit` (circuit-aligned)
- [ ] 1.2 `Meta` gains `PrevCommit`, `Commit`, `CommitAlg`, `IMTRoot`; `UpdateMeta` clears them; 
          `buildTranscript` uses `PrevCommit` (self-referential chain)
- [ ] 1.3 `computeCommitment` / `verifyCommitment` round-trip
- [ ] 1.4 `BlindingStore` interface + `MemoryBlindingStore`
- [ ] 1.5 Manager integration: commitment block in Create/Update/Rollback; 
          journal strips content in privacy mode; `NewManager` accepts `ctx`
- [ ] 1.6 Freeze test vectors (`testdata/commitment_vectors.json`)

### Phase 2 — Incremental Merkle Tree

- [ ] 2.1 Fixed-depth IMT (Semaphore/Tornado Cash algorithm) with `CanonicalLeaf` position binding
- [ ] 2.2 `BuildMembershipProof` (depth-aware, from stored leaves) + `VerifyMembershipProof`
- [ ] 2.3 IMT serialization (`filledSubtrees` + `currentRoot`)
- [ ] 2.4 Manager integration: per-chain IMT, `rebuildIMTs` from journal on init, `collectChainLeaves` for disclosure

### Phase 3 — Forest Aggregation & Epochs

- [ ] 3.1 `BuildForest`: balanced Merkle tree of chain roots, BLAKE3(chainID) ordering, forest inclusion proofs
- [ ] 3.2 `EpochBulletin`: stores only `ForestRoot` + digest (no individual chain roots); signed by operator
- [ ] 3.3 Manager `PublishEpoch`: builds forest, creates bulletin, caches `ForestState`

### Phase 4 — ZK Circuits (parallelizable with 2 & 3; cross-tests need 2.2)

- [ ] 4.1 `CommitmentCircuit`: `Poseidon(TranscriptHash, Blinding) == Commit` (PLONK); native/circuit cross-test
- [ ] 4.2 `InclusionCircuit`: Merkle path verification with Poseidon; native IMT proof → circuit witness round-trip
- [ ] 4.3 `TransitionCircuit`: template predicate (monotonic increase) over committed states

### Phase 5 — Selective Disclosure & Integration

- [ ] 5.1 `ContentDisclosure`: config + blinding + membership proof + forest inclusion proof + bulletin
- [ ] 5.2 `ZKDisclosure`: PLONK proofs instead of revealed content
- [ ] 5.3 `ValidateCommitmentChain`: walks `PrevCommit → Commit` links
- [ ] 5.4 Privacy-aware `ValidateChain`: loads from config store when journal entries lack configs
- [ ] 5.5 `JournalEntry` gains `PrevCommit`; compact interaction documented
- [ ] 5.6 End-to-end integration test (both disclosure modes, backward compat)

### Phase 6 — Future (not in current plan)

- Per-chain keys (`ChainPubKey`) replacing string IDs in forest ordering
- External bulletin anchoring (blockchain, TSA, append-only log)
- Fuzz targets for `poseidonCommit`, `bytesToFieldElements`, IMT, forest

## Key design decisions

| #  | Decision                                                  | Rationale                                                                                              |
|----|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| D1 | Two-stage Poseidon: `Poseidon(Poseidon(chunks…), blind)`  | Circuit takes exactly 2 field elements; native must match                                              |
| D2 | Self-referential commitment chain (`PrevCommit → Commit`) | Article: `"prev:" \|\| PrevCommit_bytes`                                                               |
| D3 | BLAKE3(chainID) for forest ordering                       | Article specifies BLAKE3; chainID is a stepping stone for ChainPubKey                                  |
| D4 | Bulletin stores ForestRoot + digest only                  | Article: "digest of all chain roots"                                                                   |
| D5 | Fixed-depth IMT with Semaphore algorithm                  | Article's pseudocode is a sketch; real impl needs zero-padded balanced tree for Root/Proof consistency |
| D6 | Forest as balanced Merkle tree                            | Article uses sequential fold; balanced tree enables O(log n) inclusion proofs                          |
| D7 | `CanonicalLeaf(index, commit, prevCommit)`                | Position binding prevents reordering; domain tag prevents leaf/node confusion                          |

## Dependencies

```
gnark-crypto  — native Poseidon / BN254
gnark         — ZK circuits (PLONK)
blake3        — chain ordering
btcec         — existing Schnorr signatures (unchanged)
```
