// Snippet 1 — Per-chain Incremental Merkle Tree with canonical leaves.
//
// Carries: Theorem 3 (per-chain inclusion soundness).
//
// The tree binds three things into every leaf:
//   - position i  → reorder-resistance
//   - prev_i      → predecessor chaining
//   - "leaf" tag  → leaf/node domain separation (required by the proof)
//
// leaf_i  = Poseidon("leaf" || i || C_i || prev_i)
// node    = Poseidon("node" || L || R)
//
// Append is O(depth). Root is O(1). Proof generation is O(2^depth) over
// stored leaves (acceptable for presentation; production code reconstructs
// from the journal on demand).

package merkleforest

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
)

const (
	leafDomain = uint64(0x6c656166) // "leaf"
	nodeDomain = uint64(0x6e6f6465) // "node"
)

// IMT is a fixed-depth incremental Merkle tree over a single chain.
type IMT struct {
	depth          int
	zeros          []fr.Element // zeros[level] = empty subtree hash at this level
	filledSubtrees []fr.Element // last left-child at each level
	root           fr.Element
	leaves         []fr.Element // canonical leaves, kept for proof generation
	prev           fr.Element   // leaf hash of position size-1 (or zero)
	size           uint64
}

func NewIMT(depth int) *IMT {
	zeros := make([]fr.Element, depth+1)
	// zeros[0] is the all-zero field element (default fr.Element)
	for i := 1; i <= depth; i++ {
		zeros[i] = nodeHash(zeros[i-1], zeros[i-1])
	}
	filled := make([]fr.Element, depth)
	copy(filled, zeros[:depth])
	return &IMT{
		depth:          depth,
		zeros:          zeros,
		filledSubtrees: filled,
		root:           zeros[depth],
	}
}

// Append commits a new record to the chain.
//   commit: the hiding commitment C_i (already computed by caller)
//   returns: (canonical leaf hash, new chain root)
func (t *IMT) Append(commit fr.Element) (leaf fr.Element, root fr.Element, err error) {
	if t.size >= 1<<uint(t.depth) {
		return leaf, root, errors.New("imt full")
	}

	// canonical leaf binds position and predecessor
	leaf = leafHash(t.size, commit, t.prev)

	// walk up the tree, no early exit (Tornado/Semaphore pattern)
	current := leaf
	idx := t.size
	for level := 0; level < t.depth; level++ {
		if idx%2 == 0 {
			t.filledSubtrees[level] = current
			current = nodeHash(current, t.zeros[level])
		} else {
			current = nodeHash(t.filledSubtrees[level], current)
		}
		idx /= 2
	}

	t.size++
	t.root = current
	t.prev = leaf
	t.leaves = append(t.leaves, leaf)
	return leaf, current, nil
}

func (t *IMT) Root() fr.Element { return t.root }
func (t *IMT) Size() uint64     { return t.size }

// InclusionProof for the leaf at position i.
type InclusionProof struct {
	Leaf     fr.Element
	Index    uint64
	Siblings []fr.Element // length = depth, root-side last
}

func (t *IMT) Prove(i uint64) (*InclusionProof, error) {
	if i >= t.size {
		return nil, fmt.Errorf("index %d out of range [0, %d)", i, t.size)
	}

	// pad the leaf set to 2^depth with the zero leaf
	full := make([]fr.Element, 1<<uint(t.depth))
	copy(full, t.leaves)
	for k := len(t.leaves); k < len(full); k++ {
		full[k] = t.zeros[0]
	}

	siblings := make([]fr.Element, t.depth)
	idx := i
	layer := full
	for level := 0; level < t.depth; level++ {
		if idx%2 == 0 {
			siblings[level] = layer[idx+1]
		} else {
			siblings[level] = layer[idx-1]
		}
		next := make([]fr.Element, len(layer)/2)
		for k := 0; k < len(layer); k += 2 {
			next[k/2] = nodeHash(layer[k], layer[k+1])
		}
		layer = next
		idx /= 2
	}

	return &InclusionProof{Leaf: t.leaves[i], Index: i, Siblings: siblings}, nil
}

// VerifyInclusion checks π against a published root.
// The verifier never sees the underlying commitment or message — only
// that some leaf at position Index hashes up to root.
func VerifyInclusion(p *InclusionProof, root fr.Element) bool {
	current := p.Leaf
	idx := p.Index
	for _, sib := range p.Siblings {
		if idx%2 == 0 {
			current = nodeHash(current, sib)
		} else {
			current = nodeHash(sib, current)
		}
		idx /= 2
	}
	return current.Equal(&root)
}

// Hashing primitives — domain-separated, length-prefixed.

func leafHash(index uint64, commit, prev fr.Element) fr.Element {
	var dom, idx fr.Element
	dom.SetUint64(leafDomain)
	idx.SetUint64(index)
	return poseidon.Sum(dom, idx, commit, prev)
}

func nodeHash(left, right fr.Element) fr.Element {
	var dom fr.Element
	dom.SetUint64(nodeDomain)
	return poseidon.Sum(dom, left, right)
}
