// Snippet 2 — Forest binary Merkle root with cross-chain inclusion proofs.
//
// Carries: Theorem 4 (cross-chain binding).
//
// At each epoch, every active chain owner publishes its current chain
// root R^(j). The operator orders the chains deterministically by
// BLAKE3(chainID), builds a balanced Merkle tree, signs the resulting
// forest root F_e, and publishes (e, F_e, ordering) on the bulletin.
//
// A verifier presented with (R^(j), forest path, F_e, operator sig)
// is convinced — assuming CR of Poseidon and EUF-CMA of the operator
// signature — that chain j was bound into the forest at epoch e with
// exactly root R^(j).
//
// Key correction over the original article: this is a *binary Merkle
// tree*, not a sequential hash fold. Cross-chain proofs are O(log n),
// not O(n), and the security reduction in Theorem 4 carries through.

package merkleforest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	"lukechampine.com/blake3"
)

const forestDomain = uint64(0x666f7273) // "fors" — distinct from leaf/node

// Forest holds one epoch's aggregated state.
type Forest struct {
	Epoch      uint64
	OrderedIDs []string     // deterministic order via BLAKE3(chainID)
	ChainRoots []fr.Element // parallel to OrderedIDs
	Depth      int          // ceil(log2(n)), padded with zero
	Root       fr.Element
}

// BuildForest aggregates one chain root per chain into a binary
// Merkle tree using BLAKE3-keyed deterministic ordering.
func BuildForest(epoch uint64, chainRoots map[string]fr.Element) *Forest {
	n := len(chainRoots)
	if n == 0 {
		return &Forest{Epoch: epoch}
	}

	// 1. Deterministic ordering by BLAKE3(chainID).
	type entry struct {
		key  [32]byte
		id   string
		root fr.Element
	}
	entries := make([]entry, 0, n)
	for id, r := range chainRoots {
		entries = append(entries, entry{
			key:  blake3.Sum256([]byte(id)),
			id:   id,
			root: r,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		for k := 0; k < 32; k++ {
			if entries[i].key[k] != entries[j].key[k] {
				return entries[i].key[k] < entries[j].key[k]
			}
		}
		return false
	})

	// 2. Pad to the next power of two with the zero element.
	depth := 0
	for (1 << uint(depth)) < n {
		depth++
	}
	full := 1 << uint(depth)
	if full == 0 {
		full = 1
	}

	ids := make([]string, n)
	leaves := make([]fr.Element, full) // zero-padded
	for i, e := range entries {
		ids[i] = e.id
		leaves[i] = e.root
	}

	// 3. Fold pairwise to the root with the forest domain separator.
	layer := leaves
	for len(layer) > 1 {
		next := make([]fr.Element, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next[i/2] = forestNode(layer[i], layer[i+1])
		}
		layer = next
	}

	chainRootsOrdered := make([]fr.Element, n)
	for i, e := range entries {
		chainRootsOrdered[i] = e.root
	}

	return &Forest{
		Epoch:      epoch,
		OrderedIDs: ids,
		ChainRoots: chainRootsOrdered,
		Depth:      depth,
		Root:       layer[0],
	}
}

// ForestProof: O(log n) cross-chain inclusion path.
type ForestProof struct {
	ChainRoot fr.Element
	Index     int
	Siblings  []fr.Element
}

func (f *Forest) Prove(chainID string) (*ForestProof, error) {
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

	full := 1 << uint(f.Depth)
	if full == 0 {
		full = 1
	}
	layer := make([]fr.Element, full)
	copy(layer, f.ChainRoots)

	siblings := make([]fr.Element, f.Depth)
	cur := idx
	for level := 0; level < f.Depth; level++ {
		if cur%2 == 0 {
			siblings[level] = layer[cur+1]
		} else {
			siblings[level] = layer[cur-1]
		}
		next := make([]fr.Element, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			next[i/2] = forestNode(layer[i], layer[i+1])
		}
		layer = next
		cur /= 2
	}
	return &ForestProof{
		ChainRoot: f.ChainRoots[idx],
		Index:     idx,
		Siblings:  siblings,
	}, nil
}

// VerifyForestProof recomputes the forest root from the path and
// returns true iff it matches `forestRoot`.
func VerifyForestProof(p *ForestProof, forestRoot fr.Element) bool {
	current := p.ChainRoot
	idx := p.Index
	for _, sib := range p.Siblings {
		if idx%2 == 0 {
			current = forestNode(current, sib)
		} else {
			current = forestNode(sib, current)
		}
		idx /= 2
	}
	return current.Equal(&forestRoot)
}

// Bulletin is the operator's signed publication for one epoch.
// Verifiers fetch this from the (assumed-immutable) bulletin channel
// and check the operator signature before trusting the forest root.
type Bulletin struct {
	Epoch      uint64
	ForestRoot fr.Element
	ChainCount int
	OrderHash  [32]byte // BLAKE3 of concatenated chain IDs in order
	Signature  []byte   // operator's Ed25519 signature
}

func PublishBulletin(f *Forest, sk ed25519.PrivateKey) *Bulletin {
	h := blake3.New(32, nil)
	for _, id := range f.OrderedIDs {
		h.Write([]byte(id))
		h.Write([]byte{0x00}) // separator
	}
	var orderHash [32]byte
	copy(orderHash[:], h.Sum(nil))

	b := &Bulletin{
		Epoch:      f.Epoch,
		ForestRoot: f.Root,
		ChainCount: len(f.OrderedIDs),
		OrderHash:  orderHash,
	}
	b.Signature = ed25519.Sign(sk, b.signingPayload())
	return b
}

func (b *Bulletin) Verify(pk ed25519.PublicKey) error {
	if !ed25519.Verify(pk, b.signingPayload(), b.Signature) {
		return errors.New("bulletin signature invalid")
	}
	return nil
}

func (b *Bulletin) signingPayload() []byte {
	rootBytes := b.ForestRoot.Marshal()
	out := make([]byte, 0, 8+len(rootBytes)+8+32)
	out = appendUint64(out, b.Epoch)
	out = append(out, rootBytes...)
	out = appendUint64(out, uint64(b.ChainCount))
	out = append(out, b.OrderHash[:]...)
	return out
}

func appendUint64(b []byte, v uint64) []byte {
	for i := 7; i >= 0; i-- {
		b = append(b, byte(v>>uint(i*8)))
	}
	return b
}

func forestNode(left, right fr.Element) fr.Element {
	var dom fr.Element
	dom.SetUint64(forestDomain)
	return poseidon.Sum(dom, left, right)
}
