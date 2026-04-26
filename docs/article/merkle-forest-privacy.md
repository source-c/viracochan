---
title: "Merkle-Forest Privacy: A Cryptographic Architecture for Transparent yet Confidential Versioned Chains"
subtitle: "Formal Treatment with Security Proofs"
date: "October 2025 (rev. April 2026)"
abstract: |
  Distributed versioned data structures must reconcile two opposing
  requirements: *transparency* - anyone can verify that the recorded
  history has not been tampered with - and *confidentiality* - observers
  learn nothing about payloads they are not authorised to see. Classical
  hash-chained ledgers give the former and forbid the latter; classical
  encrypted stores give the latter and weaken the former. We present
  *Merkle-Forest Privacy*, a three-layer architecture that combines
  hiding commitments, per-chain incremental Merkle trees, and a binary
  Merkle aggregation across chains (the *forest*) to achieve both
  properties simultaneously. We give precise definitions for each
  layer, state and prove four security theorems (binding,
  computational hiding, per-chain inclusion soundness, and cross-chain
  binding), provide a concrete instantiation, and analyse the storage
  and proof-size trade-offs honestly. The construction reduces to
  standard assumptions: collision resistance of the underlying hash
  family and EUF-CMA of the operator signature scheme. Optional
  zero-knowledge integration is described at the level of circuit
  interfaces, with proof sketches for soundness and zero-knowledge
  carried over from the underlying SNARK.
---

# 1. Introduction

A *versioned chain* is an append-only sequence of records where each
record commits to its predecessor. Distributed ledgers, transparency
logs, and reproducible-build attestations are all instances. The
canonical design - what we will call a *glass chain* - stores public
hashes of payloads so any observer can recompute the digest from the
visible bytes and verify integrity. Glass chains give strong public
auditability and zero confidentiality: every byte that ever entered the
chain is visible to every observer.

Many real applications require the opposite balance on payloads while
keeping the auditability of the chain structure. Confidential
supply-chain telemetry, health-record provenance, regulated financial
trails, and multi-tenant build attestations all want a verifier to be
able to check *that* an event occurred, with what predecessor, and
within what aggregate, without learning *what* the event was unless
explicitly authorised.

The standard cryptographic toolkit already contains the pieces:

- **Hiding commitments** decouple binding from disclosure. A commitment
  $C = \mathrm{Commit}(m, r)$ binds the committer to $m$ while
  revealing nothing about $m$ to a party who does not know $r$.
- **Merkle trees** aggregate many commitments into one root, with
  membership proofs of size $O(\log n)$.
- **Zero-knowledge proofs** demonstrate predicates over committed data
  without revealing it.

What is missing is a clean, end-to-end architecture that composes these
primitives across multiple chains in a way that is both efficient and
*provably* secure under explicit assumptions. The contribution of this
paper is exactly that composition, together with theorems that pin down
which properties hold under which assumptions and where the boundary
of formal guarantees lies.

## 1.1 Contributions

1. **Architecture.** A three-layer construction - hiding commitments,
   per-chain incremental Merkle trees, and a forest Merkle root over
   chains - with a precise specification of each layer and the
   interfaces between them (Sections 3, 4).
2. **Security theorems.** Four theorems with full proofs covering
   binding, hiding, per-chain inclusion soundness, and cross-chain
   binding, reducing the security of the composed system to standard
   assumptions on the underlying primitives (Section 5).
3. **Honest evaluation.** Concrete formulas for storage and proof size,
   correcting common arithmetic errors that appear in informal
   write-ups of similar constructions (Section 7).
4. **ZK integration.** A specification of three optional circuits
   (commitment correctness, inclusion, transition) and a discussion of
   how their security properties compose with those of the base
   architecture (Section 6).

## 1.2 What this paper does *not* claim

We are explicit about the limits of the formal results. We do **not**
prove:

- Liveness or censorship-resistance of the operator publishing forest
  roots. These are protocol-level concerns outside the cryptographic
  model.
- Security of any specific hardware (TEE, secure element) used by
  participants.
- Privacy properties of the network layer; we treat communication as a
  black box that delivers messages.
- Soundness or zero-knowledge of any specific SNARK; we cite these as
  black-box assumptions of the chosen system (Section 6).

# 2. Background

## 2.1 Notation and conventions

We write $\lambda \in \mathbb{N}$ for the security parameter. PPT means
*probabilistic polynomial-time*. A function
$\mathrm{negl} : \mathbb{N} \to \mathbb{R}$ is *negligible* if for every
polynomial $p$ there exists $N$ such that
$\mathrm{negl}(\lambda) < 1/p(\lambda)$ for all $\lambda \geq N$. We
write $x \xleftarrow{\$} S$ for sampling $x$ uniformly from a finite
set $S$. Concatenation is $\|$; $|x|$ denotes the bit-length of $x$.
$[n] = \{1, \ldots, n\}$. By a hash family
$H = \{H_\lambda : \{0,1\}^* \to \{0,1\}^{\ell(\lambda)}\}$ we mean a
family of functions indexed by $\lambda$; we suppress $\lambda$ when
clear from context.

## 2.2 Cryptographic primitives

**Collision-resistant hash families.** $H$ is *collision-resistant*
(CR) if for every PPT adversary $\mathcal{A}$,

$$
\Pr_{\lambda} \left[ (x, x') \leftarrow \mathcal{A}(1^\lambda) :
  x \neq x' \wedge H(x) = H(x') \right] \leq \mathrm{negl}(\lambda).
$$

**Commitment schemes.** A non-interactive commitment scheme is a triple
of PPT algorithms $(\mathsf{Setup}, \mathsf{Commit}, \mathsf{Open})$.
$\mathsf{Setup}(1^\lambda)$ produces public parameters $\mathsf{pp}$.
$\mathsf{Commit}(\mathsf{pp}, m; r)$ outputs $C$. $\mathsf{Open}$ takes
$(\mathsf{pp}, C, m, r)$ and returns $\{0,1\}$.

The scheme is *computationally binding* if for every PPT $\mathcal{A}$,

$$
\Pr \left[ \mathsf{Open}(\mathsf{pp}, C, m, r) = 1 \wedge
           \mathsf{Open}(\mathsf{pp}, C, m', r') = 1 \wedge m \neq m' \right]
\leq \mathrm{negl}(\lambda),
$$

where $\mathsf{pp} \leftarrow \mathsf{Setup}(1^\lambda)$ and
$(C, m, r, m', r') \leftarrow \mathcal{A}(\mathsf{pp})$.

The scheme is *computationally hiding* if for every PPT $\mathcal{A}$
and every pair of equal-length messages $m_0, m_1$,

$$
\left| \Pr[\mathcal{A}(\mathsf{pp}, \mathsf{Commit}(\mathsf{pp}, m_0; r)) = 1] -
       \Pr[\mathcal{A}(\mathsf{pp}, \mathsf{Commit}(\mathsf{pp}, m_1; r)) = 1] \right|
\leq \mathrm{negl}(\lambda),
$$

where $\mathsf{pp} \leftarrow \mathsf{Setup}(1^\lambda)$ and
$r \xleftarrow{\$} \{0,1\}^{\rho(\lambda)}$ for the scheme's randomness
length $\rho$.

**Merkle trees.** Given a CR hash $H$ and leaves
$\ell_1, \ldots, \ell_n$ (with $n$ a power of two; we pad with a
distinguished zero leaf when necessary), the binary Merkle root is
defined recursively: for a single leaf $\ell$, the root is
$H(0\|\ell)$; for two subtrees with roots $L, R$, the parent is
$H(1\|L\|R)$. The domain-separation prefix bits $0$/$1$ for leaves and
internal nodes are critical for the standard reduction to CR; without
them, one can substitute a leaf with an internal node carrying the same
hash and break inclusion soundness. An *inclusion proof* for leaf
$\ell_i$ is the list of sibling hashes $\pi_i$ along the root path; a
verifier recomputes the root by hashing $\ell_i$ together with the
siblings and checks equality with the published root.

**Signature schemes.** $\Sigma = (\mathsf{KeyGen}, \mathsf{Sign},
\mathsf{Vfy})$ is *EUF-CMA secure* if no PPT adversary with oracle
access to $\mathsf{Sign}_{sk}(\cdot)$ can output a fresh
message-signature pair $(m^*, \sigma^*)$ with $\mathsf{Vfy}_{pk}(m^*,
\sigma^*) = 1$ except with negligible probability.

## 2.3 Why a hash commitment differs from a hash checksum

A SHA-256 *checksum* of a record $m$ is a deterministic public function
of $m$. Anyone who possesses the canonical bytes can recompute it,
which makes it useful for integrity but useless for confidentiality:
the checksum is a one-way function only when $m$ has high min-entropy,
and most application payloads do not. Worse, if the message space is
small or guessable (e.g., a boolean, a small enumeration, a known
template), the adversary can compute the checksum of every candidate
and recover $m$ exactly.

A *commitment* $C = \mathsf{Commit}(m; r)$ with a fresh uniformly random
$r$ of length $\rho(\lambda)$ severs this link: the same $m$ produces
different commitments under different $r$, and the hiding property
guarantees that $C$ leaks nothing about $m$ to a party who does not
know $r$.

# 3. System Model

## 3.1 Parties and trust

The architecture has three logical roles. The *operator* maintains the
forest and publishes forest roots at fixed epochs. *Chain owners* each
maintain a local incremental Merkle tree (IMT) and submit per-epoch
chain roots to the operator. *Verifiers* receive selectively disclosed
proofs and check them against published forest roots.

The operator is **untrusted for confidentiality**: it never sees
plaintext payloads. The operator is **trusted for liveness**: if it
stops publishing forest roots, the system halts (this is a known
limitation; see Section 8).

Chain owners are trusted to keep their own blinding factors confidential
and to handle their own data appropriately. The architecture does not
defend a chain owner against itself.

Verifiers are mutually distrusting; they trust only what they can
recompute from public data and the proofs they receive.

## 3.2 Adversary

We consider a static, malicious adversary $\mathcal{A}$ that may:

- Observe all public data: forest roots, chain roots published at
  epochs, and any commitments and inclusion proofs disclosed to it.
- Adaptively request commitments and openings to specific records of
  its choice (this captures the case where the adversary controls some
  chain owners or has compromised some authorised verifiers).
- Submit arbitrary chain roots and inclusion proofs for verification.

$\mathcal{A}$ may **not**:

- Compute hash collisions, except with the negligible probability
  guaranteed by CR.
- Forge operator signatures on forest roots, except with the negligible
  probability guaranteed by EUF-CMA.

The adversary is computationally bounded (PPT in $\lambda$).

## 3.3 What the architecture guarantees, informally

- **Local privacy.** A non-authorised observer who sees a published
  commitment, the chain roots it appears in, and the forest roots
  binding those chain roots learns nothing about the underlying
  message except its existence and position in the chain.
- **Selective disclosure.** A chain owner can reveal a specific record
  (or a derived predicate over records) to a chosen verifier without
  exposing other records.
- **Inclusion soundness.** A verifier accepting a per-chain inclusion
  proof is convinced, except with negligible probability, that the
  committed leaf was indeed appended to the chain in the asserted
  position.
- **Cross-chain binding.** A verifier accepting a forest-level proof
  is convinced that the asserted chain root was bound into the
  asserted forest root, and therefore that all chain owners agree on
  the cross-chain history at that epoch.

The next two sections make these statements precise.

# 4. Construction

The construction has three layers. We specify each as a tuple of
algorithms.

## 4.1 Layer 1: Hiding Commitments

Let $\mathsf{Hash} : \{0,1\}^* \to \{0,1\}^\ell$ be a CR hash, modelled
as a random oracle for the hiding proof (Section 5.2). The commitment
algorithm is:

$$
\mathsf{Commit}(m) :
  \quad r \xleftarrow{\$} \{0,1\}^\lambda; \quad
  C := \mathsf{Hash}(\mathtt{"cmt"} \| m \| r); \quad
  \text{return } (C, r).
$$

$\mathsf{Open}(C, m, r) := [\mathsf{Hash}(\mathtt{"cmt"} \| m \| r) = C]$.

The domain separator $\mathtt{"cmt"}$ ensures commitments are distinct
from internal Merkle hashes (Section 4.2) and forest hashes
(Section 4.3) even if all three layers use the same underlying hash
function.

The randomness length is fixed at $\lambda$ bits (256 for
$\lambda = 128$). This is the source of computational hiding; reducing
$|r|$ below $\lambda$ weakens hiding correspondingly.

In practice $\mathsf{Hash}$ may be SHA-256 (for software/on-chain
verification) or Poseidon2 (for verification inside SNARK/STARK
circuits). The proofs in Section 5 are agnostic to the choice provided
the assumed properties hold.

## 4.2 Layer 2: Per-Chain Incremental Merkle Tree

Each chain owner maintains an *incremental Merkle tree* (IMT) over the
sequence of commitments $C_1, C_2, \ldots, C_t$ produced for its chain.
The IMT supports `Append` in $O(\log t)$ time and $O(\log t)$ state
(the *frontier*).

We define the canonical leaf of the chain at position $i$ as

$$
\mathsf{leaf}_i := \mathsf{Hash}(\mathtt{"leaf"} \| i \| C_i \| \mathsf{prev}_i),
$$

where $\mathsf{prev}_i$ is the leaf hash of position $i-1$ (with
$\mathsf{prev}_1$ a fixed all-zero string). The chaining of $\mathsf{prev}$
binds each leaf to its predecessor and prevents reordering: any
permutation of leaves that keeps the same multiset of commitments
produces a different leaf hash at every position.

Internal Merkle nodes are computed as
$\mathsf{node}(L, R) := \mathsf{Hash}(\mathtt{"node"} \| L \| R)$. The
tree is padded to the next power of two with the all-zero leaf
$\mathsf{leaf}_\bot := \mathsf{Hash}(\mathtt{"leaf"} \| 0 \| 0^\ell \| 0^\ell)$.

The chain root at time $t$, denoted $R_t$, is the root of the resulting
binary tree.

### 4.2.1 IMT append algorithm

```
state Frontier : array of Hash, initially empty
state Count    : Int, initially 0

function Append(commitment C, prev leaf hash p) -> (R, leaf):
    Count := Count + 1
    leaf := Hash("leaf" || Count || C || p)
    node := leaf
    idx  := Count - 1                    # zero-indexed position
    for level := 0 while (idx mod 2) == 1:
        sibling := Frontier[level]
        node    := Hash("node" || sibling || node)
        idx     := idx / 2
        level   := level + 1
    Frontier[level] := node
    R := compute_root_from_frontier(Frontier, Count)
    return (R, leaf)
```

`compute_root_from_frontier` zero-pads the right-hand siblings up to
the next power of two and folds the frontier into a single root in
$O(\log t)$ hash evaluations.

### 4.2.2 Inclusion proofs

An inclusion proof $\pi_i$ for leaf $\mathsf{leaf}_i$ in the tree of
size $t$ consists of the $\lceil \log_2 t \rceil$ sibling hashes along
the path from $\mathsf{leaf}_i$ to the root, together with a bit per
level indicating whether the path goes left or right.

`Verify(R, i, leaf, π)` recomputes the root by iteratively hashing
`leaf` with siblings according to the direction bits and returns
$[R' = R]$.

## 4.3 Layer 3: Forest Merkle Root

At the end of each epoch, every active chain owner publishes its
current chain root $R^{(j)}_t$ for chain $j \in [n]$. The operator
collects these and orders them deterministically; we use lexicographic
order on $\mathsf{Hash}(\mathtt{"chain-id"} \| \mathsf{ChainPubKey}_j)$.
This deterministic ordering is essential: a verifier who sees only the
forest root must be able to recompute it from the chain-root multiset
without ambiguity.

The forest root $F$ is the **binary Merkle root** over the ordered
sequence of chain roots, using the same `node` function as in
Layer 2:

$$
F := \mathsf{MerkleRoot}\bigl(R^{(\sigma(1))}, R^{(\sigma(2))}, \ldots, R^{(\sigma(n))}\bigr),
$$

where $\sigma$ is the deterministic ordering. The number of chains $n$
is padded to the next power of two with the zero leaf, identically to
Layer 2.

A *forest inclusion proof* for chain $j$ at epoch $e$ is the tuple
$(R^{(j)}, \pi^{\text{forest}}_j, F_e, \sigma_e)$ where
$\pi^{\text{forest}}_j$ is the $\lceil \log_2 n \rceil$-sized Merkle
path from $R^{(j)}$ to $F_e$ under the ordering $\sigma_e$.

The operator publishes $(e, F_e, \sigma_e)$ on an immutable bulletin
(blockchain anchor, time-stamping authority, or signed append-only
log) and signs the tuple with its long-term key
$pk_{\mathsf{op}}$. Verifiers fetch the published tuple and check the
operator signature before relying on $F_e$.

## 4.4 Summary of guarantees by layer

| Layer | Provides | Reduces to |
|-------|----------|-----------|
| 1: Hiding commitment | binding, hiding | CR (binding); RO model (hiding) |
| 2: Per-chain IMT | inclusion soundness within chain | CR |
| 3: Forest Merkle root | cross-chain binding | CR; EUF-CMA of operator |

# 5. Security

We state and prove four theorems. Throughout this section
$\mathsf{Hash}$ is the hash family of Section 4 and $\Sigma$ is the
operator signature scheme. $\lambda$ is the security parameter.

## 5.1 Theorem 1 (Commitment binding)

**Theorem.** If $\mathsf{Hash}$ is collision-resistant, then the
commitment scheme of Section 4.1 is computationally binding.

**Proof.** Suppose for contradiction that there is a PPT adversary
$\mathcal{A}_{\mathsf{bind}}$ that, on input $1^\lambda$, outputs
$(C, m, r, m', r')$ with $m \neq m'$ and
$\mathsf{Hash}(\mathtt{"cmt"} \| m \| r) =
 \mathsf{Hash}(\mathtt{"cmt"} \| m' \| r') = C$
with non-negligible probability $\varepsilon(\lambda)$.

Construct a CR adversary $\mathcal{B}$ as follows: on input
$1^\lambda$, run $\mathcal{A}_{\mathsf{bind}}(1^\lambda)$ to obtain
$(C, m, r, m', r')$. Output the pair
$x := \mathtt{"cmt"} \| m \| r$ and $x' := \mathtt{"cmt"} \| m' \| r'$.
Since $m \neq m'$, we have $x \neq x'$, and
$\mathsf{Hash}(x) = \mathsf{Hash}(x') = C$. Therefore $\mathcal{B}$
outputs a collision with probability $\varepsilon(\lambda)$,
contradicting CR of $\mathsf{Hash}$. $\square$

## 5.2 Theorem 2 (Commitment hiding)

**Theorem.** Modelling $\mathsf{Hash}$ as a random oracle, the
commitment scheme of Section 4.1 is computationally hiding.

**Proof sketch.** Let $\mathcal{A}_{\mathsf{hide}}$ be a PPT
distinguisher that on input $\mathsf{Commit}(m_b)$ for a uniformly
chosen $b \in \{0,1\}$ guesses $b$ with advantage $\varepsilon(\lambda)$.

The challenger samples $r \xleftarrow{\$} \{0,1\}^\lambda$ and computes
$C^* := \mathsf{Hash}(\mathtt{"cmt"} \| m_b \| r)$. Because $r$ is
uniform and $|r| = \lambda$, the probability that the adversary queries
the random oracle on the exact string $\mathtt{"cmt"} \| m_0 \| r$ or
$\mathtt{"cmt"} \| m_1 \| r$ is at most $q(\lambda) \cdot 2^{-\lambda}$,
where $q$ is the number of oracle queries made by the adversary
(polynomial in $\lambda$).

Conditioned on no such query, $C^*$ is a uniformly random element of
$\{0,1\}^\ell$ independent of $b$, so $\mathcal{A}_{\mathsf{hide}}$'s
advantage is zero. Removing the conditioning,
$\varepsilon(\lambda) \leq q(\lambda) \cdot 2^{-\lambda} =
 \mathrm{negl}(\lambda)$. $\square$

> **Remark.** Without the random oracle assumption, hiding does not
> follow from CR alone. Hash commitments are computationally hiding
> under the assumption that the hash is a *pseudorandom function*
> when keyed by $r$, which is a stronger property than CR but weaker
> than the RO model. For information-theoretic hiding one must move
> to Pedersen commitments over a prime-order group.

## 5.3 Theorem 3 (Per-chain inclusion soundness)

**Theorem.** Let $H$ be CR. Let $R_t$ be the chain root after $t$
appends to an IMT as defined in Section 4.2. No PPT adversary, given
the chain history, can produce
$(i, \mathsf{leaf}', \pi')$ with $\mathsf{leaf}' \neq \mathsf{leaf}_i$
and $\mathsf{Verify}(R_t, i, \mathsf{leaf}', \pi') = 1$, except with
negligible probability.

**Proof.** Suppose $\mathcal{A}_{\mathsf{incl}}$ outputs such a tuple
with non-negligible probability $\varepsilon$. Consider the path from
position $i$ to the root in the honest tree, with sequence of node
hashes $h_0 = \mathsf{leaf}_i, h_1, \ldots, h_d = R_t$ where
$d = \lceil \log_2 t \rceil$. Consider the path induced by
$(\mathsf{leaf}', \pi')$: a sequence
$h'_0 = \mathsf{leaf}' \neq h_0, h'_1, \ldots, h'_d = R_t$.

Let $k^* := \min\{k : h'_k = h_k\}$. Such a $k^*$ exists because
$h'_d = h_d = R_t$, and $k^* \geq 1$ because $h'_0 \neq h_0$. At level
$k^*$, both honest and adversarial computations produce the same hash:
$h_{k^*} = h'_{k^*}$. But the inputs to the hash differ: in the honest
path the level-$(k^*-1)$ child on the $i$-side is $h_{k^*-1}$, and in
the adversarial path it is $h'_{k^*-1} \neq h_{k^*-1}$ (by minimality
of $k^*$). The sibling at level $k^*-1$ may match or differ; in either
case the *full input strings* to the level-$k^*$ hash differ, since
they agree on the sibling and disagree on the $i$-side child.

Therefore the adversary has produced
$\mathsf{Hash}(\mathtt{"node"} \| L \| R) =
 \mathsf{Hash}(\mathtt{"node"} \| L' \| R')$ with
$(L, R) \neq (L', R')$, which is a collision in $H$. Reducing in the
standard way, this gives a CR adversary with success probability
$\varepsilon$, contradicting CR of $H$. $\square$

> **Why the $\mathtt{"leaf"}/\mathtt{"node"}$ separation matters.**
> Without domain separation between leaves and internal nodes, the
> adversary could substitute an internal node as a "leaf" carrying
> the same hash and produce a valid-looking inclusion proof. The
> standard attack and its countermeasure are documented in the
> Bitcoin and RFC 6962 ecosystems; we make the separation explicit
> in the construction so the reduction above is clean.

## 5.4 Theorem 4 (Cross-chain binding)

**Theorem.** Let $H$ be CR and let $\Sigma$ be EUF-CMA. Let $F_e$ be a
forest root signed by the operator at epoch $e$ over an ordering
$\sigma_e$ of chain roots $\{R^{(1)}, \ldots, R^{(n)}\}$. No PPT
adversary, given access to operator signing on chosen forest roots
other than $F_e$, can produce
$(j, R'^{(j)}, \pi'^{\mathrm{forest}}, F_e, \sigma_e, \varsigma_e)$
with:

(a) $\mathsf{Vfy}_{pk_{\mathsf{op}}}((e, F_e, \sigma_e), \varsigma_e) = 1$,
(b) the recomputed Merkle root from $R'^{(j)}$ and
    $\pi'^{\mathrm{forest}}$ equals $F_e$,
(c) $R'^{(j)} \neq R^{(j)}$, where $R^{(j)}$ is the chain-$j$ root
    actually published into the forest at epoch $e$,

except with probability negligible in $\lambda$.

**Proof.** We split the adversary's success into two cases.

*Case A: $(e, F_e, \sigma_e)$ was never signed by the honest operator.*
Then the adversary has produced a valid signature on a fresh message,
contradicting EUF-CMA of $\Sigma$. The reduction is standard: an EUF-CMA
challenger generates $pk_{\mathsf{op}}$, the reduction simulates the
adversary by forwarding signing queries to its oracle, and outputs the
forged tuple.

*Case B: $(e, F_e, \sigma_e)$ was signed by the honest operator on the
honest chain-root multiset $\{R^{(1)}, \ldots, R^{(n)}\}$.* Then $F_e$
is the genuine Merkle root over the ordered honest chain roots, and the
adversary has produced a Merkle inclusion proof for $R'^{(j)} \neq
R^{(j)}$ under $F_e$. By Theorem 3 applied to the forest Merkle tree
(which is structurally identical to a per-chain IMT), this requires a
collision in $H$, contradicting CR.

Combining both cases via the union bound, the adversary's success
probability is at most
$\mathrm{Adv}^{\mathsf{EUF\text{-}CMA}}_{\Sigma}(\lambda) +
 \mathrm{Adv}^{\mathsf{CR}}_{H}(\lambda) = \mathrm{negl}(\lambda)$.
$\square$

## 5.5 What is *not* proved

The following properties are common requests but require additional
structure beyond what Section 4 specifies:

- **Selective-disclosure unforgeability under partial revelation.** If
  a chain owner reveals openings $(m_i, r_i)$ for some indices
  $i \in S$, an adversary may use these as a leverage in
  *zero-knowledge* protocols built on top. Soundness of those
  protocols depends on the SNARK chosen (Section 6) and is not
  inherited from Theorems 1–4.
- **Forward secrecy.** If the operator's signing key is compromised
  at time $\tau$, the adversary can sign forged forest tuples for
  epochs $> \tau$. The architecture as specified does not defend
  against this; standard mitigations (key rotation, threshold
  signatures, transparency-log anchoring) apply but are out of scope.
- **Liveness and censorship-resistance.** Section 8 discusses these
  as protocol-level concerns.

# 6. Optional Zero-Knowledge Layer

The architecture above is fully functional without any SNARK. Three
optional circuits, when added, support stronger predicates over
committed data without revealing the data.

Throughout this section we assume an underlying SNARK system
$(\mathsf{Setup}_{\mathsf{ZK}}, \mathsf{Prove}, \mathsf{Verify})$ with
the standard properties of *completeness*, *knowledge soundness*, and
*zero-knowledge*. Concrete instantiations are PLONK with KZG
commitments (universal setup, ~400-byte proofs), Groth16 (circuit-
specific setup, ~200-byte proofs), or STARK-based systems (transparent,
larger proofs typically 50–200 KB). The choice trades proof size,
prover time, setup assumptions, and post-quantum resilience.

## 6.1 Commitment correctness circuit

Statement: "I know $(m, r)$ such that $\mathsf{Commit}(m; r) = C$."

```
public input:  C
private input: m, r
constraint:    C = Hash("cmt" || m || r)
```

This is the simplest circuit. Soundness inherits directly from the
SNARK's knowledge soundness: a verifier accepting the proof is
convinced (with the SNARK's negligible error) that the prover knows
$(m, r)$ opening $C$.

## 6.2 Inclusion circuit

Statement: "I know $(\mathsf{leaf}, \pi, i)$ such that the Merkle path
verifies to public root $R$ at position $i$."

```
public input:  R, i
private input: leaf, π = (s_0, ..., s_{d-1}), direction bits b_0,...,b_{d-1}
constraint:    iterative recomputation of root from leaf and π equals R
```

This circuit hides *which* leaf the prover knows; the verifier learns
only that some valid leaf exists at some position. Combined with the
commitment circuit, the prover can demonstrate "I know an opening of
some commitment in the chain with root $R$" without revealing which
commitment.

## 6.3 Optional transition predicate

For applications where state transitions must satisfy domain rules
(e.g., a quantity must be non-decreasing, an ordering relation must
hold), a third circuit can encode the predicate as an arithmetic
constraint over $(m_i, m_{i-1})$. This gives the prover the ability
to assert that the entire chain satisfies the predicate without
revealing the chain.

## 6.4 Composition

The three circuits compose by sharing public inputs. A typical
disclosure of "record at position $i$ in chain $j$ at epoch $e$
satisfies predicate $P$" combines:

1. Forest inclusion proof (non-ZK, Section 4.3) anchoring $R^{(j)}$
   to $F_e$.
2. Inclusion ZK proof (Section 6.2) that some leaf at position $i$
   exists under $R^{(j)}$.
3. Transition ZK proof (Section 6.3) that the predicate $P$ holds for
   the underlying $m_i$.

Soundness of the composed disclosure follows from Theorems 1–4 plus
knowledge soundness of the SNARK; zero-knowledge is inherited
unconditionally from the SNARK.

# 7. Evaluation

We give exact formulas, not benchmark numbers. Benchmark numbers are
implementation-specific and become misleading when divorced from
hardware, hash choice, and SNARK parameters.

## 7.1 Storage

Per record: one commitment of size $\ell$ bits and one blinding factor
of size $\lambda$ bits, total $\ell + \lambda$ bits.

For $\ell = \lambda = 256$ (SHA-256 or Poseidon2 over a 256-bit field):
**64 bytes per record**.

Per chain at any time: an IMT frontier of at most
$\lceil \log_2 t \rceil + 1$ hashes, plus one current root. For
$t = 10^6$: at most $21 \cdot 32 = 672$ bytes of state, regardless
of chain history.

Per epoch on the bulletin: one operator-signed forest tuple of size
$\ell + |\sigma_e| + |\varsigma|$ bits. With $n$ chains, $\sigma_e$
is a permutation encoded in $n \log_2 n$ bits; for moderate $n$ this
is dominated by the signature.

## 7.2 Proof sizes

Per-chain inclusion proof for a chain of $t$ leaves:
$\lceil \log_2 t \rceil$ siblings of $\ell$ bits each, plus
$\lceil \log_2 t \rceil$ direction bits. For $t = 10^6$ and
$\ell = 256$:

$$
20 \cdot 32 \text{ bytes} + 20 \text{ bits} \approx \mathbf{640 \text{ bytes}}.
$$

Forest inclusion proof for $n$ chains: $\lceil \log_2 n \rceil$
siblings, identically to Section 7.2. For $n = 1024$ chains: about
$10 \cdot 32 = 320$ bytes.

End-to-end verifier work to anchor a single record into a forest root:
one chain inclusion proof + one forest inclusion proof + one operator
signature verification. For $t = 10^6, n = 1024, \ell = 256$, total
proof bytes excluding the signature: $\approx 960$ bytes.

ZK proof sizes (Section 6) depend on the SNARK; rough current numbers:

| System | Inclusion proof size | Notes |
|--------|---------------------|-------|
| Groth16 | ~200 bytes | circuit-specific setup |
| PLONK | ~400 bytes | universal setup |
| STARK (uncompressed) | 50–200 KB | transparent, post-quantum |
| STARK + Groth16 wrapper | ~300 bytes | hybrid |

These figures track 2025–2026 reported numbers and should be
re-checked against current implementations before being cited.

## 7.3 Asymptotic summary

| Quantity | Cost |
|----------|------|
| Append a record (chain owner) | $O(\log t)$ hash evals |
| Build epoch forest root (operator) | $O(n)$ hash evals |
| Per-chain inclusion proof | $O(\log t)$ hashes |
| Forest inclusion proof | $O(\log n)$ hashes |
| Verifier work for one record | $O(\log t + \log n)$ hashes + 1 sig vfy |
| Storage per record | $O(\ell + \lambda)$ bits |
| Storage per chain (frontier) | $O(\ell \log t)$ bits |

# 8. Discussion and Limitations

**Liveness.** The operator is a single point of liveness failure for
forest publication. Practical deployments mitigate this with: a
threshold-signed operator role (an $m$-of-$n$ committee), anchoring
forest tuples to an external append-only log (a public blockchain or
a transparency log à la RFC 6962), and SLA-driven redundancy. None of
these strengthen the cryptographic guarantees of Theorems 1–4; they
strengthen the operational availability around them.

**Metadata leakage.** The architecture hides payload contents but does
not hide *that* a chain produced a record at a given epoch, nor does
it hide chain identifiers. Applications requiring metadata privacy
must compose the architecture with a mixing or anonymisation layer.

**Quantum adversaries.** All four theorems are stated for PPT
adversaries. Under a quantum adversary, EUF-CMA of classical
signatures and CR of classical hashes both degrade, but at different
rates: Grover gives a square-root speedup against CR (effectively
halving the security level in bits), while Shor breaks classical
discrete-log signatures. Migrating to a post-quantum signature
(Dilithium, FALCON) and a hash with $2\lambda$ output bits restores
classical-equivalent security.

**Small-message space attacks.** If a chain owner commits to messages
drawn from a known small set (e.g., booleans), an adversary cannot
*open* a commitment but can guess. The hiding property is unaffected
- guessing is exactly the brute-force channel hiding makes
indistinguishable from random - but applications should pad messages
to a domain-appropriate length before committing.

**Forward integrity under operator key rotation.** If the operator
rotates its signing key at epoch $e^*$, all forest tuples at epochs
$\leq e^*$ remain verifiable under the old key. Anchoring the
key-rotation event itself in a transparency log preserves forward
integrity.

# 9. Related Work

The components are individually well-studied:

- **Hash commitments** are folklore; the standard treatment under the
  random oracle model goes back to Damgård's surveys.
- **Pedersen commitments** [Pedersen 1991] give information-theoretic
  hiding and computational binding under discrete log; they are the
  alternative when hiding must hold against unbounded adversaries.
- **Merkle trees** [Merkle 1987] underpin every modern transparency
  and ledger system; RFC 6962 (Certificate Transparency) and RFC 9162
  formalise the consistency- and inclusion-proof structure for
  append-only logs.
- **Incremental Merkle trees** are the standard data structure for
  Zcash's Sapling/Orchard note commitment trees and the Ethereum
  Deposit Contract; Cassez (2021) gives a Dafny-verified correctness
  proof of the IMT algorithm used in Ethereum.
- **Poseidon and Poseidon2** [Grassi et al. 2021, Grassi et al. 2023]
  are the SNARK-friendly hashes used in modern proof systems; the
  reduction to CR carries over with the underlying assumptions of the
  Poseidon analysis.
- **PLONK** [Gabizon, Williamson, Ciobotaru 2019] provides the
  universal-setup SNARK most commonly used in our setting; STARKs
  [Ben-Sasson et al.] provide a transparent, post-quantum-friendly
  alternative.

The contribution of this paper is the *composition* of these
primitives into a forest architecture with a cohesive set of security
theorems, and an honest accounting of what is and is not proved.

# 10. Conclusion

We have specified a three-layer architecture for transparent yet
confidential versioned chains, given precise definitions of each layer,
and proved four security theorems (binding, hiding, per-chain
inclusion soundness, cross-chain binding) under standard assumptions.
We have given exact storage and proof-size formulas, corrected
arithmetic errors that appear in informal write-ups, and described an
optional zero-knowledge layer with a clean composition story.

The architecture is implementable with off-the-shelf primitives. Its
strengths are clarity of trust boundaries, modular swapping of hash
and signature primitives, and logarithmic proof sizes at both the
chain and forest levels. Its limitations - operator liveness,
metadata leakage, key-rotation handling - are explicitly listed and
amenable to standard mitigations.

# Appendix A. Worked Example

We illustrate the construction with a tiny instance: two chains, four
records each, one epoch.

Let $\mathsf{Hash} = \mathrm{SHA\text{-}256}$ truncated to $\ell = 64$
bits for display purposes (production deployments use full
$\ell = 256$).

**Chain $A$.** Records $m^A_1, m^A_2, m^A_3, m^A_4$ with blinding
factors $r^A_1, \ldots, r^A_4$. The chain owner computes:

- $C^A_i := \mathsf{Hash}(\mathtt{"cmt"} \| m^A_i \| r^A_i)$ for $i = 1..4$.
- $\mathsf{leaf}^A_i := \mathsf{Hash}(\mathtt{"leaf"} \| i \| C^A_i \|
  \mathsf{prev}^A_i)$.
- IMT pairs: $L^A_{12} := \mathsf{node}(\mathsf{leaf}^A_1,
  \mathsf{leaf}^A_2)$,
  $L^A_{34} := \mathsf{node}(\mathsf{leaf}^A_3, \mathsf{leaf}^A_4)$.
- Chain root: $R^A := \mathsf{node}(L^A_{12}, L^A_{34})$.

**Chain $B$.** Same procedure yields $R^B$.

**Forest at epoch 1.** Suppose the deterministic ordering gives
$\sigma = (A, B)$. Then $F_1 := \mathsf{node}(R^A, R^B)$, padded to a
2-chain tree (no padding needed since $n = 2$).

**Operator publication.** $(1, F_1, (A,B))$ signed by the operator.

**Verifier checks inclusion of record 3 in chain $A$.** Receives:

- Operator-signed $(1, F_1, (A,B))$ plus signature $\varsigma_1$.
- Forest path: $R^B$ (sibling), direction bit "left" (since $A$ is
  first in $\sigma$).
- Chain-$A$ inclusion: $\mathsf{leaf}^A_3$, $C^A_3$, $r^A_3, m^A_3$
  for opening, sibling $\mathsf{leaf}^A_4$ at level 0, sibling
  $L^A_{12}$ at level 1.

Verifier:

1. Checks $\varsigma_1$ against $pk_{\mathsf{op}}$.
2. Recomputes $C^A_3 = \mathsf{Hash}(\mathtt{"cmt"} \| m^A_3 \| r^A_3)$.
3. Recomputes $\mathsf{leaf}^A_3 = \mathsf{Hash}(\mathtt{"leaf"} \| 3
   \| C^A_3 \| \mathsf{prev}^A_3)$.
4. Folds path: $L'_{34} := \mathsf{node}(\mathsf{leaf}^A_3,
   \mathsf{leaf}^A_4)$; $R'^A := \mathsf{node}(L^A_{12}, L'_{34})$;
   $F'_1 := \mathsf{node}(R'^A, R^B)$.
5. Checks $F'_1 = F_1$.

All five checks succeed iff the disclosed opening is valid.

# Appendix B. Implementation checklist

1. Pick $\mathsf{Hash}$ (SHA-256 for software, Poseidon2 for SNARK
   circuits) and instantiate domain separators
   $\mathtt{"cmt"}, \mathtt{"leaf"}, \mathtt{"node"},
   \mathtt{"chain-id"}$ as distinct tagged byte strings.
2. Implement the commitment routine of Section 4.1.
3. Implement the IMT of Section 4.2 with append, root, inclusion proof,
   and verify.
4. Implement the binary Merkle root of Section 4.3 - **not** a hash
   chain.
5. Choose and integrate a signature scheme $\Sigma$ (Ed25519 for
   software; consider Dilithium for post-quantum).
6. Choose a publication channel for forest tuples (transparency log,
   blockchain anchor, signed bulletin).
7. Optional: select a SNARK system and implement the three circuits
   of Section 6 sharing the chosen $\mathsf{Hash}$ as the in-circuit
   hash.
8. Test vectors: produce known-answer tests for each algorithm before
   deployment.
9. Run negative tests: attempt to validate proofs with substituted
   leaves, reordered chains, forged operator signatures, and
   collision-attempt hashes; confirm rejection in each case.

# References

Ben-Sasson, E., Bentov, I., Horesh, Y., Riabzev, M.
"Scalable, transparent, and post-quantum secure computational
integrity." IACR ePrint 2018/046.

Cassez, F. "Verification of the Incremental Merkle Tree Algorithm with
Dafny." arXiv:2105.06009, 2021.

Gabizon, A., Williamson, Z., Ciobotaru, O. "PLONK: Permutations over
Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge."
IACR ePrint 2019/953.

Grassi, L., Khovratovich, D., Rechberger, C., Roy, A., Schofnegger, M.
"Poseidon: A New Hash Function for Zero-Knowledge Proof Systems."
USENIX Security 2021.

Grassi, L., Khovratovich, D., Schofnegger, M.
"Poseidon2: A Faster Version of the Poseidon Hash Function."
IACR ePrint 2023/323.

Groth, J. "On the Size of Pairing-Based Non-interactive Arguments."
EUROCRYPT 2016.

Laurie, B., Langley, A., Käsper, E. "Certificate Transparency."
RFC 6962, 2013.

Laurie, B., Messeri, E., Stradling, R. "Certificate Transparency
Version 2.0." RFC 9162, 2021.

Merkle, R. "A Digital Signature Based on a Conventional Encryption
Function." CRYPTO 1987.

Pedersen, T.P. "Non-Interactive and Information-Theoretic Secure
Verifiable Secret Sharing." CRYPTO 1991.
