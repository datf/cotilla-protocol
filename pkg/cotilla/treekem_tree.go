package cotilla

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"
)

var (
	// ErrTreeKEMEvictedMember indicates an evicted member attempted an unauthorized operation.
	ErrTreeKEMEvictedMember = errors.New("treekem: member is evicted from ratchet tree")
	// ErrTreeKEMInvalidCommit indicates a commit failed cryptographic verification.
	ErrTreeKEMInvalidCommit = errors.New("treekem: invalid commit signature, transcript hash, or confirmation tag")
	// ErrTreeKEMEpochMismatch indicates an unexpected epoch in commit or proposal.
	ErrTreeKEMEpochMismatch = errors.New("treekem: epoch mismatch")
	// ErrTreeKEMDecryptionFailed indicates unable to decrypt any path secret along copath resolution.
	ErrTreeKEMDecryptionFailed = errors.New("treekem: unable to decrypt path secret in direct path")
	// ErrTreeKEMLeafNotFound indicates the specified leaf does not exist.
	ErrTreeKEMLeafNotFound = errors.New("treekem: leaf index not found")
)

// TreeKEMNode represents a node in the MLS ratchet tree (RFC 9420 Section 7).
// Even node indices represent leaves (node = 2*leaf); odd indices represent internal nodes.
type TreeKEMNode struct {
	Index          int       `json:"index"`
	LeafIndex      int       `json:"leaf_index"` // >= 0 for leaves, -1 for internal nodes
	Blank          bool      `json:"blank"`
	PublicKey      [32]byte  `json:"public_key"`
	PrivateKey     *[32]byte `json:"-"` // held only if local peer knows this node's private key
	Identity       *Identity `json:"-"` // held for local or peer leaf credential
	SignPubHex     string    `json:"sign_pub_hex,omitempty"`
	JoinedEpoch    uint64    `json:"joined_epoch,omitempty"`
	UnmergedLeaves []int     `json:"unmerged_leaves,omitempty"` // RFC 9420 §7.2: leaves added under non-blank node lacking its private key
	Parent         int       `json:"parent"`
	Left           int       `json:"left"`
	Right          int       `json:"right"`
}

// ExportedNode is a serializable representation of a ratchet tree node for Welcome frames.
type ExportedNode struct {
	Index          int      `json:"index"`
	LeafIndex      int      `json:"leaf_index"`
	Blank          bool     `json:"blank"`
	PublicKey      [32]byte `json:"public_key"`
	SignPubHex     string   `json:"sign_pub_hex,omitempty"`
	JoinedEpoch    uint64   `json:"joined_epoch,omitempty"`
	UnmergedLeaves []int    `json:"unmerged_leaves,omitempty"`
	Parent         int      `json:"parent"`
	Left           int      `json:"left"`
	Right          int      `json:"right"`
}

// KeyPackage represents a client's pre-published public credentials (RFC 9420 Section 10).
type KeyPackage struct {
	Identity  *Identity `json:"-"`
	InitPriv  *[32]byte `json:"-"` // Ephemeral private key kept locally for Welcome decryption
	SignPub   string    `json:"sign_pub"` // hex Ed25519 identity
	InitKey   [32]byte  `json:"init_key"` // X25519 HPKE public key
	Timestamp int64     `json:"timestamp"`
	Signature []byte    `json:"signature"`
}

// NewKeyPackage creates a signed KeyPackage with fresh ephemeral init key for joining an MLS group.
func NewKeyPackage(id *Identity) (*KeyPackage, error) {
	var initPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, initPriv[:]); err != nil {
		return nil, err
	}
	initPriv[0] &= 248
	initPriv[31] &= 127
	initPriv[31] |= 64

	pub, err := curve25519.X25519(initPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	var initPub [32]byte
	copy(initPub[:], pub)

	pkg := &KeyPackage{
		Identity:  id,
		InitPriv:  &initPriv,
		SignPub:   id.Address(),
		InitKey:   initPub,
		Timestamp: time.Now().UnixMilli(),
	}
	canonical := canonicalKeyPackageBytes(pkg.SignPub, pkg.InitKey, pkg.Timestamp)
	pkg.Signature = ed25519.Sign(id.SignPriv, canonical)
	return pkg, nil
}

// Verify validates the self-signature on a KeyPackage.
func (kp *KeyPackage) Verify() bool {
	pubBytes, err := hex.DecodeString(kp.SignPub)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return false
	}
	canonical := canonicalKeyPackageBytes(kp.SignPub, kp.InitKey, kp.Timestamp)
	return ed25519.Verify(pubBytes, canonical, kp.Signature)
}

func canonicalKeyPackageBytes(signPub string, initKey [32]byte, ts int64) []byte {
	return EncodeCanonical("MLS 1.0 key_package", signPub, string(initKey[:]), strconv.FormatInt(ts, 10))
}

// DirectPathNode contains the public key and encrypted path secret for an ancestor node.
type DirectPathNode struct {
	NodeIndex     int              `json:"node_index"`
	PublicKey     [32]byte         `json:"public_key"`
	EncryptedKeys map[int]HPKECipher `json:"encrypted_keys"` // copath node index -> ciphertext
}

// HPKECipher represents an encrypted secret using DHKEM(X25519, HKDF-SHA256) + ChaCha20-Poly1305.
type HPKECipher struct {
	EphemeralPub [32]byte `json:"ephemeral_pub"`
	Ciphertext   []byte   `json:"ciphertext"`
}

// DirectPath represents a sequence of updated ancestor nodes from committer's leaf to root.
type DirectPath struct {
	LeafIndex     int              `json:"leaf_index"`
	LeafPublicKey [32]byte         `json:"leaf_public_key"`
	Nodes         []DirectPathNode `json:"nodes"`
}

// GroupContext binds the cryptographic context of an MLS epoch (RFC 9420 Section 8.1).
type GroupContext struct {
	GroupID                 string   `json:"group_id"`
	Epoch                   uint64   `json:"epoch"`
	TreeHash                [32]byte `json:"tree_hash"`
	ConfirmedTranscriptHash [32]byte `json:"confirmed_transcript_hash"`
}

// MaxTreeLeaves caps decoded RatchetTree leaf count to prevent DoS allocations on malformed commits.
const MaxTreeLeaves = 8192

// MLSCommit represents a group state transition commit (RFC 9420 Section 12).
type MLSCommit struct {
	GroupID         string         `json:"group_id,omitempty"`
	CommitterLeaf   int            `json:"committer_leaf"`
	Epoch           uint64         `json:"epoch"`
	RemovedLeaf     int            `json:"removed_leaf"` // -1 if no removal
	AddedPackage    *KeyPackage    `json:"added_package,omitempty"`
	Path            *DirectPath    `json:"path"`
	TreeNodes       []ExportedNode `json:"tree_nodes,omitempty"`
	ConfirmationTag [32]byte       `json:"confirmation_tag"`
	Signature       []byte         `json:"signature"`
}

// MLSWelcome transports the initial group state and encrypted epoch secret to newcomers.
type MLSWelcome struct {
	GroupID                 string         `json:"group_id"`
	Epoch                   uint64         `json:"epoch"`
	SignerLeaf              int            `json:"signer_leaf"`
	TreeNodes               []ExportedNode `json:"tree_nodes"`
	EncryptedGroupSecret    HPKECipher     `json:"encrypted_group_secret"`
	TreeHash                [32]byte       `json:"tree_hash"`
	ConfirmedTranscriptHash [32]byte       `json:"confirmed_transcript_hash"`
	ConfirmationTag         [32]byte       `json:"confirmation_tag"`
	Signature               []byte         `json:"signature,omitempty"`
}

func (w *MLSWelcome) CanonicalBytes() []byte {
	return EncodeCanonical(
		"MLS 1.0 Welcome",
		w.GroupID,
		strconv.FormatUint(w.Epoch, 10),
		strconv.Itoa(w.SignerLeaf),
		hex.EncodeToString(w.EncryptedGroupSecret.EphemeralPub[:]),
		hex.EncodeToString(w.EncryptedGroupSecret.Ciphertext),
		hex.EncodeToString(w.TreeHash[:]),
		hex.EncodeToString(w.ConfirmedTranscriptHash[:]),
		hex.EncodeToString(w.ConfirmationTag[:]),
	)
}

// RatchetTree represents an MLS Left-Balanced Binary Tree (RFC 9420 Section 7).
type RatchetTree struct {
	NumLeaves int
	Nodes     []*TreeKEMNode
}

// NewRatchetTree constructs a left-balanced binary tree with numLeaves leaves.
func NewRatchetTree(numLeaves int) *RatchetTree {
	if numLeaves < 1 {
		numLeaves = 1
	}
	totalNodes := 2*numLeaves - 1
	nodes := make([]*TreeKEMNode, totalNodes)
	for i := range nodes {
		leafIdx := -1
		if i%2 == 0 {
			leafIdx = i / 2
		}
		nodes[i] = &TreeKEMNode{
			Index:     i,
			LeafIndex: leafIdx,
			Blank:     true,
			Parent:    -1,
			Left:      -1,
			Right:     -1,
		}
	}
	t := &RatchetTree{
		NumLeaves: numLeaves,
		Nodes:     nodes,
	}
	if numLeaves > 1 {
		t.wireSubtree(0, numLeaves)
	}
	return t
}

func (t *RatchetTree) wireSubtree(leafStart, count int) int {
	if count == 1 {
		return 2 * leafStart
	}
	k := largestPowerOfTwoLessThan(count)
	leftRoot := t.wireSubtree(leafStart, k)
	rightRoot := t.wireSubtree(leafStart+k, count-k)

	// In LBBT with leafStart and count, the root node index is leftRoot + (k * 2) - 1 ...
	// More precisely: internal node between left subtree and right subtree:
	rootIdx := 2*(leafStart+k) - 1
	t.Nodes[rootIdx].Left = leftRoot
	t.Nodes[rootIdx].Right = rightRoot
	t.Nodes[leftRoot].Parent = rootIdx
	t.Nodes[rightRoot].Parent = rootIdx
	return rootIdx
}

func largestPowerOfTwoLessThan(x int) int {
	k := 1
	for (k << 1) < x {
		k <<= 1
	}
	return k
}

// RootIndex returns the root node index of the tree.
func (t *RatchetTree) RootIndex() int {
	if t.NumLeaves == 1 {
		return 0
	}
	k := largestPowerOfTwoLessThan(t.NumLeaves)
	return 2*k - 1
}

// DirectPathIndices returns the sequence of ancestor node indices from leaf to root.
func (t *RatchetTree) DirectPathIndices(leafIdx int) []int {
	nodeIdx := 2 * leafIdx
	if nodeIdx < 0 || nodeIdx >= len(t.Nodes) {
		return nil
	}
	var path []int
	curr := t.Nodes[nodeIdx].Parent
	for curr != -1 && curr < len(t.Nodes) {
		path = append(path, curr)
		curr = t.Nodes[curr].Parent
	}
	return path
}

// CopathIndex returns the sibling of the child along the direct path.
func (t *RatchetTree) CopathIndex(ancestorIdx, directChildIdx int) int {
	anc := t.Nodes[ancestorIdx]
	if anc.Left == directChildIdx {
		return anc.Right
	}
	return anc.Left
}

// Clone returns an isolated deep copy of RatchetTree so failed commits never mutate live state.
func (t *RatchetTree) Clone() *RatchetTree {
	out := &RatchetTree{
		NumLeaves: t.NumLeaves,
		Nodes:     make([]*TreeKEMNode, len(t.Nodes)),
	}
	for i, n := range t.Nodes {
		if n == nil {
			continue
		}
		cp := *n
		if n.PrivateKey != nil {
			privCopy := *n.PrivateKey
			cp.PrivateKey = &privCopy
		}
		if len(n.UnmergedLeaves) > 0 {
			cp.UnmergedLeaves = append([]int(nil), n.UnmergedLeaves...)
		}
		out.Nodes[i] = &cp
	}
	return out
}

// Resolution returns the non-blank node indices that cover the subtree at nodeIdx,
// including any UnmergedLeaves on non-blank internal nodes (RFC 9420 Section 7.2).
func (t *RatchetTree) Resolution(nodeIdx int) []int {
	if nodeIdx < 0 || nodeIdx >= len(t.Nodes) {
		return nil
	}
	n := t.Nodes[nodeIdx]
	if !n.Blank {
		res := []int{nodeIdx}
		seen := map[int]bool{nodeIdx: true}
		for _, leafIdx := range n.UnmergedLeaves {
			uNodeIdx := 2 * leafIdx
			if uNodeIdx >= 0 && uNodeIdx < len(t.Nodes) && !t.Nodes[uNodeIdx].Blank && !seen[uNodeIdx] {
				res = append(res, uNodeIdx)
				seen[uNodeIdx] = true
			}
		}
		return res
	}
	// Blank internal node: resolve children recursively
	if n.Left == -1 && n.Right == -1 {
		return nil // blank leaf
	}
	var res []int
	if n.Left != -1 {
		res = append(res, t.Resolution(n.Left)...)
	}
	if n.Right != -1 {
		res = append(res, t.Resolution(n.Right)...)
	}
	return res
}

// addUnmergedLeaf records leafIdx as unmerged in every non-blank ancestor on its direct path.
func (t *RatchetTree) addUnmergedLeaf(leafIdx int) {
	for _, ancIdx := range t.DirectPathIndices(leafIdx) {
		anc := t.Nodes[ancIdx]
		if anc.Blank {
			continue
		}
		already := false
		for _, u := range anc.UnmergedLeaves {
			if u == leafIdx {
				already = true
				break
			}
		}
		if !already {
			anc.UnmergedLeaves = append(anc.UnmergedLeaves, leafIdx)
		}
	}
}

// clearLeafFromUnmerged removes leafIdx from all ancestors' UnmergedLeaves slices.
func (t *RatchetTree) clearLeafFromUnmerged(leafIdx int) {
	for _, ancIdx := range t.DirectPathIndices(leafIdx) {
		anc := t.Nodes[ancIdx]
		if len(anc.UnmergedLeaves) == 0 {
			continue
		}
		filtered := anc.UnmergedLeaves[:0]
		for _, u := range anc.UnmergedLeaves {
			if u != leafIdx {
				filtered = append(filtered, u)
			}
		}
		if len(filtered) == 0 {
			anc.UnmergedLeaves = nil
		} else {
			anc.UnmergedLeaves = filtered
		}
	}
}

// TreeHash computes the deterministic Merkle tree hash of the ratchet tree (RFC 9420 Section 7.7).
func (t *RatchetTree) TreeHash() [32]byte {
	return t.hashSubtree(t.RootIndex())
}

func (t *RatchetTree) hashSubtree(nodeIdx int) [32]byte {
	if nodeIdx < 0 || nodeIdx >= len(t.Nodes) {
		return [32]byte{}
	}
	n := t.Nodes[nodeIdx]
	h := sha256.New()
	if n.LeafIndex != -1 {
		// Leaf node hash
		h.Write([]byte("MLS 1.0 leaf"))
		_ = binary.Write(h, binary.BigEndian, uint32(n.Index))
		if n.Blank {
			h.Write([]byte{0})
		} else {
			h.Write([]byte{1})
			h.Write(n.PublicKey[:])
			h.Write([]byte(n.SignPubHex))
		}
	} else {
		// Internal node hash
		h.Write([]byte("MLS 1.0 node"))
		_ = binary.Write(h, binary.BigEndian, uint32(n.Index))
		if n.Blank {
			h.Write([]byte{0})
		} else {
			h.Write([]byte{1})
			h.Write(n.PublicKey[:])
			_ = binary.Write(h, binary.BigEndian, uint32(len(n.UnmergedLeaves)))
			for _, u := range n.UnmergedLeaves {
				_ = binary.Write(h, binary.BigEndian, uint32(u))
			}
		}
		leftHash := t.hashSubtree(n.Left)
		rightHash := t.hashSubtree(n.Right)
		h.Write(leftHash[:])
		h.Write(rightHash[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MLSGroup represents an active MLS group state machine (RFC 9420).
func (t *RatchetTree) resize(newLeaves int) {
	if newLeaves <= t.NumLeaves {
		return
	}
	newTree := NewRatchetTree(newLeaves)
	for i, oldNode := range t.Nodes {
		if i < len(newTree.Nodes) {
			newTree.Nodes[i].Blank = oldNode.Blank
			newTree.Nodes[i].PublicKey = oldNode.PublicKey
			newTree.Nodes[i].PrivateKey = oldNode.PrivateKey
			newTree.Nodes[i].Identity = oldNode.Identity
			newTree.Nodes[i].SignPubHex = oldNode.SignPubHex
			newTree.Nodes[i].JoinedEpoch = oldNode.JoinedEpoch
			if len(oldNode.UnmergedLeaves) > 0 {
				newTree.Nodes[i].UnmergedLeaves = append([]int(nil), oldNode.UnmergedLeaves...)
			}
		}
	}
	t.NumLeaves = newTree.NumLeaves
	t.Nodes = newTree.Nodes
}

// CreateAddCommit proposes and commits adding a new member from their KeyPackage.
// Returns the commit message for the room and a Welcome message for the newcomer.
func (g *MLSGroup) exportTreeNodes() []ExportedNode {
	out := make([]ExportedNode, len(g.Tree.Nodes))
	for i, n := range g.Tree.Nodes {
		var unmerged []int
		if len(n.UnmergedLeaves) > 0 {
			unmerged = append([]int(nil), n.UnmergedLeaves...)
		}
		out[i] = ExportedNode{
			Index:          n.Index,
			LeafIndex:      n.LeafIndex,
			Blank:          n.Blank,
			PublicKey:      n.PublicKey,
			SignPubHex:     n.SignPubHex,
			JoinedEpoch:    n.JoinedEpoch,
			UnmergedLeaves: unmerged,
			Parent:         n.Parent,
			Left:           n.Left,
			Right:          n.Right,
		}
	}
	return out
}

// CanonicalBytes returns the canonical encoding of a commit before the confirmation tag.
func (g *MLSGroup) dumpTree() string {
	res := ""
	for _, n := range g.Tree.Nodes {
		res += fmt.Sprintf("[%d: leaf=%d blank=%v pub=%x sign=%s] ", n.Index, n.LeafIndex, n.Blank, n.PublicKey[:4], n.SignPubHex)
	}
	return res
}
