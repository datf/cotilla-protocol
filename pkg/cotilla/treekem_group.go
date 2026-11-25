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
	"sync"

	"golang.org/x/crypto/hkdf"
)

type MLSGroup struct {
	mu                      sync.RWMutex
	GroupID                 string
	Epoch                   uint64
	MyLeafIndex             int
	LocalIdentity           *Identity
	Tree                    *RatchetTree
	InitSecret              [32]byte
	EpochSecret             [32]byte
	ApplicationSecret       [32]byte
	ConfirmationKey         [32]byte
	ExporterSecret          [32]byte
	ConfirmedTranscriptHash [32]byte
}

// NewMLSGroup creates a new MLS group with the local peer as the group creator at leaf 0.
func NewMLSGroup(groupID string, id *Identity) (*MLSGroup, error) {
	tree := NewRatchetTree(1)

	// Setup creator leaf 0
	leafNode := tree.Nodes[0]
	leafNode.Blank = false
	leafNode.PublicKey = id.EncPub
	leafNode.PrivateKey = new([32]byte)
	*leafNode.PrivateKey = id.EncPriv
	leafNode.Identity = id
	leafNode.SignPubHex = id.Address()
	leafNode.JoinedEpoch = 1

	var initSecret [32]byte
	if _, err := io.ReadFull(rand.Reader, initSecret[:]); err != nil {
		return nil, err
	}

	g := &MLSGroup{
		GroupID:       groupID,
		Epoch:         1,
		MyLeafIndex:   0,
		LocalIdentity: id,
		Tree:          tree,
		InitSecret:    initSecret,
	}

	// Bootstrap Genesis Epoch 1 secrets
	var commitSecret [32]byte
	if _, err := io.ReadFull(rand.Reader, commitSecret[:]); err != nil {
		return nil, err
	}
	g.deriveEpochSecrets(commitSecret)

	return g, nil
}

// deriveEpochSecrets derives the key schedule for the current epoch (RFC 9420 Section 8).
func (g *MLSGroup) deriveEpochSecrets(commitSecret [32]byte) {
	// epoch_secret = HKDF-Extract(commit_secret, init_secret)
	extractor := hkdf.Extract(sha256.New, commitSecret[:], g.InitSecret[:])
	var nextEpochSecret [32]byte
	copy(nextEpochSecret[:], extractor)
	defer zeroizeBytes(nextEpochSecret[:])
	g.deriveEpochSecretsFromEpochSecret(nextEpochSecret)
}

// deriveEpochSecretsFromEpochSecret sets up secrets when EpochSecret is already known (e.g. Welcome).
func (g *MLSGroup) deriveEpochSecretsFromEpochSecret(epochSecret [32]byte) {
	zeroizeBytes(g.EpochSecret[:])
	zeroizeBytes(g.InitSecret[:])
	zeroizeBytes(g.ApplicationSecret[:])
	zeroizeBytes(g.ConfirmationKey[:])
	zeroizeBytes(g.ExporterSecret[:])

	g.EpochSecret = epochSecret

	gc := g.GroupContext()
	gcBytes := gc.Bytes()

	initReader := hkdf.Expand(sha256.New, g.EpochSecret[:], append([]byte("MLS 1.0 init"), gcBytes...))
	_, _ = io.ReadFull(initReader, g.InitSecret[:])

	appReader := hkdf.Expand(sha256.New, g.EpochSecret[:], append([]byte("MLS 1.0 app"), gcBytes...))
	_, _ = io.ReadFull(appReader, g.ApplicationSecret[:])

	confirmReader := hkdf.Expand(sha256.New, g.EpochSecret[:], append([]byte("MLS 1.0 confirm"), gcBytes...))
	_, _ = io.ReadFull(confirmReader, g.ConfirmationKey[:])

	exporterReader := hkdf.Expand(sha256.New, g.EpochSecret[:], append([]byte("MLS 1.0 exporter"), gcBytes...))
	_, _ = io.ReadFull(exporterReader, g.ExporterSecret[:])
}

// GroupContext returns the current cryptographic group context.
func (g *MLSGroup) GroupContext() GroupContext {
	return GroupContext{
		GroupID:                 g.GroupID,
		Epoch:                   g.Epoch,
		TreeHash:                g.Tree.TreeHash(),
		ConfirmedTranscriptHash: g.ConfirmedTranscriptHash,
	}
}

// Bytes serializes GroupContext canonically.
func (gc GroupContext) Bytes() []byte {
	return EncodeCanonical("MLS 1.0 GroupContext", gc.GroupID, strconv.FormatUint(gc.Epoch, 10), hex.EncodeToString(gc.TreeHash[:]), hex.EncodeToString(gc.ConfirmedTranscriptHash[:]))
}

func (g *MLSGroup) CreateAddCommit(pkg *KeyPackage) (*MLSCommit, *MLSWelcome, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if pkg == nil {
		return nil, nil, errors.New("treekem: nil key package")
	}
	if g.MyLeafIndex < 0 || g.MyLeafIndex >= g.Tree.NumLeaves || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return nil, nil, ErrTreeKEMEvictedMember
	}

	if !pkg.Verify() {
		return nil, nil, errors.New("treekem: invalid key package signature")
	}

	// If this identity already occupies a leaf (e.g. F5 browser refresh with a new KeyPackage),
	// blank the old leaf and its direct path first so it gets cleanly replaced without duplicate leaves.
	removedLeaf := -1
	for i := 0; i < g.Tree.NumLeaves; i++ {
		if !g.Tree.Nodes[2*i].Blank && g.Tree.Nodes[2*i].SignPubHex == pkg.SignPub {
			if i == g.MyLeafIndex {
				return nil, nil, errors.New("treekem: cannot re-add self via add commit")
			}
			removedLeaf = i
			break
		}
	}
	if removedLeaf != -1 {
		oldNode := g.Tree.Nodes[2*removedLeaf]
		if oldNode.PrivateKey != nil {
			zeroizeBytes(oldNode.PrivateKey[:])
		}
		oldNode.Blank = true
		oldNode.PublicKey = [32]byte{}
		oldNode.PrivateKey = nil
		oldNode.SignPubHex = ""
		oldNode.JoinedEpoch = 0
		g.Tree.clearLeafFromUnmerged(removedLeaf)
		curr := oldNode.Parent
		for curr != -1 && curr < len(g.Tree.Nodes) {
			if g.Tree.Nodes[curr].PrivateKey != nil {
				zeroizeBytes(g.Tree.Nodes[curr].PrivateKey[:])
			}
			g.Tree.Nodes[curr].Blank = true
			g.Tree.Nodes[curr].PublicKey = [32]byte{}
			g.Tree.Nodes[curr].PrivateKey = nil
			g.Tree.Nodes[curr].UnmergedLeaves = nil
			curr = g.Tree.Nodes[curr].Parent
		}
	}

	// 1. Find first blank leaf or expand tree
	newLeafIdx := -1
	for i := 0; i < g.Tree.NumLeaves; i++ {
		if g.Tree.Nodes[2*i].Blank {
			newLeafIdx = i
			break
		}
	}
	if newLeafIdx == -1 {
		g.Tree.resize(g.Tree.NumLeaves + 1)
		newLeafIdx = g.Tree.NumLeaves - 1
	}

	// Assign newcomer to leaf and record them as unmerged on existing non-blank ancestors
	newLeafNode := g.Tree.Nodes[2*newLeafIdx]
	newLeafNode.Blank = false
	newLeafNode.PublicKey = pkg.InitKey
	newLeafNode.PrivateKey = nil
	newLeafNode.SignPubHex = pkg.SignPub
	newLeafNode.JoinedEpoch = g.Epoch + 1
	g.Tree.addUnmergedLeaf(newLeafIdx)

	// 2. Committer ratchets their direct path
	path, commitSecret, err := g.buildDirectPath()
	if err != nil {
		return nil, nil, err
	}
	// Newcomer will initialize via Welcome (without ancestor path_secrets), so keep newcomer unmerged on its direct path
	g.Tree.addUnmergedLeaf(newLeafIdx)

	// 3. Form Commit
	commit := &MLSCommit{
		GroupID:       g.GroupID,
		CommitterLeaf: g.MyLeafIndex,
		Epoch:         g.Epoch + 1,
		RemovedLeaf:   removedLeaf,
		AddedPackage:  pkg,
		Path:          path,
		TreeNodes:     g.exportTreeNodes(),
	}

	newTranscript := sha256.Sum256(append(g.ConfirmedTranscriptHash[:], commit.CanonicalBytes()...))

	// Derive new epoch secret
	extractor := hkdf.Extract(sha256.New, commitSecret[:], g.InitSecret[:])
	var newEpochSecret [32]byte
	copy(newEpochSecret[:], extractor)

	tempGC := GroupContext{
		GroupID:                 g.GroupID,
		Epoch:                   commit.Epoch,
		TreeHash:                g.Tree.TreeHash(),
		ConfirmedTranscriptHash: newTranscript,
	}
	gcBytes := tempGC.Bytes()

	var newConfirmKey [32]byte
	confirmReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 confirm"), gcBytes...))
	_, _ = io.ReadFull(confirmReader, newConfirmKey[:])

	commit.ConfirmationTag = hmacSHA256(newConfirmKey[:], newTranscript[:])
	commit.Signature = ed25519.Sign(g.LocalIdentity.SignPriv, commit.CanonicalBytesWithConfirmation())

	var newInitSecret [32]byte
	initReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 init"), gcBytes...))
	_, _ = io.ReadFull(initReader, newInitSecret[:])

	var newAppSecret [32]byte
	appReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 app"), gcBytes...))
	_, _ = io.ReadFull(appReader, newAppSecret[:])

	// 4. Create signed Welcome message bound to GroupID and Epoch
	groupSecrets := make([]byte, 0, 96)
	groupSecrets = append(groupSecrets, newEpochSecret[:]...)
	groupSecrets = append(groupSecrets, newInitSecret[:]...)
	groupSecrets = append(groupSecrets, newAppSecret[:]...)
	welcomeInfo := welcomeHPKEInfo(g.GroupID, commit.Epoch)
	welcomeCipher, err := hpkeEncrypt(pkg.InitKey, groupSecrets, welcomeInfo)
	zeroizeBytes(groupSecrets)
	zeroizeBytes(commitSecret[:])
	zeroizeBytes(newConfirmKey[:])
	if err != nil {
		return nil, nil, err
	}
	welcome := &MLSWelcome{
		GroupID:                 g.GroupID,
		Epoch:                   commit.Epoch,
		SignerLeaf:              g.MyLeafIndex,
		TreeNodes:               g.exportTreeNodes(),
		EncryptedGroupSecret:    welcomeCipher,
		TreeHash:                g.Tree.TreeHash(),
		ConfirmedTranscriptHash: newTranscript,
		ConfirmationTag:         commit.ConfirmationTag,
	}
	welcome.Signature = ed25519.Sign(g.LocalIdentity.SignPriv, welcome.CanonicalBytes())

	// Apply commit locally
	g.Epoch = commit.Epoch
	g.ConfirmedTranscriptHash = newTranscript
	g.deriveEpochSecretsFromEpochSecret(newEpochSecret)

	return commit, welcome, nil
}

// CreateRemoveCommit proposes and commits removing (evicting) a member from targetLeaf.
func (g *MLSGroup) CreateRemoveCommit(targetLeaf int) (*MLSCommit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.MyLeafIndex < 0 || g.MyLeafIndex >= g.Tree.NumLeaves || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return nil, ErrTreeKEMEvictedMember
	}

	if targetLeaf < 0 || targetLeaf >= g.Tree.NumLeaves {
		return nil, ErrTreeKEMLeafNotFound
	}
	if targetLeaf == g.MyLeafIndex {
		return nil, errors.New("treekem: cannot evict self")
	}

	targetNode := g.Tree.Nodes[2*targetLeaf]
	if targetNode.Blank {
		return nil, errors.New("treekem: member already blank/evicted")
	}

	// 1. Blank the evicted leaf and clear ancestor keys + unmerged tracking
	if targetNode.PrivateKey != nil {
		zeroizeBytes(targetNode.PrivateKey[:])
	}
	targetNode.Blank = true
	targetNode.PublicKey = [32]byte{}
	targetNode.PrivateKey = nil
	targetNode.SignPubHex = ""
	targetNode.JoinedEpoch = 0
	g.Tree.clearLeafFromUnmerged(targetLeaf)

	curr := targetNode.Parent
	for curr != -1 && curr < len(g.Tree.Nodes) {
		if g.Tree.Nodes[curr].PrivateKey != nil {
			zeroizeBytes(g.Tree.Nodes[curr].PrivateKey[:])
		}
		g.Tree.Nodes[curr].Blank = true
		g.Tree.Nodes[curr].PublicKey = [32]byte{}
		g.Tree.Nodes[curr].PrivateKey = nil
		g.Tree.Nodes[curr].UnmergedLeaves = nil
		curr = g.Tree.Nodes[curr].Parent
	}

	// 2. Committer builds direct path to fresh root secret
	path, commitSecret, err := g.buildDirectPath()
	if err != nil {
		return nil, err
	}

	commit := &MLSCommit{
		GroupID:       g.GroupID,
		CommitterLeaf: g.MyLeafIndex,
		Epoch:         g.Epoch + 1,
		RemovedLeaf:   targetLeaf,
		AddedPackage:  nil,
		Path:          path,
		TreeNodes:     g.exportTreeNodes(),
	}

	newTranscript := sha256.Sum256(append(g.ConfirmedTranscriptHash[:], commit.CanonicalBytes()...))

	extractor := hkdf.Extract(sha256.New, commitSecret[:], g.InitSecret[:])
	var newEpochSecret [32]byte
	copy(newEpochSecret[:], extractor)

	tempGC := GroupContext{
		GroupID:                 g.GroupID,
		Epoch:                   commit.Epoch,
		TreeHash:                g.Tree.TreeHash(),
		ConfirmedTranscriptHash: newTranscript,
	}
	gcBytes := tempGC.Bytes()

	var newConfirmKey [32]byte
	confirmReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 confirm"), gcBytes...))
	_, _ = io.ReadFull(confirmReader, newConfirmKey[:])

	commit.ConfirmationTag = hmacSHA256(newConfirmKey[:], newTranscript[:])
	commit.Signature = ed25519.Sign(g.LocalIdentity.SignPriv, commit.CanonicalBytesWithConfirmation())

	// Apply commit locally
	g.Epoch = commit.Epoch
	g.ConfirmedTranscriptHash = newTranscript
	g.deriveEpochSecretsFromEpochSecret(newEpochSecret)

	return commit, nil
}

// CreateUpdateCommit performs continuous asymmetric key ratcheting (PCS) for the committer.
func (g *MLSGroup) CreateUpdateCommit() (*MLSCommit, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.MyLeafIndex < 0 || g.MyLeafIndex >= g.Tree.NumLeaves || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return nil, ErrTreeKEMEvictedMember
	}

	path, commitSecret, err := g.buildDirectPath()
	if err != nil {
		return nil, err
	}

	commit := &MLSCommit{
		GroupID:       g.GroupID,
		CommitterLeaf: g.MyLeafIndex,
		Epoch:         g.Epoch + 1,
		RemovedLeaf:   -1,
		AddedPackage:  nil,
		Path:          path,
		TreeNodes:     g.exportTreeNodes(),
	}

	newTranscript := sha256.Sum256(append(g.ConfirmedTranscriptHash[:], commit.CanonicalBytes()...))

	extractor := hkdf.Extract(sha256.New, commitSecret[:], g.InitSecret[:])
	var newEpochSecret [32]byte
	copy(newEpochSecret[:], extractor)

	tempGC := GroupContext{
		GroupID:                 g.GroupID,
		Epoch:                   commit.Epoch,
		TreeHash:                g.Tree.TreeHash(),
		ConfirmedTranscriptHash: newTranscript,
	}
	gcBytes := tempGC.Bytes()

	var newConfirmKey [32]byte
	confirmReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 confirm"), gcBytes...))
	_, _ = io.ReadFull(confirmReader, newConfirmKey[:])

	commit.ConfirmationTag = hmacSHA256(newConfirmKey[:], newTranscript[:])
	commit.Signature = ed25519.Sign(g.LocalIdentity.SignPriv, commit.CanonicalBytesWithConfirmation())

	g.Epoch = commit.Epoch
	g.ConfirmedTranscriptHash = newTranscript
	g.deriveEpochSecretsFromEpochSecret(newEpochSecret)

	return commit, nil
}

// buildDirectPath generates fresh path secrets along the committer's direct path to root.
func (g *MLSGroup) buildDirectPath() (*DirectPath, [32]byte, error) {
	if g.MyLeafIndex < 0 || g.MyLeafIndex >= g.Tree.NumLeaves || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return nil, [32]byte{}, ErrTreeKEMEvictedMember
	}

	var leafSecret [32]byte
	if _, err := io.ReadFull(rand.Reader, leafSecret[:]); err != nil {
		return nil, [32]byte{}, err
	}

	// Derive committer's new leaf keypair
	committerNode := g.Tree.Nodes[2*g.MyLeafIndex]
	leafPub, leafPriv := deriveKeyPair(leafSecret)
	committerNode.Blank = false
	committerNode.PublicKey = leafPub
	committerNode.PrivateKey = &leafPriv

	directPathIndices := g.Tree.DirectPathIndices(g.MyLeafIndex)
	pathNodes := make([]DirectPathNode, len(directPathIndices))

	currentPathSecret := derivePathSecret(leafSecret)
	childIdx := 2 * g.MyLeafIndex

	for i, ancIdx := range directPathIndices {
		nodeSecret := deriveNodeSecret(currentPathSecret)
		ancPub, ancPriv := deriveKeyPair(nodeSecret)

		ancNode := g.Tree.Nodes[ancIdx]
		ancNode.Blank = false
		ancNode.PublicKey = ancPub
		ancNode.PrivateKey = &ancPriv
		// Every non-blank peer in the opposite subtree receives the path secret via copath resolution below,
		// so prior unmerged leaves from that subtree can now be cleared cleanly.
		ancNode.UnmergedLeaves = nil

		// Copath is sibling of childIdx under ancIdx
		copathIdx := g.Tree.CopathIndex(ancIdx, childIdx)
		resolution := g.Tree.Resolution(copathIdx)

		encryptedKeys := make(map[int]HPKECipher)
		for _, resNodeIdx := range resolution {
			resPub := g.Tree.Nodes[resNodeIdx].PublicKey
			cipher, err := hpkeEncrypt(resPub, currentPathSecret[:], []byte("MLS 1.0 direct_path"))
			if err != nil {
				return nil, [32]byte{}, err
			}
			encryptedKeys[resNodeIdx] = cipher
		}

		pathNodes[i] = DirectPathNode{
			NodeIndex:     ancIdx,
			PublicKey:     ancPub,
			EncryptedKeys: encryptedKeys,
		}

		childIdx = ancIdx
		currentPathSecret = derivePathSecret(currentPathSecret)
	}

	commitSecret := deriveCommitSecret(currentPathSecret)
	return &DirectPath{
		LeafIndex:     g.MyLeafIndex,
		LeafPublicKey: leafPub,
		Nodes:         pathNodes,
	}, commitSecret, nil
}

func (g *MLSGroup) ApplicationSecretBytes() [32]byte {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.ApplicationSecret
}

// LeafSnapshot describes a non-blank member leaf in the MLS ratchet tree for key export.
type LeafSnapshot struct {
	LeafIndex int
	Address   string
}

// Export implements RFC 9420 Section 8.5 MLS-Exporter bound to the current epoch's ExporterSecret.
func (g *MLSGroup) Export(label string, context []byte, length int) ([]byte, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.exportLocked(label, context, length)
}

func (g *MLSGroup) exportLocked(label string, context []byte, length int) ([]byte, error) {
	if g.Epoch == 0 || g.MyLeafIndex < 0 || g.Tree == nil || 2*g.MyLeafIndex >= len(g.Tree.Nodes) || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return nil, ErrTreeKEMEvictedMember
	}
	if length <= 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("treekem: invalid export length %d", length)
	}
	derived := mlsExpandWithLabel(g.ExporterSecret[:], label, nil, sha256.Size)
	defer zeroizeBytes(derived)
	ctxHash := sha256.Sum256(context)
	return mlsExpandWithLabel(derived, "exported", ctxHash[:], length), nil
}

// SnapshotForSFrame atomically captures the epoch, local leaf index, active tree leaves,
// and an exported base secret under a single read lock.
func (g *MLSGroup) SnapshotForSFrame(label string, context []byte) (epoch uint64, myLeaf int, leaves []LeafSnapshot, exported []byte, err error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	exported, err = g.exportLocked(label, context, 32)
	if err != nil {
		return 0, -1, nil, nil, err
	}
	epoch = g.Epoch
	myLeaf = g.MyLeafIndex
	leaves = make([]LeafSnapshot, 0, g.Tree.NumLeaves)
	for i := 0; i < g.Tree.NumLeaves; i++ {
		n := g.Tree.Nodes[2*i]
		if n != nil && !n.Blank && n.SignPubHex != "" {
			leaves = append(leaves, LeafSnapshot{
				LeafIndex: i,
				Address:   n.SignPubHex,
			})
		}
	}
	return epoch, myLeaf, leaves, exported, nil
}

func mlsExpandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	fullLabel := append([]byte("MLS 1.0 "), label...)
	kdfLabel := make([]byte, 0, 2+2+len(fullLabel)+2+len(context))
	kdfLabel = binary.BigEndian.AppendUint16(kdfLabel, uint16(length))
	kdfLabel = appendMLSOpaque(kdfLabel, fullLabel)
	kdfLabel = appendMLSOpaque(kdfLabel, context)

	out := make([]byte, length)
	r := hkdf.Expand(sha256.New, secret, kdfLabel)
	_, _ = io.ReadFull(r, out)
	return out
}

func appendMLSOpaque(dst, data []byte) []byte {
	n := len(data)
	switch {
	case n < 1<<6:
		dst = append(dst, byte(n))
	case n < 1<<14:
		dst = append(dst, byte(0x40|(n>>8)), byte(n))
	default:
		dst = append(dst, byte(0x80|(n>>24)), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(dst, data...)
}

// FindLeafByAddress returns the leaf index of the member with the given Ed25519 public address, or -1.
func (g *MLSGroup) FindLeafByAddress(signPubHex string) int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	for i := 0; i < g.Tree.NumLeaves; i++ {
		node := g.Tree.Nodes[2*i]
		if !node.Blank && node.SignPubHex == signPubHex {
			return i
		}
	}
	return -1
}

// EnsureMemberLeaf ensures that a member with the given address and init key is present in a leaf.
// Returns the assigned leaf index.
func (g *MLSGroup) EnsureMemberLeaf(signPubHex string, initKey [32]byte) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	for i := 0; i < g.Tree.NumLeaves; i++ {
		node := g.Tree.Nodes[2*i]
		if node.SignPubHex == signPubHex && !node.Blank {
			return i
		}
	}

	joinedEp := g.Epoch
	if joinedEp == 0 {
		joinedEp = 1
	}

	// Look for first blank leaf
	for i := 0; i < g.Tree.NumLeaves; i++ {
		node := g.Tree.Nodes[2*i]
		if node.Blank {
			node.Blank = false
			node.PublicKey = initKey
			node.SignPubHex = signPubHex
			node.JoinedEpoch = joinedEp
			g.Tree.addUnmergedLeaf(i)
			return i
		}
	}

	// Expand tree
	g.Tree.resize(g.Tree.NumLeaves + 1)
	newLeafIdx := g.Tree.NumLeaves - 1
	newLeafNode := g.Tree.Nodes[2*newLeafIdx]
	newLeafNode.Blank = false
	newLeafNode.PublicKey = initKey
	newLeafNode.SignPubHex = signPubHex
	newLeafNode.JoinedEpoch = joinedEp
	g.Tree.addUnmergedLeaf(newLeafIdx)
	return newLeafIdx
}

// exportTreeNodes creates serializable snapshot of the tree for Welcome messages.
