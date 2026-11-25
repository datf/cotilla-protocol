package cotilla

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func welcomeHPKEInfo(groupID string, epoch uint64) []byte {
	return EncodeCanonical("MLS 1.0 welcome", groupID, strconv.FormatUint(epoch, 10))
}

// ProcessCommit verifies and applies an inbound commit atomically against a cloned ratchet tree.
func (g *MLSGroup) ProcessCommit(commit *MLSCommit) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if commit == nil || commit.Path == nil {
		return ErrTreeKEMInvalidCommit
	}
	if commit.GroupID != "" && commit.GroupID != g.GroupID {
		return ErrTreeKEMInvalidCommit
	}
	if g.MyLeafIndex < 0 || g.MyLeafIndex >= g.Tree.NumLeaves || g.Tree.Nodes[2*g.MyLeafIndex].Blank {
		return ErrTreeKEMEvictedMember
	}

	// 1. Verify epoch sequence BEFORE touching or inspecting untrusted tree snapshots
	if commit.Epoch != g.Epoch+1 {
		return ErrTreeKEMEpochMismatch
	}

	// 2. Verify Committer against TRUSTED local g.Tree leaf (prevents committer SignPub swap)
	if commit.CommitterLeaf < 0 || commit.CommitterLeaf >= g.Tree.NumLeaves {
		return ErrTreeKEMLeafNotFound
	}
	if commit.Path.LeafIndex != commit.CommitterLeaf {
		return ErrTreeKEMInvalidCommit
	}
	origCommitterNode := g.Tree.Nodes[2*commit.CommitterLeaf]
	if origCommitterNode.Blank {
		return ErrTreeKEMEvictedMember
	}
	committerPubBytes, err := hex.DecodeString(origCommitterNode.SignPubHex)
	if err != nil || len(committerPubBytes) != ed25519.PublicKeySize {
		return errors.New("treekem: invalid committer public key")
	}
	if !ed25519.Verify(committerPubBytes, commit.CanonicalBytesWithConfirmation(), commit.Signature) {
		return fmt.Errorf("treekem: committer ed25519 signature verification failed (committer leaf %d, pub %s)", commit.CommitterLeaf, origCommitterNode.SignPubHex)
	}

	if commit.RemovedLeaf == g.MyLeafIndex {
		targetNode := g.Tree.Nodes[2*commit.RemovedLeaf]
		if targetNode.PrivateKey != nil {
			zeroizeBytes(targetNode.PrivateKey[:])
		}
		targetNode.Blank = true
		targetNode.PublicKey = [32]byte{}
		targetNode.PrivateKey = nil
		targetNode.JoinedEpoch = 0
		return ErrTreeKEMEvictedMember
	}

	// 3. Apply candidate state changes to an isolated deep clone (atomic rollback on any error)
	candidate := g.Tree.Clone()
	candidateMyLeaf := g.MyLeafIndex

	if len(commit.TreeNodes) > 0 {
		if len(commit.TreeNodes) > 2*MaxTreeLeaves {
			return ErrTreeKEMInvalidCommit
		}
		maxLeaf := candidate.NumLeaves - 1
		for _, en := range commit.TreeNodes {
			if en.Index < 0 || en.LeafIndex < -1 || en.LeafIndex >= MaxTreeLeaves {
				return ErrTreeKEMInvalidCommit
			}
			if en.LeafIndex >= 0 {
				if en.Index != 2*en.LeafIndex {
					return ErrTreeKEMInvalidCommit
				}
				if en.LeafIndex > maxLeaf {
					maxLeaf = en.LeafIndex
				}
			}
		}
		if maxLeaf >= MaxTreeLeaves {
			return ErrTreeKEMInvalidCommit
		}
		if maxLeaf+1 > candidate.NumLeaves {
			candidate.resize(maxLeaf + 1)
		}
		for _, en := range commit.TreeNodes {
			if en.Index >= len(candidate.Nodes) {
				return ErrTreeKEMInvalidCommit
			}
			node := candidate.Nodes[en.Index]
			// Existing non-blank leaves cannot silently change SignPubHex unless explicitly removed
			if node.LeafIndex >= 0 && !node.Blank && node.LeafIndex != commit.RemovedLeaf {
				if en.Blank || en.SignPubHex != node.SignPubHex {
					return ErrTreeKEMInvalidCommit
				}
			}
			// Never overwrite an active leaf PrivateKey with unrelated static keys;
			// preserve existing PrivateKey ONLY if this node's PublicKey did not change.
			if node.PrivateKey != nil && node.PublicKey != en.PublicKey {
				zeroizeBytes(node.PrivateKey[:])
				node.PrivateKey = nil
			}
			node.Blank = en.Blank
			node.PublicKey = en.PublicKey
			node.SignPubHex = en.SignPubHex
			node.JoinedEpoch = en.JoinedEpoch
			if len(en.UnmergedLeaves) > 0 {
				node.UnmergedLeaves = append([]int(nil), en.UnmergedLeaves...)
			} else {
				node.UnmergedLeaves = nil
			}
		}
	} else {
		if commit.RemovedLeaf != -1 {
			if commit.RemovedLeaf < 0 || commit.RemovedLeaf >= candidate.NumLeaves {
				return ErrTreeKEMLeafNotFound
			}
			targetNode := candidate.Nodes[2*commit.RemovedLeaf]
			targetNode.Blank = true
			targetNode.PublicKey = [32]byte{}
			targetNode.PrivateKey = nil
			targetNode.SignPubHex = ""
			targetNode.JoinedEpoch = 0
			candidate.clearLeafFromUnmerged(commit.RemovedLeaf)
			curr := targetNode.Parent
			for curr != -1 && curr < len(candidate.Nodes) {
				candidate.Nodes[curr].Blank = true
				candidate.Nodes[curr].PublicKey = [32]byte{}
				candidate.Nodes[curr].PrivateKey = nil
				candidate.Nodes[curr].UnmergedLeaves = nil
				curr = candidate.Nodes[curr].Parent
			}
		}

		if commit.AddedPackage != nil {
			if !commit.AddedPackage.Verify() {
				return errors.New("treekem: invalid added package signature")
			}
			newLeafIdx := -1
			for i := 0; i < candidate.NumLeaves; i++ {
				if candidate.Nodes[2*i].Blank {
					newLeafIdx = i
					break
				}
			}
			if newLeafIdx == -1 {
				candidate.resize(candidate.NumLeaves + 1)
				newLeafIdx = candidate.NumLeaves - 1
			}
			candidate.Nodes[2*newLeafIdx].Blank = false
			candidate.Nodes[2*newLeafIdx].PublicKey = commit.AddedPackage.InitKey
			candidate.Nodes[2*newLeafIdx].SignPubHex = commit.AddedPackage.SignPub
			candidate.Nodes[2*newLeafIdx].JoinedEpoch = commit.Epoch
			candidate.addUnmergedLeaf(newLeafIdx)
		}
	}

	// Validate path node bounds before indexing
	for _, pathNode := range commit.Path.Nodes {
		if pathNode.NodeIndex < 0 || pathNode.NodeIndex >= len(candidate.Nodes) {
			return ErrTreeKEMInvalidCommit
		}
	}

	// 4. Decrypt path secret from lowest common ancestor (LCA)
	myPath := candidate.DirectPathIndices(candidateMyLeaf)
	myKnownNodes := make(map[int]*[32]byte, 1+len(myPath))
	if candidate.Nodes[2*candidateMyLeaf].PrivateKey != nil {
		myKnownNodes[2*candidateMyLeaf] = candidate.Nodes[2*candidateMyLeaf].PrivateKey
	}
	for _, ancIdx := range myPath {
		if candidate.Nodes[ancIdx].PrivateKey != nil {
			myKnownNodes[ancIdx] = candidate.Nodes[ancIdx].PrivateKey
		}
	}

	var decryptedPathSecret [32]byte
	defer zeroizeBytes(decryptedPathSecret[:])
	found := false
	decryptedLevel := -1

	for levelIdx, pathNode := range commit.Path.Nodes {
		for targetNodeIdx, cipher := range pathNode.EncryptedKeys {
			priv := myKnownNodes[targetNodeIdx]
			if priv != nil {
				plain, err := hpkeDecrypt(*priv, cipher.EphemeralPub, cipher.Ciphertext, []byte("MLS 1.0 direct_path"))
				if err == nil && len(plain) == 32 {
					copy(decryptedPathSecret[:], plain)
					zeroizeBytes(plain)
					found = true
					decryptedLevel = levelIdx
					break
				}
			}
		}
		if found {
			break
		}
	}

	if !found {
		return ErrTreeKEMDecryptionFailed
	}

	// 5. Update committer leaf and direct path public keys in candidate tree
	commNode := candidate.Nodes[2*commit.CommitterLeaf]
	commNode.Blank = false
	commNode.PublicKey = commit.Path.LeafPublicKey
	commNode.PrivateKey = nil

	for _, pathNode := range commit.Path.Nodes {
		anc := candidate.Nodes[pathNode.NodeIndex]
		anc.Blank = false
		anc.PublicKey = pathNode.PublicKey
		if anc.PrivateKey != nil {
			zeroizeBytes(anc.PrivateKey[:])
			anc.PrivateKey = nil
		}
		if len(commit.TreeNodes) == 0 {
			anc.UnmergedLeaves = nil
		}
	}

	// 6. Derive commit secret to root and intermediate ancestor keys
	currSecret := decryptedPathSecret
	defer zeroizeBytes(currSecret[:])
	for step := decryptedLevel; step < len(commit.Path.Nodes); step++ {
		ancIdx := commit.Path.Nodes[step].NodeIndex
		nodeSecret := deriveNodeSecret(currSecret)
		ancPub, ancPriv := deriveKeyPair(nodeSecret)
		zeroizeBytes(nodeSecret[:])
		if ancPub != commit.Path.Nodes[step].PublicKey {
			zeroizeBytes(ancPriv[:])
			return ErrTreeKEMInvalidCommit
		}
		ancNode := candidate.Nodes[ancIdx]
		ancNode.PublicKey = ancPub
		ancNode.PrivateKey = &ancPriv
		ancNode.Blank = false

		currSecret = derivePathSecret(currSecret)
	}
	commitSecret := deriveCommitSecret(currSecret)
	defer zeroizeBytes(commitSecret[:])

	// 7. Verify Confirmation Tag against candidate TreeHash
	newTranscript := sha256.Sum256(append(g.ConfirmedTranscriptHash[:], commit.CanonicalBytes()...))

	extractor := hkdf.Extract(sha256.New, commitSecret[:], g.InitSecret[:])
	var newEpochSecret [32]byte
	copy(newEpochSecret[:], extractor)

	tempGC := GroupContext{
		GroupID:                 g.GroupID,
		Epoch:                   commit.Epoch,
		TreeHash:                candidate.TreeHash(),
		ConfirmedTranscriptHash: newTranscript,
	}
	gcBytes := tempGC.Bytes()

	var newConfirmKey [32]byte
	defer zeroizeBytes(newConfirmKey[:])
	confirmReader := hkdf.Expand(sha256.New, newEpochSecret[:], append([]byte("MLS 1.0 confirm"), gcBytes...))
	_, _ = io.ReadFull(confirmReader, newConfirmKey[:])

	expectedTag := hmacSHA256(newConfirmKey[:], newTranscript[:])
	if subtle.ConstantTimeCompare(expectedTag[:], commit.ConfirmationTag[:]) != 1 {
		zeroizeBytes(newEpochSecret[:])
		return fmt.Errorf("treekem: confirmation tag mismatch (expected %x, got %x)", expectedTag, commit.ConfirmationTag)
	}

	// 8. Commit verified state atomically
	g.Tree = candidate
	g.MyLeafIndex = candidateMyLeaf
	g.Epoch = commit.Epoch
	g.ConfirmedTranscriptHash = newTranscript
	g.deriveEpochSecretsFromEpochSecret(newEpochSecret)
	zeroizeBytes(newEpochSecret[:])

	return nil
}

// NewMLSGroupFromWelcome initializes an MLSGroup for a newly invited member from a Welcome message.
// It strictly binds welcome decryption to the supplied ephemeral initPriv (when provided),
// verifies TreeHash, committer signature on MLSWelcome, and ConfirmationTag before accepting.
func NewMLSGroupFromWelcome(id *Identity, welcome *MLSWelcome, initPriv ...*[32]byte) (*MLSGroup, error) {
	if id == nil || welcome == nil {
		return nil, errors.New("treekem: nil identity or welcome")
	}
	if len(welcome.TreeNodes) == 0 || len(welcome.TreeNodes) > 2*MaxTreeLeaves {
		return nil, errors.New("treekem: invalid welcome tree size")
	}

	// 1. Validate bounds and reconstruct ratchet tree FIRST
	maxLeaf := 0
	for _, en := range welcome.TreeNodes {
		if en.Index < 0 || en.LeafIndex < -1 || en.LeafIndex >= MaxTreeLeaves {
			return nil, errors.New("treekem: out-of-bounds node index in welcome")
		}
		if en.LeafIndex >= 0 && en.Index != 2*en.LeafIndex {
			return nil, errors.New("treekem: mismatched leaf index in welcome")
		}
		if en.LeafIndex > maxLeaf {
			maxLeaf = en.LeafIndex
		}
	}
	tree := NewRatchetTree(maxLeaf + 1)
	myLeaf := -1
	for _, en := range welcome.TreeNodes {
		if en.Index >= len(tree.Nodes) {
			return nil, errors.New("treekem: welcome node index exceeds tree bounds")
		}
		node := tree.Nodes[en.Index]
		node.Blank = en.Blank
		node.PublicKey = en.PublicKey
		node.SignPubHex = en.SignPubHex
		node.JoinedEpoch = en.JoinedEpoch
		if len(en.UnmergedLeaves) > 0 {
			node.UnmergedLeaves = append([]int(nil), en.UnmergedLeaves...)
		}
		if !en.Blank && en.SignPubHex == id.Address() && en.LeafIndex >= 0 {
			myLeaf = en.LeafIndex
		}
	}

	if myLeaf == -1 {
		return nil, errors.New("treekem: welcome message does not contain local identity in tree leaves")
	}

	// Verify tree hash before checking signature
	if tree.TreeHash() != welcome.TreeHash {
		return nil, errors.New("treekem: welcome tree hash mismatch")
	}

	// 2. Verify signer Ed25519 signature over MLSWelcome
	if welcome.SignerLeaf < 0 || welcome.SignerLeaf >= tree.NumLeaves {
		return nil, errors.New("treekem: invalid welcome signer leaf")
	}
	signerNode := tree.Nodes[2*welcome.SignerLeaf]
	if signerNode.Blank {
		return nil, errors.New("treekem: welcome signer leaf is blank")
	}
	signerPubBytes, err := hex.DecodeString(signerNode.SignPubHex)
	if err != nil || len(signerPubBytes) != ed25519.PublicKeySize {
		return nil, errors.New("treekem: invalid welcome signer public key")
	}
	if len(welcome.Signature) == 0 || !ed25519.Verify(signerPubBytes, welcome.CanonicalBytes(), welcome.Signature) {
		return nil, errors.New("treekem: invalid welcome signature")
	}

	// 3. Strictly select decryption key without falling back to static EncPriv when ephemeral key was used
	var privKey [32]byte
	if len(initPriv) > 0 && initPriv[0] != nil {
		privKey = *initPriv[0]
	} else {
		if tree.Nodes[2*myLeaf].PublicKey != id.EncPub {
			return nil, errors.New("treekem: missing ephemeral initPriv matching leaf public key")
		}
		privKey = id.EncPriv
	}
	defer zeroizeBytes(privKey[:])

	myLeafNode := tree.Nodes[2*myLeaf]
	privCopy := privKey
	myLeafNode.PrivateKey = &privCopy
	myLeafNode.Identity = id

	// 4. Decrypt group secret bound to GroupID & Epoch
	welcomeInfo := welcomeHPKEInfo(welcome.GroupID, welcome.Epoch)
	groupSecretBytes, err := hpkeDecrypt(privKey, welcome.EncryptedGroupSecret.EphemeralPub, welcome.EncryptedGroupSecret.Ciphertext, welcomeInfo)
	if err != nil {
		return nil, fmt.Errorf("treekem: failed to decrypt welcome message: %w", err)
	}
	defer zeroizeBytes(groupSecretBytes)
	if len(groupSecretBytes) < 32 {
		return nil, errors.New("treekem: invalid decrypted group secret length")
	}
	var newEpochSecret [32]byte
	copy(newEpochSecret[:], groupSecretBytes[:32])
	defer zeroizeBytes(newEpochSecret[:])

	g := &MLSGroup{
		GroupID:                 welcome.GroupID,
		Epoch:                   welcome.Epoch,
		MyLeafIndex:             myLeaf,
		LocalIdentity:           id,
		Tree:                    tree,
		ConfirmedTranscriptHash: welcome.ConfirmedTranscriptHash,
	}

	// Derive InitSecret, ApplicationSecret, ConfirmationKey strictly from GroupContext + EpochSecret
	g.deriveEpochSecretsFromEpochSecret(newEpochSecret)

	// Verify ConfirmationTag against locally derived ConfirmationKey and GroupContext
	expectedTag := hmacSHA256(g.ConfirmationKey[:], welcome.ConfirmedTranscriptHash[:])
	if subtle.ConstantTimeCompare(expectedTag[:], welcome.ConfirmationTag[:]) != 1 {
		return nil, errors.New("treekem: welcome confirmation tag verification failed")
	}
	if len(groupSecretBytes) >= 64 && subtle.ConstantTimeCompare(groupSecretBytes[32:64], g.InitSecret[:]) != 1 {
		return nil, errors.New("treekem: welcome init secret mismatch")
	}
	if len(groupSecretBytes) >= 96 && subtle.ConstantTimeCompare(groupSecretBytes[64:96], g.ApplicationSecret[:]) != 1 {
		return nil, errors.New("treekem: welcome application secret mismatch")
	}

	return g, nil
}

// ApplicationSecretBytes returns the 32-byte symmetric key for encrypting room traffic in this epoch.
func (c *MLSCommit) CanonicalBytes() []byte {
	parts := []string{
		c.GroupID,
		strconv.Itoa(c.CommitterLeaf),
		strconv.FormatUint(c.Epoch, 10),
		strconv.Itoa(c.RemovedLeaf),
	}
	if c.AddedPackage != nil {
		parts = append(
			parts,
			"added",
			c.AddedPackage.SignPub,
			hex.EncodeToString(c.AddedPackage.InitKey[:]),
			strconv.FormatInt(c.AddedPackage.Timestamp, 10),
			hex.EncodeToString(c.AddedPackage.Signature),
		)
	} else {
		parts = append(parts, "no_added")
	}
	if c.Path != nil {
		parts = append(parts, "path", strconv.Itoa(c.Path.LeafIndex), hex.EncodeToString(c.Path.LeafPublicKey[:]), strconv.Itoa(len(c.Path.Nodes)))
		for _, pn := range c.Path.Nodes {
			parts = append(parts, strconv.Itoa(pn.NodeIndex), hex.EncodeToString(pn.PublicKey[:]))
			keys := make([]int, 0, len(pn.EncryptedKeys))
			for idx := range pn.EncryptedKeys {
				keys = append(keys, idx)
			}
			sort.Ints(keys)
			parts = append(parts, strconv.Itoa(len(keys)))
			for _, idx := range keys {
				cipher := pn.EncryptedKeys[idx]
				parts = append(parts, strconv.Itoa(idx), hex.EncodeToString(cipher.EphemeralPub[:]), hex.EncodeToString(cipher.Ciphertext))
			}
		}
	} else {
		parts = append(parts, "no_path")
	}
	return EncodeCanonical("MLS 1.0 Commit", parts...)
}

// CanonicalBytesWithConfirmation returns canonical bytes including the confirmation tag for signature.
func (c *MLSCommit) CanonicalBytesWithConfirmation() []byte {
	return EncodeCanonical(
		"MLS 1.0 CommitConfirmed",
		string(c.CanonicalBytes()),
		string(c.ConfirmationTag[:]),
	)
}

// --- Cryptographic Primitive Helpers (HPKE & KDF) ---

func derivePathSecret(secret [32]byte) [32]byte {
	r := hkdf.Expand(sha256.New, secret[:], []byte("MLS 1.0 path"))
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

func deriveNodeSecret(pathSecret [32]byte) [32]byte {
	r := hkdf.Expand(sha256.New, pathSecret[:], []byte("MLS 1.0 node"))
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

func deriveKeyPair(secret [32]byte) ([32]byte, [32]byte) {
	var priv [32]byte = secret
	// Clamp private key scalar as per X25519 specification
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	return pubArr, priv
}

func deriveCommitSecret(pathSecret [32]byte) [32]byte {
	r := hkdf.Expand(sha256.New, pathSecret[:], []byte("MLS 1.0 commit"))
	var out [32]byte
	_, _ = io.ReadFull(r, out[:])
	return out
}

func hpkeEncrypt(recipientPub [32]byte, plaintext []byte, info []byte) (HPKECipher, error) {
	var ePriv [32]byte
	defer zeroizeBytes(ePriv[:])
	if _, err := io.ReadFull(rand.Reader, ePriv[:]); err != nil {
		return HPKECipher{}, err
	}
	clampX25519Scalar(&ePriv)

	ePub, err := curve25519.X25519(ePriv[:], curve25519.Basepoint)
	if err != nil {
		return HPKECipher{}, err
	}
	ss, err := curve25519.X25519(ePriv[:], recipientPub[:])
	if err != nil {
		return HPKECipher{}, err
	}
	defer zeroizeBytes(ss)

	keyReader := hkdf.New(sha256.New, ss, append(append([]byte(nil), ePub...), recipientPub[:]...), info)
	var key [32]byte
	defer zeroizeBytes(key[:])
	if _, err := io.ReadFull(keyReader, key[:]); err != nil {
		return HPKECipher{}, err
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return HPKECipher{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return HPKECipher{}, err
	}

	sealed := aead.Seal(nonce, nonce, plaintext, info)
	var ePubArr [32]byte
	copy(ePubArr[:], ePub)
	return HPKECipher{
		EphemeralPub: ePubArr,
		Ciphertext:   sealed,
	}, nil
}

func hpkeDecrypt(recipientPriv [32]byte, ephemeralPub [32]byte, ciphertext []byte, info []byte) ([]byte, error) {
	ss, err := curve25519.X25519(recipientPriv[:], ephemeralPub[:])
	if err != nil {
		return nil, err
	}
	defer zeroizeBytes(ss)

	recipientPub, err := curve25519.X25519(recipientPriv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	keyReader := hkdf.New(sha256.New, ss, append(ephemeralPub[:], recipientPub...), info)

	var key [32]byte
	defer zeroizeBytes(key[:])
	if _, err := io.ReadFull(keyReader, key[:]); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("treekem: ciphertext too short")
	}

	nonce := ciphertext[:aead.NonceSize()]
	payload := ciphertext[aead.NonceSize():]
	return aead.Open(nil, nonce, payload, info)
}

func hmacSHA256(key, data []byte) [32]byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

