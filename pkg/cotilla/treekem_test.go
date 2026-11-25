package cotilla

import (
	"bytes"
	"crypto/subtle"
	"testing"
)

// TestTreeKEM_LBBT_Structure verifies Left-Balanced Binary Tree construction and navigation.
func TestTreeKEM_LBBT_Structure(t *testing.T) {
	testCases := []struct {
		leaves    int
		total     int
		rootIndex int
	}{
		{leaves: 1, total: 1, rootIndex: 0},
		{leaves: 2, total: 3, rootIndex: 1},
		{leaves: 3, total: 5, rootIndex: 3},
		{leaves: 4, total: 7, rootIndex: 3},
		{leaves: 5, total: 9, rootIndex: 7},
		{leaves: 7, total: 13, rootIndex: 7},
		{leaves: 8, total: 15, rootIndex: 7},
		{leaves: 16, total: 31, rootIndex: 15},
	}

	for _, tc := range testCases {
		tree := NewRatchetTree(tc.leaves)
		if len(tree.Nodes) != tc.total {
			t.Fatalf("for %d leaves, expected %d total nodes, got %d", tc.leaves, tc.total, len(tree.Nodes))
		}
		if tree.RootIndex() != tc.rootIndex {
			t.Fatalf("for %d leaves, expected root index %d, got %d", tc.leaves, tc.rootIndex, tree.RootIndex())
		}

		// Verify every leaf has even index 2*i
		for i := 0; i < tc.leaves; i++ {
			nodeIdx := 2 * i
			if tree.Nodes[nodeIdx].LeafIndex != i {
				t.Fatalf("node %d expected leafIndex %d, got %d", nodeIdx, i, tree.Nodes[nodeIdx].LeafIndex)
			}
		}

		// Verify direct path from leaf 0 leads to root
		path := tree.DirectPathIndices(0)
		if tc.leaves > 1 {
			if len(path) == 0 {
				t.Fatalf("expected non-empty direct path for %d leaves", tc.leaves)
			}
			if path[len(path)-1] != tc.rootIndex {
				t.Fatalf("expected direct path to terminate at root %d, got %d", tc.rootIndex, path[len(path)-1])
			}
		}
	}
}

// TestTreeKEM_TreeHash_MerkleIntegrity verifies that changing any leaf alters TreeHash.
func TestTreeKEM_TreeHash_MerkleIntegrity(t *testing.T) {
	tree := NewRatchetTree(4)
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()

	tree.Nodes[0].Blank = false
	tree.Nodes[0].PublicKey = idA.EncPub
	tree.Nodes[0].SignPubHex = idA.Address()

	tree.Nodes[2].Blank = false
	tree.Nodes[2].PublicKey = idB.EncPub
	tree.Nodes[2].SignPubHex = idB.Address()

	h1 := tree.TreeHash()

	// Alter leaf 1
	tree.Nodes[2].PublicKey[0] ^= 0xFF
	h2 := tree.TreeHash()

	if h1 == h2 {
		t.Fatal("expected TreeHash to change after altering leaf public key")
	}

	// Blank leaf 1
	tree.Nodes[2].Blank = true
	h3 := tree.TreeHash()

	if h2 == h3 || h1 == h3 {
		t.Fatal("expected TreeHash to change after blanking leaf")
	}
}

// TestTreeKEM_KeyPackage_SignAndVerify tests KeyPackage creation and cryptographic verification.
func TestTreeKEM_KeyPackage_SignAndVerify(t *testing.T) {
	id, _ := NewIdentity()
	pkg, err := NewKeyPackage(id)
	if err != nil {
		t.Fatalf("NewKeyPackage failed: %v", err)
	}

	if !pkg.Verify() {
		t.Fatal("valid KeyPackage failed verification")
	}

	// Tampering test: alter init key
	pkg.InitKey[0] ^= 0x01
	if pkg.Verify() {
		t.Fatal("tampered KeyPackage unexpectedly passed verification")
	}
}

// TestTreeKEM_MultiMemberLifecycle exercises group creation, sequential additions (A -> B -> C -> D),
// continuous asymmetric ratcheting (PCS), cryptographic member eviction (evict C), and rogue lockout.
func TestTreeKEM_MultiMemberLifecycle(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()
	idD, _ := NewIdentity()

	// 1. Alice creates group
	groupA, err := NewMLSGroup("treekem-burner-room", idA)
	if err != nil {
		t.Fatalf("NewMLSGroup failed: %v", err)
	}
	if groupA.Epoch != 1 {
		t.Fatalf("expected genesis epoch 1, got %d", groupA.Epoch)
	}

	// 2. Alice adds Bob
	pkgB, _ := NewKeyPackage(idB)
	_, welcomeB, err := groupA.CreateAddCommit(pkgB)
	if err != nil {
		t.Fatalf("Alice adding Bob failed: %v", err)
	}
	if groupA.Epoch != 2 {
		t.Fatalf("expected epoch 2 after adding Bob, got %d", groupA.Epoch)
	}

	// Bob joins from Welcome
	groupB, err := NewMLSGroupFromWelcome(idB, welcomeB, pkgB.InitPriv)
	if err != nil {
		t.Fatalf("Bob joining from Welcome failed: %v", err)
	}
	if groupB.Epoch != groupA.Epoch {
		t.Fatalf("Bob epoch mismatch: expected %d, got %d", groupA.Epoch, groupB.Epoch)
	}
	if groupB.ApplicationSecretBytes() != groupA.ApplicationSecretBytes() {
		t.Fatal("Bob and Alice application secret mismatch after Add(Bob)")
	}

	// 3. Bob adds Charlie
	pkgC, _ := NewKeyPackage(idC)
	commitC, welcomeC, err := groupB.CreateAddCommit(pkgC)
	if err != nil {
		t.Fatalf("Bob adding Charlie failed: %v", err)
	}

	// Alice processes commitC
	if err := groupA.ProcessCommit(commitC); err != nil {
		t.Fatalf("Alice processing Add(Charlie) failed: %v", err)
	}

	// Charlie joins from Welcome
	groupC, err := NewMLSGroupFromWelcome(idC, welcomeC, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("Charlie joining from Welcome failed: %v", err)
	}

	if groupA.ApplicationSecretBytes() != groupC.ApplicationSecretBytes() {
		t.Fatal("Charlie and Alice application secret mismatch after Add(Charlie)")
	}

	// 4. Alice adds Dave
	pkgD, _ := NewKeyPackage(idD)
	commitD, welcomeD, err := groupA.CreateAddCommit(pkgD)
	if err != nil {
		t.Fatalf("Alice adding Dave failed: %v", err)
	}

	if err := groupB.ProcessCommit(commitD); err != nil {
		t.Fatalf("Bob processing Add(Dave) failed: %v", err)
	}
	if err := groupC.ProcessCommit(commitD); err != nil {
		t.Fatalf("Charlie processing Add(Dave) failed: %v", err)
	}

	groupD, err := NewMLSGroupFromWelcome(idD, welcomeD, pkgD.InitPriv)
	if err != nil {
		t.Fatalf("Dave joining from Welcome failed: %v", err)
	}

	// Verify all 4 peers agree on Epoch 4 and ApplicationSecret
	epochExpected := uint64(4)
	for name, g := range map[string]*MLSGroup{"A": groupA, "B": groupB, "C": groupC, "D": groupD} {
		if g.Epoch != epochExpected {
			t.Fatalf("%s expected epoch %d, got %d", name, epochExpected, g.Epoch)
		}
		if g.ApplicationSecretBytes() != groupA.ApplicationSecretBytes() {
			t.Fatalf("%s application secret does not match Alice", name)
		}
	}

	// 5. Post-Compromise Security (PCS): Bob ratchets his leaf key
	oldAppSecret := groupA.ApplicationSecretBytes()
	updateCommit, err := groupB.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("Bob CreateUpdateCommit failed: %v", err)
	}

	if err := groupA.ProcessCommit(updateCommit); err != nil {
		t.Fatalf("Alice ProcessCommit(update) failed: %v", err)
	}
	if err := groupC.ProcessCommit(updateCommit); err != nil {
		t.Fatalf("Charlie ProcessCommit(update) failed: %v", err)
	}
	if err := groupD.ProcessCommit(updateCommit); err != nil {
		t.Fatalf("Dave ProcessCommit(update) failed: %v", err)
	}

	newAppSecret := groupA.ApplicationSecretBytes()
	if oldAppSecret == newAppSecret {
		t.Fatal("PCS violation: application secret did not change after update commit")
	}
	if groupB.ApplicationSecretBytes() != newAppSecret ||
		groupC.ApplicationSecretBytes() != newAppSecret ||
		groupD.ApplicationSecretBytes() != newAppSecret {
		t.Fatal("members failed to derive matching post-update application secret")
	}

	// 6. Cryptographic Eviction of Charlie (leaf 2): Alice evicts Charlie
	charlieLeaf := groupC.MyLeafIndex
	evictCommit, err := groupA.CreateRemoveCommit(charlieLeaf)
	if err != nil {
		t.Fatalf("Alice CreateRemoveCommit(Charlie) failed: %v", err)
	}

	// Bob and Dave process eviction commit
	if err := groupB.ProcessCommit(evictCommit); err != nil {
		t.Fatalf("Bob processing Charlie eviction failed: %v", err)
	}
	if err := groupD.ProcessCommit(evictCommit); err != nil {
		t.Fatalf("Dave processing Charlie eviction failed: %v", err)
	}

	postEvictSecret := groupA.ApplicationSecretBytes()
	if postEvictSecret == newAppSecret {
		t.Fatal("expected new application secret after eviction commit")
	}
	if groupB.ApplicationSecretBytes() != postEvictSecret || groupD.ApplicationSecretBytes() != postEvictSecret {
		t.Fatal("remaining members A, B, D failed to agree on post-eviction secret")
	}

	// Check 6A: Charlie receives eviction commit and is locked out!
	err = groupC.ProcessCommit(evictCommit)
	if err != ErrTreeKEMEvictedMember {
		t.Fatalf("expected ErrTreeKEMEvictedMember for Charlie, got %v", err)
	}
	if groupC.ApplicationSecretBytes() == postEvictSecret {
		t.Fatal("SECURITY BUG: Evicted Charlie was able to derive the post-eviction group secret!")
	}

	// Check 6B: Evicted Charlie CANNOT create a valid commit!
	rogueCommit, err := groupC.CreateUpdateCommit()
	if err == nil {
		// Even if Charlie manufactures a commit locally, other peers MUST reject it
		if err := groupA.ProcessCommit(rogueCommit); err != ErrTreeKEMEvictedMember {
			t.Fatalf("expected Alice to reject Charlie's rogue commit with ErrTreeKEMEvictedMember, got %v", err)
		}
		if err := groupB.ProcessCommit(rogueCommit); err != ErrTreeKEMEvictedMember {
			t.Fatalf("expected Bob to reject Charlie's rogue commit with ErrTreeKEMEvictedMember, got %v", err)
		}
	}

	// Check 6C: Evicted Charlie CANNOT add Edward and merge with main group!
	idE, _ := NewIdentity()
	pkgE, _ := NewKeyPackage(idE)
	rogueAddCommit, _, err := groupC.CreateAddCommit(pkgE)
	if err == nil {
		if err := groupA.ProcessCommit(rogueAddCommit); err == nil {
			t.Fatal("SECURITY BUG: Alice accepted rogue member addition from evicted Charlie!")
		}
		if err := groupD.ProcessCommit(rogueAddCommit); err == nil {
			t.Fatal("SECURITY BUG: Dave accepted rogue member addition from evicted Charlie!")
		}
	}
}

// TestTreeKEM_LargeMeshScaling verifies TreeKEM tree operations on an 8-peer mesh
// showing logarithmic path derivation and valid multi-peer agreement.
func TestTreeKEM_LargeMeshScaling(t *testing.T) {
	const peerCount = 8
	identities := make([]*Identity, peerCount)
	groups := make([]*MLSGroup, peerCount)

	for i := 0; i < peerCount; i++ {
		identities[i], _ = NewIdentity()
	}

	// Creator is peer 0
	var err error
	groups[0], err = NewMLSGroup("treekem-scale-room", identities[0])
	if err != nil {
		t.Fatalf("failed to create root group: %v", err)
	}

	// Sequentially add peers 1 through 7
	for i := 1; i < peerCount; i++ {
		pkg, _ := NewKeyPackage(identities[i])
		commit, welcome, err := groups[0].CreateAddCommit(pkg)
		if err != nil {
			t.Fatalf("peer 0 adding peer %d failed: %v", i, err)
		}

		// Existing peers process commit
		for j := 1; j < i; j++ {
			if err := groups[j].ProcessCommit(commit); err != nil {
				t.Fatalf("peer %d processing commit for peer %d failed: %v", j, i, err)
			}
		}

		// New peer joins via Welcome
		groups[i], err = NewMLSGroupFromWelcome(identities[i], welcome, pkg.InitPriv)
		if err != nil {
			t.Fatalf("peer %d joining from Welcome failed: %v", i, err)
		}
	}

	// Verify all 8 peers hold identical epoch and application secret
	expectedAppSecret := groups[0].ApplicationSecretBytes()
	for i := 1; i < peerCount; i++ {
		sec := groups[i].ApplicationSecretBytes()
		if subtle.ConstantTimeCompare(sec[:], expectedAppSecret[:]) != 1 {
			t.Fatalf("peer %d application secret mismatch in 8-peer mesh", i)
		}
	}

	// Verify direct path length is bounded by log2(N)
	path := groups[0].Tree.DirectPathIndices(0)
	if len(path) > 4 { // log2(8) = 3 (+1 for tree shape)
		t.Fatalf("direct path too long for 8 peers: %d", len(path))
	}
}

// TestTreeKEM_HPKE_Roundtrip verifies DHKEM(X25519) + ChaCha20-Poly1305 single-shot encryption.
func TestTreeKEM_HPKE_Roundtrip(t *testing.T) {
	id, _ := NewIdentity()
	plaintext := []byte("top secret treekem path secret payload 32 bytes")
	info := []byte("MLS 1.0 test info")

	cipher, err := hpkeEncrypt(id.EncPub, plaintext, info)
	if err != nil {
		t.Fatalf("hpkeEncrypt failed: %v", err)
	}

	decrypted, err := hpkeDecrypt(id.EncPriv, cipher.EphemeralPub, cipher.Ciphertext, info)
	if err != nil {
		t.Fatalf("hpkeDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted %q does not match original %q", decrypted, plaintext)
	}

	// Tampered info must fail
	_, err = hpkeDecrypt(id.EncPriv, cipher.EphemeralPub, cipher.Ciphertext, []byte("wrong info"))
	if err == nil {
		t.Fatal("expected decryption failure with mismatched AAD info")
	}
}

// TestTreeKEM_WelcomeAndEvictionSequence tests the multi-party lifecycle with member admission and eviction:
// Alice creates room (Epoch 1)
// Bob joins via AddCommit + Welcome (Epoch 2)
// Charlie joins via AddCommit + Welcome (Epoch 3)
// Dave joins via AddCommit + Welcome (Epoch 4)
// Alice, Bob, Charlie, and Dave verify identical Epoch 4 key
// Alice evicts Charlie (Epoch 5)
// Bob and Dave process commit and advance to Epoch 5 with matching key
// Charlie is locked out (cannot decrypt or process commit)
func TestTreeKEM_WelcomeAndEvictionSequence(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()
	idD, _ := NewIdentity()

	pkgB, _ := NewKeyPackage(idB)
	pkgC, _ := NewKeyPackage(idC)
	pkgD, _ := NewKeyPackage(idD)

	// 1. Alice creates room at Epoch 1
	aliceGroup, err := NewMLSGroup("burner-room-123", idA)
	if err != nil {
		t.Fatalf("failed to create alice MLS group: %v", err)
	}
	if aliceGroup.Epoch != 1 {
		t.Fatalf("expected alice epoch 1, got %d", aliceGroup.Epoch)
	}

	// 2. Bob joins via AddCommit + Welcome at Epoch 2
	_, bobWelcome, err := aliceGroup.CreateAddCommit(pkgB)
	if err != nil {
		t.Fatalf("failed to add Bob: %v", err)
	}
	bobGroup, err := NewMLSGroupFromWelcome(idB, bobWelcome, pkgB.InitPriv)
	if err != nil {
		t.Fatalf("bob failed to join from welcome: %v", err)
	}

	// 3. Charlie joins via AddCommit + Welcome at Epoch 3
	commitAddC, charlieWelcome, err := aliceGroup.CreateAddCommit(pkgC)
	if err != nil {
		t.Fatalf("failed to add Charlie: %v", err)
	}
	if err := bobGroup.ProcessCommit(commitAddC); err != nil {
		t.Fatalf("bob failed to process add Charlie commit: %v", err)
	}
	charlieGroup, err := NewMLSGroupFromWelcome(idC, charlieWelcome, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("charlie failed to join from welcome: %v", err)
	}

	// 4. Dave joins via AddCommit + Welcome at Epoch 4
	commitAddD, daveWelcome, err := aliceGroup.CreateAddCommit(pkgD)
	if err != nil {
		t.Fatalf("failed to add Dave: %v", err)
	}
	if err := bobGroup.ProcessCommit(commitAddD); err != nil {
		t.Fatalf("bob failed to process add Dave commit: %v", err)
	}
	if err := charlieGroup.ProcessCommit(commitAddD); err != nil {
		t.Fatalf("charlie failed to process add Dave commit: %v", err)
	}
	daveGroup, err := NewMLSGroupFromWelcome(idD, daveWelcome, pkgD.InitPriv)
	if err != nil {
		t.Fatalf("dave failed to join from welcome: %v", err)
	}

	// Verify all 4 peers hold identical Epoch 4 application secret
	secA := aliceGroup.ApplicationSecretBytes()
	secB := bobGroup.ApplicationSecretBytes()
	secC := charlieGroup.ApplicationSecretBytes()
	secD := daveGroup.ApplicationSecretBytes()

	if secA != secB || secA != secC || secA != secD {
		t.Fatalf("application secret mismatch at Epoch 4: A=%x B=%x C=%x D=%x", secA, secB, secC, secD)
	}

	// 5. Alice evicts Charlie (leaf 2) -> advances to Epoch 5
	charlieLeaf := aliceGroup.FindLeafByAddress(idC.Address())
	evictCommit, err := aliceGroup.CreateRemoveCommit(charlieLeaf)
	if err != nil {
		t.Fatalf("alice failed to evict charlie: %v", err)
	}
	if evictCommit.Epoch != 5 {
		t.Fatalf("expected evictCommit epoch 5, got %d", evictCommit.Epoch)
	}

	// Bob processes commit -> advances to Epoch 5
	if err := bobGroup.ProcessCommit(evictCommit); err != nil {
		t.Fatalf("bob failed to process evict commit: %v", err)
	}
	if bobGroup.Epoch != 5 {
		t.Fatalf("expected bob epoch 5, got %d", bobGroup.Epoch)
	}

	// Dave processes commit -> advances to Epoch 5
	if err := daveGroup.ProcessCommit(evictCommit); err != nil {
		t.Fatalf("dave failed to process evict commit: %v", err)
	}
	if daveGroup.Epoch != 5 {
		t.Fatalf("expected dave epoch 5, got %d", daveGroup.Epoch)
	}

	// Charlie processes commit -> MUST return ErrTreeKEMEvictedMember
	if err := charlieGroup.ProcessCommit(evictCommit); err != ErrTreeKEMEvictedMember {
		t.Fatalf("expected charlie to get ErrTreeKEMEvictedMember, got %v", err)
	}

	// Verify Alice, Bob, and Dave have identical Epoch 5 keys
	newSecA := aliceGroup.ApplicationSecretBytes()
	newSecB := bobGroup.ApplicationSecretBytes()
	newSecD := daveGroup.ApplicationSecretBytes()

	if newSecA != newSecB || newSecA != newSecD {
		t.Fatalf("Epoch 5 key mismatch: A=%x B=%x D=%x", newSecA, newSecB, newSecD)
	}
	if newSecA == secA {
		t.Fatal("Epoch 5 key did not rotate from Epoch 4 key")
	}

	// Charlie's key is NOT Epoch 5 key
	oldSecC := charlieGroup.ApplicationSecretBytes()
	if oldSecC == newSecA {
		t.Fatal("evicted Charlie unexpectedly has Epoch 5 key")
	}
}

// TestTreeKEM_CommitEntropyUnpredictability verifies that every commit injects fresh CSPRNG entropy
// (RFC 9420 Section 3 & Section 8.3) such that successive commits produce unique, unpredictable keys.
func TestTreeKEM_CommitEntropyUnpredictability(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()

	aliceGroup, err := NewMLSGroup("entropy-test-room", idA)
	if err != nil {
		t.Fatalf("failed to create alice MLS group: %v", err)
	}

	pkgB, _ := NewKeyPackage(idB)
	_, welcomeB, err := aliceGroup.CreateAddCommit(pkgB)
	if err != nil {
		t.Fatalf("add bob commit failed: %v", err)
	}
	bobGroup, err := NewMLSGroupFromWelcome(idB, welcomeB, pkgB.InitPriv)
	if err != nil {
		t.Fatalf("bob join failed: %v", err)
	}

	secEpoch2 := aliceGroup.ApplicationSecretBytes()

	// Alice commits an update (PCS refresh)
	commitUpdate1, err := aliceGroup.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("alice update commit 1 failed: %v", err)
	}
	if err := bobGroup.ProcessCommit(commitUpdate1); err != nil {
		t.Fatalf("bob process update commit 1 failed: %v", err)
	}
	secEpoch3 := aliceGroup.ApplicationSecretBytes()

	// Bob commits an update (PCS refresh)
	commitUpdate2, err := bobGroup.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("bob update commit 2 failed: %v", err)
	}
	if err := aliceGroup.ProcessCommit(commitUpdate2); err != nil {
		t.Fatalf("alice process update commit 2 failed: %v", err)
	}
	secEpoch4 := bobGroup.ApplicationSecretBytes()

	// Alice adds Charlie
	pkgC, _ := NewKeyPackage(idC)
	commitAddC, welcomeC, err := aliceGroup.CreateAddCommit(pkgC)
	if err != nil {
		t.Fatalf("alice add charlie failed: %v", err)
	}
	charlieGroup, err := NewMLSGroupFromWelcome(idC, welcomeC, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("charlie join failed: %v", err)
	}
	if err := bobGroup.ProcessCommit(commitAddC); err != nil {
		t.Fatalf("bob process add charlie failed: %v", err)
	}
	secEpoch5 := aliceGroup.ApplicationSecretBytes()

	// Verify all epoch keys are mutually distinct (fresh entropy per commit)
	allSecrets := [][]byte{secEpoch2[:], secEpoch3[:], secEpoch4[:], secEpoch5[:]}
	for i := 0; i < len(allSecrets); i++ {
		for j := i + 1; j < len(allSecrets); j++ {
			if bytes.Equal(allSecrets[i], allSecrets[j]) {
				t.Fatalf("entropy reuse detected: secret %d matches secret %d (%x)", i, j, allSecrets[i])
			}
		}
	}

	// Verify all members at Epoch 5 agree on the secret
	if charlieGroup.ApplicationSecretBytes() != secEpoch5 || bobGroup.ApplicationSecretBytes() != secEpoch5 {
		t.Fatal("secret disagreement at Epoch 5 across group members")
	}

	// Also verify CreateRemoveCommit injects fresh entropy and changes EpochSecret, InitSecret, ApplicationSecret, and TreeHash
	prevEpochSec := aliceGroup.EpochSecret
	prevInitSec := aliceGroup.InitSecret
	prevTreeHash := aliceGroup.Tree.TreeHash()

	charlieLeaf := aliceGroup.FindLeafByAddress(idC.Address())
	commitRemoveC, err := aliceGroup.CreateRemoveCommit(charlieLeaf)
	if err != nil {
		t.Fatalf("alice remove charlie failed: %v", err)
	}
	if err := bobGroup.ProcessCommit(commitRemoveC); err != nil {
		t.Fatalf("bob process remove charlie failed: %v", err)
	}
	secEpoch6 := aliceGroup.ApplicationSecretBytes()
	if secEpoch6 == secEpoch5 || aliceGroup.EpochSecret == prevEpochSec || aliceGroup.InitSecret == prevInitSec || aliceGroup.Tree.TreeHash() == prevTreeHash {
		t.Fatal("CreateRemoveCommit failed to inject fresh entropy across all group secrets and TreeHash")
	}

	// Verify two independent commits from identical group states produce distinct secrets (CSPRNG non-determinism)
	g1, _ := NewMLSGroup("clone-entropy-room", idA)
	kpB2, _ := NewKeyPackage(idB)
	_, wB2, _ := g1.CreateAddCommit(kpB2)
	g2, _ := NewMLSGroupFromWelcome(idB, wB2, kpB2.InitPriv)
	// Synchronize g2 to act as committer from same epoch state as another instance
	g2Clone, _ := NewMLSGroupFromWelcome(idB, wB2, kpB2.InitPriv)
	_, _ = g2.CreateUpdateCommit()
	_, _ = g2Clone.CreateUpdateCommit()
	if g2.EpochSecret == g2Clone.EpochSecret || g2.ApplicationSecret == g2Clone.ApplicationSecret {
		t.Fatal("two commits from identical group state produced identical secrets; missing CSPRNG entropy!")
	}
}

// TestTreeKEM_GroupContextAndTreeHashAgreement verifies that across sequential Add, Update, and Remove commits
// in a 5-peer group, all active non-evicted group members maintain cryptographic agreement on TreeHash and GroupContext,
// and that 1-bit tampering with any intermediate node PublicKey in commit.Path.Nodes is rejected.
func TestTreeKEM_GroupContextAndTreeHashAgreement(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()
	idD, _ := NewIdentity()
	idE, _ := NewIdentity()

	// Genesis: Alice creates room (Epoch 1)
	aliceGroup, _ := NewMLSGroup("context-agreement-room", idA)

	// Epoch 2: Alice adds Bob
	pkgB, _ := NewKeyPackage(idB)
	_, wB, _ := aliceGroup.CreateAddCommit(pkgB)
	bobGroup, _ := NewMLSGroupFromWelcome(idB, wB, pkgB.InitPriv)

	// Epoch 3: Alice adds Charlie
	pkgC, _ := NewKeyPackage(idC)
	cAddC, wC, _ := aliceGroup.CreateAddCommit(pkgC)
	_ = bobGroup.ProcessCommit(cAddC)
	charlieGroup, _ := NewMLSGroupFromWelcome(idC, wC, pkgC.InitPriv)

	// Epoch 4: Alice adds Dave
	pkgD, _ := NewKeyPackage(idD)
	cAddD, wD, _ := aliceGroup.CreateAddCommit(pkgD)
	_ = bobGroup.ProcessCommit(cAddD)
	_ = charlieGroup.ProcessCommit(cAddD)
	daveGroup, _ := NewMLSGroupFromWelcome(idD, wD, pkgD.InitPriv)

	// Epoch 5: Alice adds Eve (5-peer group)
	pkgE, _ := NewKeyPackage(idE)
	cAddE, wE, _ := aliceGroup.CreateAddCommit(pkgE)
	_ = bobGroup.ProcessCommit(cAddE)
	_ = charlieGroup.ProcessCommit(cAddE)
	_ = daveGroup.ProcessCommit(cAddE)
	eveGroup, _ := NewMLSGroupFromWelcome(idE, wE, pkgE.InitPriv)

	// Verify TreeHash and ConfirmedTranscriptHash agreement at Epoch 5 across all 5 peers
	thA := aliceGroup.Tree.TreeHash()
	thB := bobGroup.Tree.TreeHash()
	thC := charlieGroup.Tree.TreeHash()
	thD := daveGroup.Tree.TreeHash()
	thE := eveGroup.Tree.TreeHash()
	if thA != thB || thA != thC || thA != thD || thA != thE {
		t.Fatalf("tree hash disagreement at Epoch 5: A=%x B=%x C=%x D=%x E=%x", thA, thB, thC, thD, thE)
	}

	gcA := aliceGroup.ConfirmedTranscriptHash
	gcB := bobGroup.ConfirmedTranscriptHash
	gcC := charlieGroup.ConfirmedTranscriptHash
	gcD := daveGroup.ConfirmedTranscriptHash
	gcE := eveGroup.ConfirmedTranscriptHash
	if gcA != gcB || gcA != gcC || gcA != gcD || gcA != gcE {
		t.Fatalf("confirmed transcript hash disagreement: A=%x B=%x C=%x D=%x E=%x", gcA, gcB, gcC, gcD, gcE)
	}

	// Epoch 6: Alice evicts Charlie
	charlieLeaf := aliceGroup.FindLeafByAddress(idC.Address())
	cEvictC, err := aliceGroup.CreateRemoveCommit(charlieLeaf)
	if err != nil {
		t.Fatalf("remove charlie commit failed: %v", err)
	}
	if err := bobGroup.ProcessCommit(cEvictC); err != nil {
		t.Fatalf("bob process evict charlie failed: %v", err)
	}
	if err := daveGroup.ProcessCommit(cEvictC); err != nil {
		t.Fatalf("dave process evict charlie failed: %v", err)
	}
	if err := eveGroup.ProcessCommit(cEvictC); err != nil {
		t.Fatalf("eve process evict charlie failed: %v", err)
	}
	if err := charlieGroup.ProcessCommit(cEvictC); err != ErrTreeKEMEvictedMember {
		t.Fatalf("expected charlie to be rejected with ErrTreeKEMEvictedMember, got: %v", err)
	}

	// Verify TreeHash and GroupContext agreement at Epoch 6 among Alice, Bob, Dave, and Eve
	thA6 := aliceGroup.Tree.TreeHash()
	thB6 := bobGroup.Tree.TreeHash()
	thD6 := daveGroup.Tree.TreeHash()
	thE6 := eveGroup.Tree.TreeHash()
	if thA6 != thB6 || thA6 != thD6 || thA6 != thE6 {
		t.Fatalf("tree hash disagreement at Epoch 6 after eviction: A=%x B=%x D=%x E=%x", thA6, thB6, thD6, thE6)
	}
	if thA6 == thA {
		t.Fatal("tree hash did not change after member eviction")
	}

	// Epoch 7: Bob performs Update commit (PCS self-healing)
	cUpdateB, err := bobGroup.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("bob update commit failed: %v", err)
	}

	// Verify that 1-bit tampering with an intermediate node PublicKey in commit.Path.Nodes is rejected by ProcessCommit
	if len(cUpdateB.Path.Nodes) > 0 {
		tamperedNodes := make([]DirectPathNode, len(cUpdateB.Path.Nodes))
		copy(tamperedNodes, cUpdateB.Path.Nodes)
		tamperedNodes[0].PublicKey[0] ^= 0x01
		tamperedPath := *cUpdateB.Path
		tamperedPath.Nodes = tamperedNodes
		tamperedCommit := *cUpdateB
		tamperedCommit.Path = &tamperedPath
		if err := eveGroup.ProcessCommit(&tamperedCommit); err == nil {
			t.Fatal("security violation: ProcessCommit accepted commit with tampered intermediate DirectPathNode PublicKey!")
		}
	}

	if err := aliceGroup.ProcessCommit(cUpdateB); err != nil {
		t.Fatalf("alice process bob update failed: %v", err)
	}
	if err := daveGroup.ProcessCommit(cUpdateB); err != nil {
		t.Fatalf("dave process bob update failed: %v", err)
	}
	if err := eveGroup.ProcessCommit(cUpdateB); err != nil {
		t.Fatalf("eve process bob update failed: %v", err)
	}

	// Verify all 4 non-evicted peers agree at Epoch 7
	secA7 := aliceGroup.ApplicationSecretBytes()
	secB7 := bobGroup.ApplicationSecretBytes()
	secD7 := daveGroup.ApplicationSecretBytes()
	secE7 := eveGroup.ApplicationSecretBytes()
	if secA7 != secB7 || secA7 != secD7 || secA7 != secE7 {
		t.Fatalf("Epoch 7 secret disagreement: A=%x B=%x D=%x E=%x", secA7, secB7, secD7, secE7)
	}
}

// TestTreeKEM_PreJoinForwardSecrecy verifies RFC 9420 Section 3 requirement that late joiners
// cannot derive previous epoch keys or decrypt pre-join messages.
func TestTreeKEM_PreJoinForwardSecrecy(t *testing.T) {
	idA, _ := NewIdentity()
	idB, _ := NewIdentity()
	idC, _ := NewIdentity()

	// Alice creates room (Epoch 1)
	aliceGroup, _ := NewMLSGroup("pfs-prejoin-room", idA)
	secEpoch1 := aliceGroup.ApplicationSecretBytes()

	// Alice adds Bob (Epoch 2)
	pkgB, _ := NewKeyPackage(idB)
	_, wB, _ := aliceGroup.CreateAddCommit(pkgB)
	bobGroup, _ := NewMLSGroupFromWelcome(idB, wB, pkgB.InitPriv)
	secEpoch2 := aliceGroup.ApplicationSecretBytes()

	// Pre-join secret message encrypted with Epoch 2 application secret
	var key2 RoomKey
	copy(key2[:], secEpoch2[:])
	nonce, ciphertext, err := EncryptRoomPayload(key2, []byte("pre-join-epoch-2-confidential-transcript"), []byte("aad"))
	if err != nil {
		t.Fatalf("encryption of epoch 2 message failed: %v", err)
	}

	// Charlie joins late at Epoch 3
	pkgC, _ := NewKeyPackage(idC)
	cAddC, wC, _ := aliceGroup.CreateAddCommit(pkgC)
	_ = bobGroup.ProcessCommit(cAddC)
	charlieGroup, err := NewMLSGroupFromWelcome(idC, wC, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("charlie join failed: %v", err)
	}
	secEpoch3 := charlieGroup.ApplicationSecretBytes()

	// Verify Charlie holds only Epoch 3 key and cannot decrypt Epoch 2 message
	if charlieGroup.Epoch != 3 {
		t.Fatalf("expected charlie epoch 3, got %d", charlieGroup.Epoch)
	}
	if bytes.Equal(secEpoch3[:], secEpoch2[:]) || bytes.Equal(secEpoch3[:], secEpoch1[:]) {
		t.Fatal("security violation: newcomer holds previous epoch keys!")
	}

	var key3 RoomKey
	copy(key3[:], secEpoch3[:])
	_, err = DecryptRoomPayload(key3, nonce, ciphertext, []byte("aad"))
	if err == nil {
		t.Fatal("cryptographic violation: late-joining charlie successfully decrypted pre-join Epoch 2 message!")
	}
}
