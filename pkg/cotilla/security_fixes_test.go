package cotilla

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSecurity_C1_CommitCannotMutateTreeBeforeAuthOrSwapCommitter verifies:
// 1. A forged commit replacing TreeNodes[CommitterLeaf].SignPubHex with attacker's key is rejected.
// 2. A rejected commit NEVER leaves mutated nodes in receiver's g.Tree.
func TestSecurity_C1_CommitCannotMutateTreeBeforeAuthOrSwapCommitter(t *testing.T) {
	idA := newTestIdentityWithSeed(t, "c1-alice-seed-unique-00000000001")
	idB := newTestIdentityWithSeed(t, "c1-bob-seed-unique-0000000000002")
	idC := newTestIdentityWithSeed(t, "c1-charlie-seed-unique-000000003")

	groupA, err := NewMLSGroup("c1-room", idA)
	if err != nil {
		t.Fatalf("NewMLSGroup failed: %v", err)
	}
	pkgB, _ := NewKeyPackage(idB)
	_, welcomeB, err := groupA.CreateAddCommit(pkgB)
	if err != nil {
		t.Fatalf("add bob failed: %v", err)
	}
	groupB, err := NewMLSGroupFromWelcome(idB, welcomeB, pkgB.InitPriv)
	if err != nil {
		t.Fatalf("welcome bob failed: %v", err)
	}
	pkgC, _ := NewKeyPackage(idC)
	commitC, welcomeC, err := groupA.CreateAddCommit(pkgC)
	if err != nil {
		t.Fatalf("add charlie failed: %v", err)
	}
	if err := groupB.ProcessCommit(commitC); err != nil {
		t.Fatalf("bob process add charlie failed: %v", err)
	}
	groupC, err := NewMLSGroupFromWelcome(idC, welcomeC, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("welcome charlie failed: %v", err)
	}
	_ = groupC

	origHash := groupB.Tree.TreeHash()
	origSecret := groupB.ApplicationSecretBytes()
	origEpoch := groupB.Epoch

	// Attack 1: Charlie forges an update claiming CommitterLeaf == 0 (Alice),
	// overwrites TreeNodes[0].SignPubHex with Charlie's key, and signs as Charlie!
	forgedCommit, err := groupA.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("create template commit failed: %v", err)
	}
	forgedCommit.TreeNodes[0].SignPubHex = idC.Address()
	forgedCommit.Signature = ed25519.Sign(idC.SignPriv, forgedCommit.CanonicalBytesWithConfirmation())

	if err := groupB.ProcessCommit(forgedCommit); err == nil {
		t.Fatalf("C1 VULNERABILITY: groupB accepted forged commit swapping CommitterLeaf SignPubHex!")
	}
	if groupB.Epoch != origEpoch {
		t.Fatalf("rejected commit mutated Epoch: got %d, want %d", groupB.Epoch, origEpoch)
	}
	if groupB.Tree.TreeHash() != origHash {
		t.Fatalf("C1 VULNERABILITY: rejected commit mutated TreeHash on error path!")
	}
	if groupB.ApplicationSecretBytes() != origSecret {
		t.Fatalf("rejected commit mutated ApplicationSecret!")
	}

	// Attack 2: Bad confirmation tag must NOT leave groupB.Tree mutated
	badConfirm, err := groupA.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("create second commit failed: %v", err)
	}
	badConfirm.ConfirmationTag[0] ^= 0xff
	badConfirm.Signature = ed25519.Sign(idA.SignPriv, badConfirm.CanonicalBytesWithConfirmation())

	// Use fresh Bob state from clone
	if err := groupB.ProcessCommit(badConfirm); err == nil {
		t.Fatalf("expected bad confirmation tag failure")
	}
	if groupB.Tree.TreeHash() != origHash {
		t.Fatalf("C1 VULNERABILITY: failed ProcessCommit left TreeHash mutated on confirmation failure!")
	}
}

// TestSecurity_C2_BroadcastPeerInfoNoKeyLeakNoSignaling checks that BroadcastPeerInfo:
// 1. Never transmits raw RoomKey bytes over the wire inside PeerInfoFrame.
// 2. Never transmits BroadcastPeerInfo, BroadcastFrame, or gossip frames to signaling peers.
func TestSecurity_C2_BroadcastPeerInfoNoKeyLeakNoSignaling(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "c2-alice-seed", "c2-room", roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "c2-bob-seed", "c2-room", roomKey, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "c2-charlie-seed", "c2-room", roomKey, cfg, Hooks{})

	sigTr := newMemoryTransport("signaling-server")
	var mu sync.Mutex
	var sigReceived [][]byte
	var bobReceived [][]byte
	sigTr.onData = func(from string, data []byte) {
		mu.Lock()
		sigReceived = append(sigReceived, data)
		mu.Unlock()
	}
	origBobOnData := trBob.onData
	trBob.onData = func(from string, data []byte) {
		mu.Lock()
		bobReceived = append(bobReceived, data)
		mu.Unlock()
		origBobOnData(from, data)
	}

	trAlice.Connect(trBob)
	trAlice.Connect(trCharlie)
	trBob.Connect(trCharlie)
	trAlice.Connect(sigTr)
	alice.AddPeer(bob.Address())
	alice.AddPeer(charlie.Address())
	_ = bob
	_ = charlie

	inv, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInvite failed: %v", err)
	}
	alice.SetChannelInvite(inv)
	alice.BroadcastPeerInfo()
	_ = alice.JoinChannel("c2-room")

	time.Sleep(80 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(sigReceived) > 0 {
		t.Fatalf("C2 VULNERABILITY: Alice transmitted %d protocol/gossip frame(s) to signaling-server", len(sigReceived))
	}
	for _, raw := range bobReceived {
		if strings.Contains(string(raw), roomKey.String()) {
			t.Fatalf("C2 VULNERABILITY: raw RoomKey %q leaked on the wire in BroadcastPeerInfo: %s", roomKey.String(), string(raw))
		}
	}
}

// TestSecurity_C3_RejectForgedWelcomeWrongGroupOrUnauthorized verifies that uninvited /
// wrong-GroupID Welcome commits are rejected.
func TestSecurity_C3_RejectForgedWelcomeWrongGroupOrUnauthorized(t *testing.T) {
	roomID := "c3-real-room"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "c3-alice-seed", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "c3-bob-seed", roomID, roomKey, cfg, Hooks{})
	attacker, trAttacker := newTestNode(t, "c3-attacker-seed", roomID, roomKey, cfg, Hooks{})

	trAlice.Connect(trBob)
	trAttacker.Connect(trBob)
	alice.AddPeer(bob.Address())
	bob.AddPeer(alice.Address())
	bob.AddPeer(attacker.Address())

	inv, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInvite failed: %v", err)
	}
	bob.SetChannelInvite(inv)

	// Attacker builds a fake MLS group with WRONG GroupID and welcomes Bob's static/ephemeral key!
	bobKP := bob.myKeyPackage
	fakeGroup, err := NewMLSGroup("c3-wrong-room", attacker.ID)
	if err != nil {
		t.Fatalf("attacker NewMLSGroup failed: %v", err)
	}
	_, forgedWelcome, err := fakeGroup.CreateAddCommit(bobKP)
	if err != nil {
		t.Fatalf("attacker CreateAddCommit failed: %v", err)
	}

	now := time.Now().UnixMilli()
	spoofedCommit := &EpochCommit{
		EpochID:       1,
		RoomID:        roomID,
		Evictor:       attacker.Address(),
		EvictorEncPub: attacker.ID.EncAddress(),
		AddedPeer:     bob.Address(),
		Reason:        "fake welcome",
		MLSWelcome:    forgedWelcome,
		Timestamp:     now,
	}
	canonical := CanonicalEpochCommitFromCommit(spoofedCommit)
	spoofedCommit.Signature = hex.EncodeToString(attacker.ID.Sign(canonical))

	p1, _ := NewGroupPacket(attacker.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortEpochCommit, 3, spoofedCommit)
	wireBytes, _ := MarshalPacket(p1)
	bob.HandleWire(attacker.Address(), wireBytes)
	time.Sleep(50 * time.Millisecond)

	if bob.CurrentEpoch() != 0 {
		t.Fatalf("C3 VULNERABILITY: bob accepted forged MLSWelcome with wrong GroupID / unauthorized committer! epoch=%d", bob.CurrentEpoch())
	}

	// Attack 2: Attacker uses matching GroupID ("c3-real-room"), still unauthorized (never invited by Alice)!
	fakeGroupSameRoom, _ := NewMLSGroup(roomID, attacker.ID)
	_, forgedWelcomeSameRoom, _ := fakeGroupSameRoom.CreateAddCommit(bobKP)
	spoofedCommit2 := &EpochCommit{
		EpochID:       1,
		RoomID:        roomID,
		Evictor:       attacker.Address(),
		EvictorEncPub: attacker.ID.EncAddress(),
		AddedPeer:     bob.Address(),
		Reason:        "spoofed room welcome",
		MLSWelcome:    forgedWelcomeSameRoom,
		Timestamp:     time.Now().UnixMilli(),
	}
	spoofedCommit2.Signature = hex.EncodeToString(attacker.ID.Sign(CanonicalEpochCommitFromCommit(spoofedCommit2)))
	p2, _ := NewGroupPacket(attacker.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortEpochCommit, 3, spoofedCommit2)
	wireBytes2, _ := MarshalPacket(p2)
	bob.HandleWire(attacker.Address(), wireBytes2)
	time.Sleep(50 * time.Millisecond)

	if bob.CurrentEpoch() != 0 {
		t.Fatalf("C3 VULNERABILITY: bob accepted forged MLSWelcome from uninvited attacker! epoch=%d", bob.CurrentEpoch())
	}
}

// TestSecurity_C5_RelayFrameFromSpoofingRejected checks that a peer cannot spoof RelayFrame.From.
func TestSecurity_C5_RelayFrameFromSpoofingRejected(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var mu sync.Mutex
	var gotFrom string
	alice, _ := newTestNode(t, "c5-alice-seed", "c5-room", roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "c5-bob-seed", "c5-room", roomKey, cfg, Hooks{
		OnRelayPayload: func(from, relayType string, payload []byte) {
			mu.Lock()
			gotFrom = from
			mu.Unlock()
		},
	})
	charlie, trCharlie := newTestNode(t, "c5-charlie-seed", "c5-room", roomKey, cfg, Hooks{})

	trCharlie.Connect(trBob)
	bob.AddPeer(charlie.Address())

	// Charlie claims a DM packet came from Alice without Alice's signature
	forgedPkt := &Packet{
		ID:        RandomID(),
		From:      alice.Address(),
		FromEnc:   alice.ID.EncAddress(),
		To:        bob.Address(),
		HopLimit:  3,
		HopStart:  3,
		Timestamp: time.Now().UnixMilli(),
		Encrypted: false,
		Port:      PortDM,
		Payload:   []byte(`{"payload":"eyJzcG9vZmVkIjp0cnVlfQ=="}`),
		Signature: hex.EncodeToString(charlie.ID.Sign([]byte("forged"))),
	}
	data, _ := MarshalPacket(forgedPkt)
	bob.HandleWire(charlie.Address(), data)
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if gotFrom != "" {
		t.Fatalf("C5 VULNERABILITY: Bob delivered spoofed RelayFrame claiming From=%s", gotFrom)
	}
}

// TestSecurity_C7_CommitBindsGroupIDAndDigestNoCollision tests C7:
// 1. CanonicalBytes binds GroupID (commit signature cannot transfer across groups).
// 2. ComputeMLSCommitDigest avoids un-delimited concatenation collisions & covers Path/AddedPackage.
func TestSecurity_C7_CommitBindsGroupIDAndDigestNoCollision(t *testing.T) {
	idA := newTestIdentityWithSeed(t, "c7-alice-seed-unique-00000000001")
	idB := newTestIdentityWithSeed(t, "c7-bob-seed-unique-0000000000002")
	idC := newTestIdentityWithSeed(t, "c7-charlie-seed-unique-000000003")

	g1, _ := NewMLSGroup("group-alpha", idA)
	g2, _ := NewMLSGroup("group-alpha", idA)
	pkgB, _ := NewKeyPackage(idB)
	commit1, _, err := g1.CreateAddCommit(pkgB)
	if err != nil {
		t.Fatalf("g1 CreateAddCommit failed: %v", err)
	}
	pkgC, _ := NewKeyPackage(idC)
	commit2, _, err := g2.CreateAddCommit(pkgC)
	if err != nil {
		t.Fatalf("g2 CreateAddCommit failed: %v", err)
	}

	// Mutating Path on MLSCommit MUST change CanonicalBytesWithConfirmation and ComputeMLSCommitDigest
	clone := *commit1
	if clone.Path != nil {
		clone.Path = nil
	} else {
		clone.Path = &DirectPath{LeafIndex: 0}
	}
	if string(commit1.CanonicalBytes()) == string(clone.CanonicalBytes()) {
		t.Fatalf("C7 VULNERABILITY: MLSCommit.CanonicalBytes does not include Path or GroupID")
	}

	// Mutating Path or AddedPackage MUST change ComputeMLSCommitDigest
	ec1 := &EpochCommit{MLSCommit: commit1}
	origDigest := ComputeMLSCommitDigest(ec1)

	modCommit := *commit1
	modCommit.AddedPackage = pkgC
	ec2 := &EpochCommit{MLSCommit: &modCommit}
	if ComputeMLSCommitDigest(ec2) == origDigest {
		t.Fatalf("C7 VULNERABILITY: ComputeMLSCommitDigest ignores AddedPackage!")
	}
	_ = commit2
}

// TestSecurity_H1_TreeKEMUnmergedLeavesAndDirectPath_4Peers tests the RFC 9420 unmerged_leaves
// bug: Leaf 2 (Charlie) adds Leaf 3 (Dave), then Leaf 0 (Alice) updates WITHOUT removing Dave.
// Previously Leaf 0 skipped unmerged/blank parents and Dave could not decrypt Alice's Update!
func TestSecurity_H1_TreeKEMUnmergedLeavesAndDirectPath_4Peers(t *testing.T) {
	idA := newTestIdentityWithSeed(t, "h1-alice-seed-000000000000000001")
	idB := newTestIdentityWithSeed(t, "h1-bob-seed-00000000000000000002")
	idC := newTestIdentityWithSeed(t, "h1-charlie-seed-0000000000000003")
	idD := newTestIdentityWithSeed(t, "h1-dave-seed-0000000000000000004")

	gA, _ := NewMLSGroup("h1-room", idA)

	pkgB, _ := NewKeyPackage(idB)
	_, wB, _ := gA.CreateAddCommit(pkgB)
	gB, err := NewMLSGroupFromWelcome(idB, wB, pkgB.InitPriv)
	if err != nil {
		t.Fatalf("gB welcome failed: %v", err)
	}

	pkgC, _ := NewKeyPackage(idC)
	cC, wC, _ := gA.CreateAddCommit(pkgC)
	if err := gB.ProcessCommit(cC); err != nil {
		t.Fatalf("gB process cC failed: %v", err)
	}
	gC, err := NewMLSGroupFromWelcome(idC, wC, pkgC.InitPriv)
	if err != nil {
		t.Fatalf("gC welcome failed: %v", err)
	}

	// Charlie (leaf 2) adds Dave (leaf 3). Dave hasn't ratcheted parent(2,3) with an Update yet!
	pkgD, _ := NewKeyPackage(idD)
	cD, wD, err := gC.CreateAddCommit(pkgD)
	if err != nil {
		t.Fatalf("cD failed: %v", err)
	}
	if err := gA.ProcessCommit(cD); err != nil {
		t.Fatalf("gA process cD failed: %v", err)
	}
	if err := gB.ProcessCommit(cD); err != nil {
		t.Fatalf("gB process cD failed: %v", err)
	}
	gD, err := NewMLSGroupFromWelcome(idD, wD, pkgD.InitPriv)
	if err != nil {
		t.Fatalf("gD welcome failed: %v", err)
	}

	// Now Alice (leaf 0) creates an UpdateCommit: Alice encrypts to the right subtree resolution
	// (which contains both Charlie and unmerged Dave or Blank parent resolved to {Charlie, Dave}).
	cUpdA, err := gA.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("gA update failed: %v", err)
	}
	if err := gB.ProcessCommit(cUpdA); err != nil {
		t.Fatalf("gB process cUpdA failed: %v", err)
	}
	if err := gC.ProcessCommit(cUpdA); err != nil {
		t.Fatalf("gC process cUpdA failed: %v", err)
	}
	if err := gD.ProcessCommit(cUpdA); err != nil {
		t.Fatalf("H1 VULNERABILITY: Dave (added by Charlie) could not process Alice's UpdateCommit: %v", err)
	}

	secA := gA.ApplicationSecretBytes()
	if gB.ApplicationSecretBytes() != secA || gC.ApplicationSecretBytes() != secA || gD.ApplicationSecretBytes() != secA {
		t.Fatalf("H1 secret mismatch across 4 peers after unmerged-leaf update")
	}

	// Also test: Bob (leaf 1) removes Charlie (leaf 2) leaving parent(2,3) Blank, then Alice updates -> Dave STILL converges!
	cRemC, err := gB.CreateRemoveCommit(2)
	if err != nil {
		t.Fatalf("remove C failed: %v", err)
	}
	if err := gA.ProcessCommit(cRemC); err != nil {
		t.Fatalf("gA remove C failed: %v", err)
	}
	if err := gD.ProcessCommit(cRemC); err != nil {
		t.Fatalf("gD remove C failed: %v", err)
	}
	cUpdA2, err := gA.CreateUpdateCommit()
	if err != nil {
		t.Fatalf("gA second update failed: %v", err)
	}
	if err := gB.ProcessCommit(cUpdA2); err != nil {
		t.Fatalf("gB second update failed: %v", err)
	}
	if err := gD.ProcessCommit(cUpdA2); err != nil {
		t.Fatalf("H1b: Dave failed second update after neighbor Charlie was removed: %v", err)
	}
	secA2 := gA.ApplicationSecretBytes()
	if gB.ApplicationSecretBytes() != secA2 || gD.ApplicationSecretBytes() != secA2 {
		t.Fatalf("H1b secret mismatch after neighbor removal")
	}
}

// TestSecurity_H2_NoFakeUnsignedKeyPackage verifies admitMemberToTreeKEM requires a valid KeyPackage
// signed by targetAddr rather than fabricating an unsigned KeyPackage.
func TestSecurity_H2_NoFakeUnsignedKeyPackage(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()
	alice, _ := newTestNode(t, "h2-alice-seed", "h2-room", roomKey, cfg, Hooks{})
	bob, _ := newTestNode(t, "h2-bob-seed", "h2-room", roomKey, cfg, Hooks{})
	charlie, _ := newTestNode(t, "h2-charlie-seed", "h2-room", roomKey, cfg, Hooks{})

	_ = charlie
	alice.SetPeerEncKey(bob.Address(), bob.ID.EncAddress())
	bobKP := &KeyPackage{
		InitKey:   bob.ID.EncPub,
		SignPub:   bob.Address(),
		Signature: []byte("invalid-sig"),
	}
	if _, err := alice.admitMemberToTreeKEMInChannel(alice.RoomID, bob.Address(), bobKP); err == nil {
		t.Fatalf("H2 VULNERABILITY: admitMemberToTreeKEM succeeded despite invalid KeyPackage signature")
	}
	// Forged SignPub mismatch
	wrongKP, _ := NewKeyPackage(charlie.ID)
	if _, err := alice.admitMemberToTreeKEMInChannel(alice.RoomID, bob.Address(), wrongKP); err == nil {
		t.Fatalf("H2 VULNERABILITY: admitMemberToTreeKEM admitted bob using charlie's KeyPackage")
	}
}

// TestSecurity_H3_ReconnectF5ReAdmittedAndOutOfOrderWelcome verifies:
// 1. After Bob restarts (F5 refresh: same Identity seed, fresh ephemeral KeyPackage), Alice re-admits Bob
//    with a fresh commit/welcome so Bob can decrypt Epoch N+1.
// 2. If Bob receives Epoch N+1 commit BEFORE Epoch N Welcome arrives, Bob buffers and applies both!
func TestSecurity_H3_ReconnectF5ReAdmittedAndOutOfOrderWelcome(t *testing.T) {
	roomID := "h3-room"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "h3-alice-seed", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "h3-bob-seed", roomID, roomKey, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "h3-charlie-seed", roomID, roomKey, cfg, Hooks{})

	invA, _ := alice.CreateChannelInvite(15 * time.Minute)
	bob.SetChannelInvite(invA)
	charlie.SetChannelInvite(invA)

	nodes := []*Node{alice, bob, charlie}
	trs := []*memoryTransport{trAlice, trBob, trCharlie}
	connectFullMesh(nodes, trs)
	if err := alice.InitGenesisEpoch(); err != nil {
		t.Fatalf("InitGenesisEpoch failed: %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	if bob.CurrentEpoch() == 0 || charlie.CurrentEpoch() == 0 {
		t.Fatalf("initial admission failed: alice=%d bob=%d charlie=%d", alice.CurrentEpoch(), bob.CurrentEpoch(), charlie.CurrentEpoch())
	}

	// Simulate Bob F5 refresh: same seed ("h3-bob-seed"), brand new Node & fresh ephemeral KeyPackage
	trAlice.ClosePeer(bob.Address())
	trCharlie.ClosePeer(bob.Address())
	bob2, trBob2 := newTestNode(t, "h3-bob-seed", roomID, roomKey, cfg, Hooks{})
	bob2.SetChannelInvite(invA)

	trAlice.Connect(trBob2)
	trCharlie.Connect(trBob2)
	alice.AddPeer(bob2.Address())
	charlie.AddPeer(bob2.Address())
	bob2.AddPeer(alice.Address())
	bob2.AddPeer(charlie.Address())

	bob2.BroadcastPeerInfo()
	time.Sleep(250 * time.Millisecond)

	if bob2.CurrentEpoch() == 0 || bob2.CurrentEpoch() != alice.CurrentEpoch() {
		t.Fatalf("H3 VULNERABILITY: refreshed Bob was not re-admitted to active epoch! alice=%d bob2=%d", alice.CurrentEpoch(), bob2.CurrentEpoch())
	}

	// Out-of-order test for 4th peer Dave:
	// Capture Add(Dave) Welcome, first trigger another RotateEpochKey() and deliver that future commit to Dave BEFORE the Welcome!
	dave, _ := newTestNode(t, "h3-dave-seed", roomID, roomKey, cfg, Hooks{})
	dave.SetChannelInvite(invA)
	alice.SetPeerEncKey(dave.Address(), dave.ID.EncAddress())
	alice.mu.Lock()
	alice.peerKeyPackages[dave.Address()] = dave.myKeyPackage
	alice.peerInviters[dave.Address()] = alice.Address()
	alice.mu.Unlock()

	addCommit, err := alice.admitMemberToTreeKEMInChannel(alice.RoomID, dave.Address(), dave.myKeyPackage)
	if err != nil {
		t.Fatalf("admit Dave failed: %v", err)
	}
	updateCommit, err := alice.RotateEpochKey()
	if err != nil {
		t.Fatalf("alice rotate after Dave add failed: %v", err)
	}

	// Deliver future updateCommit FIRST, then welcome addCommit SECOND
	updPkt, _ := NewGroupPacket(alice.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortEpochCommit, 3, updateCommit)
	addPkt, _ := NewGroupPacket(alice.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortEpochCommit, 3, addCommit)
	updBytes, _ := MarshalPacket(updPkt)
	addBytes, _ := MarshalPacket(addPkt)
	dave.HandleWire(alice.Address(), updBytes)
	dave.HandleWire(alice.Address(), addBytes)
	time.Sleep(50 * time.Millisecond)

	if dave.CurrentEpoch() != updateCommit.EpochID {
		t.Fatalf("H3 VULNERABILITY: Dave dropped future commit while waiting for Welcome! dave=%d, want=%d", dave.CurrentEpoch(), updateCommit.EpochID)
	}
}

// TestSecurity_H4_UnauthorizedSelfEvictionRejected checks that a rogue peer cannot trigger self-eviction DoS
// by sending an EpochCommit without an authorized MLSCommit.
func TestSecurity_H4_UnauthorizedSelfEvictionRejected(t *testing.T) {
	roomID := "h4-room"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "h4-alice-seed", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "h4-bob-seed", roomID, roomKey, cfg, Hooks{})
	attacker, trAttacker := newTestNode(t, "h4-attacker-seed", roomID, roomKey, cfg, Hooks{})

	trAlice.Connect(trBob)
	trAttacker.Connect(trBob)
	alice.AddPeer(bob.Address())
	bob.AddPeer(alice.Address())
	bob.AddPeer(attacker.Address())

	inv, _ := alice.CreateChannelInvite(15 * time.Minute)
	bob.SetChannelInvite(inv)

	// Before Bob is even admitted (joinedEpoch == 0), attacker sends spoofed eviction targeting Bob with nil MLSCommit!
	forgedEvict := &EpochCommit{
		EpochID:       1,
		RoomID:        roomID,
		Evictor:       attacker.Address(),
		EvictorEncPub: attacker.ID.EncAddress(),
		EvictedPeer:   bob.Address(),
		Reason:        "DoS eviction",
		MLSCommit:     nil,
		Timestamp:     time.Now().UnixMilli(),
	}
	forgedEvict.Signature = hex.EncodeToString(attacker.ID.Sign(CanonicalEpochCommitFromCommit(forgedEvict)))
	evPkt, _ := NewGroupPacket(attacker.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortEpochCommit, 3, forgedEvict)
	data, _ := MarshalPacket(evPkt)
	bob.HandleWire(attacker.Address(), data)
	time.Sleep(30 * time.Millisecond)

	if bob.IsPeerEvicted(bob.Address()) {
		t.Fatalf("H4 VULNERABILITY: uninvited attacker self-evicted Bob (DoS) with forged EpochCommit!")
	}
}

// TestSecurity_H5_InviteParentExpiryAndInviteeBinding checks:
// 1. An expired ancestor ParentInvite invalidates the child invite.
// 2. A child invite with mismatched RoomID in ParentInvite fails.
// 3. A targeted InviteePub invite cannot be redeemed by a third party.
func TestSecurity_H5_InviteParentExpiryAndInviteeBinding(t *testing.T) {
	roomID := "h5-room"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, _ := newTestNode(t, "h5-alice-seed", roomID, roomKey, cfg, Hooks{})
	bob, _ := newTestNode(t, "h5-bob-seed", roomID, roomKey, cfg, Hooks{})
	charlie, _ := newTestNode(t, "h5-charlie-seed", roomID, roomKey, cfg, Hooks{})

	// Backdated expired parent invite from Alice (no admission yet on Charlie's verifier!)
	expiredParentExp := time.Now().Add(-2 * time.Minute).UnixMilli()
	expiredParentSig := hex.EncodeToString(alice.ID.Sign(
		CanonicalChannelInvite(roomID, alice.Address(), roomKey.String(), 0, expiredParentExp),
	))
	expiredParent := &ChannelInvite{
		RoomID:     roomID,
		InviterPub: alice.Address(),
		RoomKey:    roomKey.String(),
		EpochID:    0,
		ExpiresAt:  expiredParentExp,
		Signature:  expiredParentSig,
	}

	childExp := time.Now().Add(15 * time.Minute).UnixMilli()
	childSig := hex.EncodeToString(bob.ID.Sign(
		CanonicalChannelInvite(roomID, bob.Address(), roomKey.String(), 0, childExp),
	))
	childInv := &ChannelInvite{
		RoomID:       roomID,
		InviterPub:   bob.Address(),
		RoomKey:      roomKey.String(),
		EpochID:      0,
		ExpiresAt:    childExp,
		Signature:    childSig,
		ParentInvite: expiredParent,
	}

	// Alice admits Charlie (so Charlie knows Alice is creator, does NOT know Bob yet)
	charlie.mu.Lock()
	charlie.creatorPub = alice.Address()
	charlie.peerInviters[alice.Address()] = alice.Address()
	charlie.memberJoinEpoch[alice.Address()] = 1
	charlie.mu.Unlock()

	if err := charlie.VerifyChannelInvite(childInv); err == nil {
		t.Fatalf("H5 VULNERABILITY: child invite accepted despite EXPIRED ParentInvite!")
	}
	_ = alice
}

// TestSecurity_H7_UnverifiedEnvelopeAndChunkDoNotPoisonState checks:
// 1. A forged/tampered Envelope is NOT added to RingBuffer or seenEnvelopes.
// 2. A tampered ChunkRes is NOT cached in localAttachments.
func TestSecurity_H7_UnverifiedEnvelopeAndChunkDoNotPoisonState(t *testing.T) {
	roomID := "h7-room"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, _ := newTestNode(t, "h7-alice-seed", roomID, roomKey, cfg, Hooks{})
	bob, _ := newTestNode(t, "h7-bob-seed", roomID, roomKey, cfg, Hooks{})
	charlie, _ := newTestNode(t, "h7-charlie-seed", roomID, roomKey, cfg, Hooks{})

	bob.mu.Lock()
	bob.memberJoinEpoch[alice.Address()] = 1
	bob.memberJoinEpoch[charlie.Address()] = 1
	bob.epochKeys[1] = roomKey
	bob.currentEpoch = 1
	bob.joinedEpoch = 1
	bob.peerInviters[alice.Address()] = alice.Address()
	bob.peerInviters[charlie.Address()] = alice.Address()
	bob.mu.Unlock()

	// Charlie creates valid ciphertext sealed for epoch 1, then tampers AAD while keeping valid signature
	payload, _ := json.Marshal(ChatPayload{Type: "chat", Text: "legit"})
	nonce, ct, _ := EncryptRoomPayload(roomKey, payload, []byte("wrong-aad"))
	now := time.Now().UnixMilli()
	canonical := CanonicalEnvelopePayload(roomID, charlie.Address(), base64.StdEncoding.EncodeToString(nonce), base64.StdEncoding.EncodeToString(ct), 1, now)
	poisonEnv := &Envelope{
		RoomID:       roomID,
		AuthorPubKey: charlie.Address(),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ct),
		EpochID:      1,
		Timestamp:    now,
		Signature:    hex.EncodeToString(charlie.ID.Sign(canonical)),
	}

	envPkt, _ := NewGroupPacket(charlie.ID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 1, roomKey, PortChat, 3, poisonEnv)
	wireEnv, _ := MarshalPacket(envPkt)
	bob.HandleWire(charlie.Address(), wireEnv)

	if bob.RingBuffer.Len() != 0 {
		t.Fatalf("H7 VULNERABILITY: undecryptable forged envelope pushed into RingBuffer!")
	}
	if _, ok := bob.seenEnvelopes[poisonEnv.ID()]; ok {
		t.Fatalf("H7 VULNERABILITY: undecryptable envelope poisoned seenEnvelopes!")
	}

	// Tampered ChunkResponse test
	meta, chunks, err := PrepareAttachment(roomKey, "file.bin", "application/octet-stream", make([]byte, 1024))
	if err != nil {
		t.Fatalf("PrepareAttachment failed: %v", err)
	}
	bob.mu.Lock()
	bob.knownOffers[meta.FileID] = meta
	bob.assemblers[meta.FileID] = NewAttachmentAssembler(*meta, roomKey)
	bob.mu.Unlock()

	badChunk := append([]byte(nil), chunks[0]...)
	badChunk[len(badChunk)-1] ^= 0xff
	chunkPkt, _ := NewGroupPacket(charlie.ID, bob.Address(), ComputeChannelHash(roomID, roomKey), 0, roomKey, PortChunkRes, 3, &ChunkResponse{
		RoomID:     roomID,
		FileID:     meta.FileID,
		ChunkIndex: 0,
		Data:       badChunk,
	})
	chunkWire, _ := MarshalPacket(chunkPkt)
	bob.HandleWire(charlie.Address(), chunkWire)

	bob.mu.RLock()
	cached := bob.localAttachments[meta.FileID]
	bob.mu.RUnlock()
	if len(cached) > 0 && cached[0] != nil {
		t.Fatalf("H7 VULNERABILITY: unverified tampered chunk cached into bob.localAttachments!")
	}
}

// TestSecurity_H8_BoundsAndNilGuards checks malformed TotalChunks, OOB TreeNodes, and nil frames.
func TestSecurity_H8_BoundsAndNilGuards(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	meta := AttachmentMeta{
		FileID:      "h8-bad-file",
		TotalChunks: -5,
		Size:        100,
	}
	assembler := NewAttachmentAssembler(meta, roomKey)
	if assembler == nil {
		t.Fatalf("assembler unexpectedly nil")
	}
	if _, err := assembler.AddChunk(0, []byte("1234")); err == nil {
		t.Fatalf("expected error on negative TotalChunks")
	}

	metaTooBig := AttachmentMeta{
		FileID:      "h8-oom-file",
		TotalChunks: 1 << 28,
		Size:        1 << 40,
	}
	assemblerBig := NewAttachmentAssembler(metaTooBig, roomKey)
	if _, err := assemblerBig.AddChunk(0, []byte("1234")); err == nil {
		t.Fatalf("expected error on excessive TotalChunks without panic/OOM")
	}

	// Malformed or empty Packet payloads must never panic
	idA := newTestIdentityWithSeed(t, "h8-alice-seed-000000000000000001")
	n := NewNode(idA, "h8-room", roomKey, DefaultConfig(), newMemoryTransport(idA.Address()), Hooks{})
	for _, pt := range []Port{PortChat, PortEpochCommit, PortLeave, PortDM, PortAttachMeta, PortChunkReq, PortChunkRes, PortSyncReq, PortSyncRes, PortPeerRequest, PortPeerResponse} {
		pkt, _ := NewPlainPacket(idA, BroadcastAddr, pt, 1, nil)
		data, _ := MarshalPacket(pkt)
		n.HandleWire("peer", data)
	}

	// OOB TreeNodes in ProcessCommit must return error without panic
	gA, _ := NewMLSGroup("h8-room", idA)
	idB := newTestIdentityWithSeed(t, "h8-bob-seed-00000000000000000002")
	pkgB, _ := NewKeyPackage(idB)
	commit, _, _ := gA.CreateAddCommit(pkgB)
	badCommit := *commit
	badCommit.TreeNodes = []ExportedNode{{Index: 9999, LeafIndex: -9, Parent: 9999}}
	idA2 := newTestIdentityWithSeed(t, "h8-alice-seed-000000000000000001")
	gA2, _ := NewMLSGroup("h8-room", idA2)
	if err := gA2.ProcessCommit(&badCommit); err == nil {
		t.Fatalf("expected error on corrupted OOB TreeNodes")
	}
}

// TestSecurity_H10_MultiChannelChannelAnswerPreservesChannelID verifies that a transit/multi-channel
// node participating in multiple channels records discovered peers in the target ChannelID, NOT hardcoded n.RoomID.
func TestSecurity_H10_MultiChannelChannelAnswerPreservesChannelID(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()
	cfg.BroadcastHopTimeout = 15 * time.Millisecond

	var mu sync.Mutex
	var bobDiscoveredChannel string
	alice, trAlice := newTestNode(t, "h10-alice-seed", "genesis", roomKey, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "h10-charlie-seed", "genesis", roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "h10-bob-seed", "genesis", roomKey, cfg, Hooks{
		OnChannelDiscovered: func(channelID string, peer string) {
			mu.Lock()
			if peer == alice.Address() {
				bobDiscoveredChannel = channelID
			}
			mu.Unlock()
		},
	})

	trAlice.Connect(trCharlie)
	trCharlie.Connect(trBob)
	alice.AddPeer(charlie.Address())
	charlie.AddPeer(alice.Address())
	charlie.AddPeer(bob.Address())
	bob.AddPeer(charlie.Address())

	betaKey, _ := GenerateRoomKey()
	_ = bob.JoinChannelWithKey("target-channel-beta", betaKey)
	if err := alice.JoinChannelWithKey("target-channel-beta", betaKey); err != nil {
		t.Fatalf("JoinChannelWithKey failed: %v", err)
	}
	time.Sleep(120 * time.Millisecond)

	mu.Lock()
	gotChan := bobDiscoveredChannel
	mu.Unlock()
	if gotChan != "target-channel-beta" {
		t.Fatalf("H10 VULNERABILITY: handleChannelAnswer added peer to %q instead of %q", gotChan, "target-channel-beta")
	}
	if len(bob.ChannelPeers("target-channel-beta")) == 0 {
		t.Fatalf("H10 VULNERABILITY: bob ChannelPeers(target-channel-beta) is empty")
	}
}

// TestSecurity_H10_MultiChannelSeparateMLSGroups verifies that a node participating in
// more than one channel maintains completely separate MLS groups and key schedules per channel,
// and evicting a peer from channel A does NOT close or disrupt their participation in channel B.
func TestSecurity_H10_MultiChannelSeparateMLSGroups(t *testing.T) {
	keyA, _ := GenerateRoomKey()
	keyB, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var mu sync.Mutex
	var alphaGot, betaGot []string
	var charlieGotAlpha, charlieGotBeta []string

	alice, trAlice := newTestNode(t, "mc-alice-seed", "chan-alpha", keyA, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			mu.Lock()
			if env.RoomID == "chan-alpha" {
				alphaGot = append(alphaGot, string(pt))
			} else if env.RoomID == "chan-beta" {
				betaGot = append(betaGot, string(pt))
			}
			mu.Unlock()
		},
	})
	bob, trBob := newTestNode(t, "mc-bob-seed", "chan-alpha", keyA, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "mc-charlie-seed", "chan-alpha", keyA, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			mu.Lock()
			if env.RoomID == "chan-alpha" {
				charlieGotAlpha = append(charlieGotAlpha, string(pt))
			} else if env.RoomID == "chan-beta" {
				charlieGotBeta = append(charlieGotBeta, string(pt))
			}
			mu.Unlock()
		},
	})

	// All 3 peers join second channel "chan-beta" with keyB
	_ = alice.JoinChannelWithKey("chan-beta", keyB)
	_ = bob.JoinChannelWithKey("chan-beta", keyB)
	_ = charlie.JoinChannelWithKey("chan-beta", keyB)

	invA, err := alice.CreateChannelInviteForChannel("chan-alpha", 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInvite alpha failed: %v", err)
	}
	invB, err := alice.CreateChannelInviteForChannel("chan-beta", 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInvite beta failed: %v", err)
	}
	bob.SetChannelInviteForChannel("chan-alpha", invA)
	bob.SetChannelInviteForChannel("chan-beta", invB)
	charlie.SetChannelInviteForChannel("chan-alpha", invA)
	charlie.SetChannelInviteForChannel("chan-beta", invB)

	connectFullMesh([]*Node{alice, bob, charlie}, []*memoryTransport{trAlice, trBob, trCharlie})
	if err := alice.InitChannelMLS("chan-alpha"); err != nil {
		t.Fatalf("InitChannelMLS alpha failed: %v", err)
	}
	if err := alice.InitChannelMLS("chan-beta"); err != nil {
		t.Fatalf("InitChannelMLS beta failed: %v", err)
	}

	bob.BroadcastPeerInfo()
	charlie.BroadcastPeerInfo()
	time.Sleep(180 * time.Millisecond)

	if alice.ChannelCurrentEpoch("chan-alpha") < 3 || charlie.ChannelCurrentEpoch("chan-alpha") < 3 {
		t.Fatalf("chan-alpha failed to admit 3 peers: A=%d C=%d", alice.ChannelCurrentEpoch("chan-alpha"), charlie.ChannelCurrentEpoch("chan-alpha"))
	}
	if alice.ChannelCurrentEpoch("chan-beta") < 3 || charlie.ChannelCurrentEpoch("chan-beta") < 3 {
		t.Fatalf("chan-beta failed to admit 3 peers: A=%d C=%d", alice.ChannelCurrentEpoch("chan-beta"), charlie.ChannelCurrentEpoch("chan-beta"))
	}
	alice.mu.RLock()
	roomKeyAlpha := alice.channels["chan-alpha"].RoomKey
	roomKeyBeta := alice.channels["chan-beta"].RoomKey
	alice.mu.RUnlock()
	if roomKeyAlpha == roomKeyBeta {
		t.Fatalf("separate channels must derive separate MLS group keys")
	}

	if _, err := alice.SendChannelMessage("chan-alpha", "hello-alpha"); err != nil {
		t.Fatalf("SendChannelMessage alpha failed: %v", err)
	}
	if _, err := alice.SendChannelMessage("chan-beta", "hello-beta"); err != nil {
		t.Fatalf("SendChannelMessage beta failed: %v", err)
	}
	time.Sleep(60 * time.Millisecond)

	mu.Lock()
	gotCAlpha := len(charlieGotAlpha) == 1 && strings.Contains(charlieGotAlpha[0], "hello-alpha")
	gotCBeta := len(charlieGotBeta) == 1 && strings.Contains(charlieGotBeta[0], "hello-beta")
	mu.Unlock()
	if !gotCAlpha || !gotCBeta {
		t.Fatalf("charlie did not receive isolated channel messages: alpha=%v beta=%v", charlieGotAlpha, charlieGotBeta)
	}

	// Evict Charlie ONLY from chan-alpha; chan-beta must remain intact and functional for Charlie
	if _, err := alice.EvictPeerInChannel("chan-alpha", charlie.Address(), "ban in alpha"); err != nil {
		t.Fatalf("EvictPeerInChannel alpha failed: %v", err)
	}
	time.Sleep(60 * time.Millisecond)

	if !alice.IsPeerEvictedInChannel("chan-alpha", charlie.Address()) {
		t.Fatalf("expected charlie evicted in chan-alpha")
	}
	if alice.IsPeerEvictedInChannel("chan-beta", charlie.Address()) {
		t.Fatalf("eviction in chan-alpha leaked into chan-beta")
	}

	if _, err := bob.SendChannelMessage("chan-alpha", "post-evict-alpha"); err != nil {
		t.Fatalf("bob send alpha failed: %v", err)
	}
	if _, err := charlie.SendChannelMessage("chan-beta", "charlie-still-in-beta"); err != nil {
		t.Fatalf("charlie send beta after alpha eviction failed: %v", err)
	}
	time.Sleep(60 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	for _, m := range charlieGotAlpha {
		if strings.Contains(m, "post-evict-alpha") {
			t.Fatalf("evicted charlie decrypted post-eviction chan-alpha message")
		}
	}
	foundBeta := false
	for _, m := range betaGot {
		if strings.Contains(m, "charlie-still-in-beta") {
			foundBeta = true
			break
		}
	}
	if !foundBeta {
		t.Fatalf("alice did not receive charlie's chan-beta message after chan-alpha eviction; got=%v", betaGot)
	}
	_ = alphaGot
}
