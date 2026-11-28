package cotilla

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestNode creates a deterministic node with unique seed for multi-peer testing.
func newTestNode(t *testing.T, seed string, roomID string, roomKey RoomKey, cfg Config, hooks Hooks) (*Node, *memoryTransport) {
	t.Helper()
	seedBytes := []byte(fmt.Sprintf("%-32s", seed))[:32]
	id, err := NewIdentityFromSeed(seedBytes)
	if err != nil {
		t.Fatalf("identity from seed failed: %v", err)
	}
	tr := newMemoryTransport(id.Address())
	var closed atomic.Bool
	t.Cleanup(func() { closed.Store(true) })
	if hooks.Log == nil {
		hooks.Log = func(msg string) {
			if closed.Load() {
				return
			}
			t.Logf("[%s] %s", seed, msg)
		}
	}
	node := NewNode(id, roomID, roomKey, cfg, tr, hooks)
	tr.onData = func(from string, data []byte) {
		node.HandleWire(from, data)
	}
	tr.onClose = func(addr string) {
		node.RemovePeer(addr)
	}
	return node, tr
}

// connectFullMesh connects every node to every other node in a complete mesh topology.
func connectFullMesh(nodes []*Node, transports []*memoryTransport) {
	n := len(nodes)
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			transports[i].Connect(transports[j])
			nodes[i].AddPeer(nodes[j].Address())
			nodes[j].AddPeer(nodes[i].Address())
			nodes[i].addChannelPeer(nodes[i].RoomID, nodes[j].Address())
			nodes[j].addChannelPeer(nodes[j].RoomID, nodes[i].Address())
		}
	}
	// Distribute signed PeerInfo across all peers
	for i := 0; i < n; i++ {
		nodes[i].BroadcastPeerInfo()
	}
	// Small sleep to ensure all peer info frames settle
	time.Sleep(50 * time.Millisecond)
}

// TestMeshScaling_20PlusPeers tests a large 22-peer full mesh exchanging concurrent messages.
func TestMeshScaling_20PlusPeers(t *testing.T) {
	const peerCount = 22
	const msgsPerPeer = 3

	roomID := "room-scaling-22-peers"
	roomKey, err := GenerateRoomKey()
	if err != nil {
		t.Fatalf("room key gen failed: %v", err)
	}

	cfg := DefaultConfig()
	cfg.RingBufferCapacity = 200

	var receivedCount int64
	var dupCount int64
	var mu sync.Mutex
	receivedByPeer := make(map[string]map[string]bool)

	nodes := make([]*Node, peerCount)
	transports := make([]*memoryTransport, peerCount)

	for i := 0; i < peerCount; i++ {
		idx := i
		seed := fmt.Sprintf("seed-peer-scaling-%02d-unique-entropy", idx)
		peerAddrHolder := ""

		hooks := Hooks{
			OnMessage: func(env *Envelope, pt []byte) {
				var chat ChatPayload
				if err := json.Unmarshal(pt, &chat); err == nil {
					mu.Lock()
					if receivedByPeer[peerAddrHolder] == nil {
						receivedByPeer[peerAddrHolder] = make(map[string]bool)
					}
					if receivedByPeer[peerAddrHolder][env.ID()] {
						atomic.AddInt64(&dupCount, 1)
					} else {
						receivedByPeer[peerAddrHolder][env.ID()] = true
						atomic.AddInt64(&receivedCount, 1)
					}
					mu.Unlock()
				}
			},
		}

		node, tr := newTestNode(t, seed, roomID, roomKey, cfg, hooks)
		peerAddrHolder = node.Address()
		nodes[idx] = node
		transports[idx] = tr
	}

	connectFullMesh(nodes, transports)

	// Verify all peers see all other 21 peers
	for i, n := range nodes {
		peers := n.Peers()
		if len(peers) != peerCount-1 {
			t.Fatalf("node %d has %d peers, expected %d", i, len(peers), peerCount-1)
		}
	}

	// Concurrently broadcast messages from all 22 peers
	var wg sync.WaitGroup
	totalExpectedMessages := peerCount * msgsPerPeer
	for i := 0; i < peerCount; i++ {
		wg.Add(1)
		go func(nodeIdx int) {
			defer wg.Done()
			for m := 0; m < msgsPerPeer; m++ {
				text := fmt.Sprintf("hello from peer %d message %d", nodeIdx, m)
				if _, err := nodes[nodeIdx].SendMessage(text); err != nil {
					t.Errorf("peer %d failed to send: %v", nodeIdx, err)
				}
				time.Sleep(2 * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()

	// Wait for message delivery across all 22 peers (each non-author receives (peerCount-1) copies)
	expectedTotalDeliveries := int64(totalExpectedMessages * (peerCount - 1))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&receivedCount) >= expectedTotalDeliveries {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	curr := atomic.LoadInt64(&receivedCount)
	if curr < expectedTotalDeliveries {
		t.Fatalf("scaling test received %d deliveries, expected %d", curr, expectedTotalDeliveries)
	}

	// Verify deduplication: no peer received duplicate message IDs
	if dups := atomic.LoadInt64(&dupCount); dups > 0 {
		t.Fatalf("scaling test received %d duplicate deliveries", dups)
	}
	mu.Lock()
	if len(receivedByPeer) != peerCount {
		t.Errorf("expected %d peers to receive messages, got %d", peerCount, len(receivedByPeer))
	}
	for peerAddr, msgs := range receivedByPeer {
		if len(msgs) != (peerCount-1)*msgsPerPeer {
			t.Errorf("peer %s saw %d unique messages, expected %d", peerAddr[:8], len(msgs), (peerCount-1)*msgsPerPeer)
		}
	}
	mu.Unlock()
}

// TestTargetedSync_ExpandingRingSearch verifies that targeted sync expands ring queries
// by 2x (1, 2, 4, 8...) every round and never repeats an active peer until exhausted.
func TestTargetedSync_ExpandingRingSearch(t *testing.T) {
	const neighborCount = 15
	roomID := "room-expanding-ring-sync"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "seed-alice-expanding-ring-test", roomID, roomKey, cfg, Hooks{})

	neighbors := make([]*Node, neighborCount)
	neighborTransports := make([]*memoryTransport, neighborCount)
	for i := 0; i < neighborCount; i++ {
		seed := fmt.Sprintf("seed-neighbor-ring-%02d-entropy", i)
		node, tr := newTestNode(t, seed, roomID, roomKey, cfg, Hooks{})
		neighbors[i] = node
		neighborTransports[i] = tr

		trAlice.Connect(tr)
		alice.AddPeer(node.Address())
		node.AddPeer(alice.Address())
	}

	// Round 1: query 1 peer
	batch1, err := alice.RequestCatchUpNextBatch()
	if err != nil || len(batch1) != 1 {
		t.Fatalf("round 1 expected 1 peer, got %d (err: %v)", len(batch1), err)
	}

	// Round 2: query 2 peers
	batch2, err := alice.RequestCatchUpNextBatch()
	if err != nil || len(batch2) != 2 {
		t.Fatalf("round 2 expected 2 peers, got %d (err: %v)", len(batch2), err)
	}

	// Round 3: query 4 peers
	batch3, err := alice.RequestCatchUpNextBatch()
	if err != nil || len(batch3) != 4 {
		t.Fatalf("round 3 expected 4 peers, got %d (err: %v)", len(batch3), err)
	}

	// Round 4: query 8 peers
	batch4, err := alice.RequestCatchUpNextBatch()
	if err != nil || len(batch4) != 8 {
		t.Fatalf("round 4 expected 8 peers, got %d (err: %v)", len(batch4), err)
	}

	// Total queried so far: 1 + 2 + 4 + 8 = 15 peers
	queriedSet := make(map[string]bool)
	allBatches := append(append(append(batch1, batch2...), batch3...), batch4...)
	for _, p := range allBatches {
		if queriedSet[p] {
			t.Fatalf("peer %s was queried more than once before exhaustion!", p[:8])
		}
		queriedSet[p] = true
	}
	if len(queriedSet) != neighborCount {
		t.Fatalf("expected all %d neighbors to be queried, got %d", neighborCount, len(queriedSet))
	}

	// Round 5: all peers were exhausted, ring resets to 1 peer
	batch5, err := alice.RequestCatchUpNextBatch()
	if err != nil || len(batch5) != 1 {
		t.Fatalf("round 5 expected ring reset to 1 peer, got %d (err: %v)", len(batch5), err)
	}
}

// TestReconnectCatchUp_ExtendedOffline_20Peers verifies that reconnected peers offline
// for 8-12 minutes (past 5-min live replay window, within 15-min MessageTTL) can pull back
// missed messages without false replay rejection.
func TestReconnectCatchUp_ExtendedOffline_20Peers(t *testing.T) {
	const peerCount = 20
	roomID := "room-offline-catchup-20-peers"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()
	cfg.ReplayWindow = 5 * time.Minute
	cfg.MessageTTL = 15 * time.Minute

	var zackReceived int64
	nodes := make([]*Node, peerCount)
	transports := make([]*memoryTransport, peerCount)

	for i := 0; i < peerCount; i++ {
		seed := fmt.Sprintf("seed-offline-test-peer-%02d", i)
		hooks := Hooks{}
		if i == 0 {
			// Peer 0 is "Zack" who will go offline
			hooks.OnMessage = func(env *Envelope, pt []byte) {
				atomic.AddInt64(&zackReceived, 1)
			}
			hooks.Log = func(msg string) {
				t.Logf("[ZACK LOG] %s", msg)
			}
		}
		node, tr := newTestNode(t, seed, roomID, roomKey, cfg, hooks)
		nodes[i] = node
		transports[i] = tr
	}

	connectFullMesh(nodes, transports)

	// Peer 0 (Zack) disconnects from all 19 peers
	zack := nodes[0]
	trZack := transports[0]
	for i := 1; i < peerCount; i++ {
		trZack.Disconnect(transports[i])
		zack.RemovePeer(nodes[i].Address())
		nodes[i].RemovePeer(zack.Address())
	}

	// While Zack is offline, the remaining 19 peers produce messages.
	// We simulate that these messages were sent 10 minutes ago (> 5 min ReplayWindow, < 15 min TTL).
	staleTS := time.Now().Add(-10 * time.Minute).UnixMilli()
	const offlineMsgs = 5
	for i := 1; i <= offlineMsgs; i++ {
		authorNode := nodes[i]
		payloadBytes, _ := json.Marshal(ChatPayload{Type: "chat", Text: fmt.Sprintf("offline msg %d", i)})

		// Manually build envelope with 10-minute old timestamp
		author := authorNode.Address()
		aad := []byte(fmt.Sprintf("cotilla-envelope-v1:%s:%d:%s", roomID, int64(0), author))
		nonce, cipher, _ := EncryptRoomPayload(roomKey, payloadBytes, aad)
		nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
		cipherStr := base64.RawURLEncoding.EncodeToString(cipher)
		canonical := CanonicalEnvelopePayload(roomID, author, nonceStr, cipherStr, 0, staleTS)
		sig := hex.EncodeToString(authorNode.ID.Sign(canonical))

		env := &Envelope{
			RoomID:       roomID,
			AuthorPubKey: author,
			Nonce:        nonceStr,
			Ciphertext:   cipherStr,
			EpochID:      0,
			Timestamp:    staleTS,
			Signature:    sig,
		}
		_ = env.ID()

		// Stored in the active peers' ring buffers
		for j := 1; j < peerCount; j++ {
			nodes[j].RingBuffer.Push(env)
			nodes[j].seenEnvelopes[env.ID()] = struct{}{}
		}
	}

	// Zack reconnects to peers 1..3
	for i := 1; i <= 3; i++ {
		trZack.Connect(transports[i])
		zack.AddPeer(nodes[i].Address())
		nodes[i].AddPeer(zack.Address())
	}
	time.Sleep(30 * time.Millisecond)

	// Zack initiates catch-up sync
	chosen, err := zack.RequestCatchUpNextBatch()
	t.Logf("Zack queried peers: %v (err: %v)", chosen, err)
	for i := 0; i < peerCount; i++ {
		if nodes[i].Address() == chosen[0] {
			t.Logf("Queried peer is node %d", i)
		}
	}
	if err != nil {
		t.Fatalf("zack RequestCatchUp failed: %v", err)
	}

	// Wait for catch-up response processing
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&zackReceived) >= offlineMsgs {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if atomic.LoadInt64(&zackReceived) != offlineMsgs {
		t.Fatalf("zack received %d missed messages, expected %d", atomic.LoadInt64(&zackReceived), offlineMsgs)
	}
}

// TestChannelInvite_SignedProvenanceAndExpiry verifies cryptographic signature provenance
// and TTL expiration on room invitations.
func TestChannelInvite_SignedProvenanceAndExpiry(t *testing.T) {
	roomID := "room-invites-provenance"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, _ := newTestNode(t, "seed-alice-channel-invite-01", roomID, roomKey, cfg, Hooks{})
	bob, _ := newTestNode(t, "seed-bob-channel-invite-02", roomID, roomKey, cfg, Hooks{})
	charlie, _ := newTestNode(t, "seed-charlie-channel-invite-03", roomID, roomKey, cfg, Hooks{})

	// 1. Alice creates a valid invite with 15-minute TTL
	inv, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("create channel invite failed: %v", err)
	}
	if inv.InviterPub != alice.Address() {
		t.Fatalf("invite author mismatch: got %s, expected %s", inv.InviterPub, alice.Address())
	}

	// Bob verifies Alice's invite: must succeed
	if err := bob.VerifyChannelInvite(inv); err != nil {
		t.Fatalf("bob failed to verify valid invite: %v", err)
	}

	// Provenance tracking: Bob records who invited Charlie
	bob.peerInviters[charlie.Address()] = inv.InviterPub
	if bob.InvitedBy(charlie.Address()) != alice.Address() {
		t.Fatalf("expected charlie to be invited by alice, got %s", bob.InvitedBy(charlie.Address()))
	}

	// 2. Tampered invite: altered roomID must fail
	tampered := *inv
	tampered.RoomID = "evil-room"
	if err := bob.VerifyChannelInvite(&tampered); err == nil {
		t.Fatal("expected tampered room ID invite to fail, but it passed")
	}

	// 3. Tampered signature must fail
	tamperedSig := *inv
	tamperedSig.Signature = hex.EncodeToString([]byte("invalid-signature-bytes-00000000000000000000000000000000000000000000"))
	if err := bob.VerifyChannelInvite(&tamperedSig); err == nil {
		t.Fatal("expected tampered signature invite to fail, but it passed")
	}

	// 4. Expired invite must fail
	expiredInv := *inv
	expiredInv.ExpiresAt = time.Now().Add(-1 * time.Minute).UnixMilli()
	// Re-sign expired invite with Alice's key
	canonicalExpired := CanonicalChannelInvite(expiredInv.RoomID, expiredInv.InviterPub, expiredInv.RoomKey, expiredInv.EpochID, expiredInv.ExpiresAt)
	expiredInv.Signature = hex.EncodeToString(alice.ID.Sign(canonicalExpired))

	if err := bob.VerifyChannelInvite(&expiredInv); err == nil {
		t.Fatal("expected expired invite to fail verification, but it passed")
	}
}

// TestChannelInvite_EvictedInviterRevocation tests the user's specific scenario:
// "A sends out an invite, B joins with A's invite, A gets evicted, B stays,
// C tries to join with A's invitation and is not accepted".
func TestChannelInvite_EvictedInviterRevocation(t *testing.T) {
	roomID := "room-evicted-inviter-revocation"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "seed-alice-inviter-revocation-01", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "seed-bob-inviter-revocation-02", roomID, roomKey, cfg, Hooks{})
	charlie, _ := newTestNode(t, "seed-charlie-inviter-revocation-03", roomID, roomKey, cfg, Hooks{})
	dave, trDave := newTestNode(t, "seed-dave-inviter-revocation-04", roomID, roomKey, cfg, Hooks{})

	// Alice creates an invite IA
	inviteA, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice create invite failed: %v", err)
	}

	// Alice, Bob, and Dave connect. Bob and Dave joined using Alice's invite.
	bob.SetChannelInvite(inviteA)
	dave.SetChannelInvite(inviteA)
	connectFullMesh([]*Node{alice, bob, dave}, []*memoryTransport{trAlice, trBob, trDave})

	// Alice also sends inviteA to Charlie (Charlie has NOT joined yet).
	charlie.SetChannelInvite(inviteA)

	// Now Bob evicts Alice from the room!
	commit, err := bob.EvictPeer(alice.Address(), "disruptive conduct")
	if err != nil {
		t.Fatalf("bob failed to evict alice: %v", err)
	}
	_ = commit
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if bob.IsPeerEvicted(alice.Address()) && dave.IsPeerEvicted(alice.Address()) {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Verify Bob and Dave stayed, and Alice is evicted
	if !bob.IsPeerEvicted(alice.Address()) {
		t.Fatal("bob should have alice marked as evicted")
	}
	if !dave.IsPeerEvicted(alice.Address()) {
		t.Fatal("dave should have alice marked as evicted")
	}

	// Now Charlie tries to join Bob and Dave's room presenting Alice's invite (inviteA)
	if err := bob.VerifyChannelInvite(inviteA); err == nil {
		t.Fatal("vulnerability: bob accepted invite from evicted member alice!")
	} else {
		t.Logf("expected invite rejection for charlie: %v", err)
	}

	if err := dave.VerifyChannelInvite(inviteA); err == nil {
		t.Fatal("vulnerability: dave accepted invite from evicted member alice!")
	}
}

// TestMemberEviction_CryptographicLockout verifies that when Charlie is evicted,
// a new epoch key is distributed pairwise to remaining peers; Charlie cannot decrypt
// future messages even if Charlie holds the URL root key and captures wire traffic.
func TestMemberEviction_CryptographicLockout(t *testing.T) {
	roomID := "room-epoch-ratchet-eviction"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var testMu sync.Mutex
	var bobReceivedPt, daveReceivedPt string
	bob, trBob := newTestNode(t, "seed-bob-epoch-test-01", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			bobReceivedPt = string(pt)
			testMu.Unlock()
		},
	})
	dave, trDave := newTestNode(t, "seed-dave-epoch-test-02", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			daveReceivedPt = string(pt)
			testMu.Unlock()
		},
	})
	charlie, trCharlie := newTestNode(t, "seed-charlie-epoch-test-03", roomID, roomKey, cfg, Hooks{})

	nodes := []*Node{bob, dave, charlie}
	transports := []*memoryTransport{trBob, trDave, trCharlie}
	connectFullMesh(nodes, transports)

	// Verify all peers know each other's encryption keys
	if len(bob.PeerEncKeys()) != 2 {
		t.Fatalf("bob knows %d enc keys, expected 2", len(bob.PeerEncKeys()))
	}

	// Bob evicts Charlie
	commit, err := bob.EvictPeer(charlie.Address(), "violating privacy policy")
	if err != nil {
		t.Fatalf("bob failed to evict charlie: %v", err)
	}
	if commit.EpochID != 1 {
		t.Fatalf("expected epoch 1, got %d", commit.EpochID)
	}

	// Deliver commit frame to Dave and Charlie
	data := mustMarshalGroupPacket(t, bob, PortEpochCommit, commit)
	trBob.Send(dave.Address(), data)
	trBob.Send(charlie.Address(), data)

	commitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(commitDeadline) && dave.CurrentEpoch() != 1 {
		time.Sleep(15 * time.Millisecond)
	}

	// Dave has advanced to Epoch 1
	if dave.CurrentEpoch() != 1 {
		t.Fatalf("dave did not advance to epoch 1, current: %d", dave.CurrentEpoch())
	}

	// Bob sends a message in Epoch 1
	secretMsg := "top-secret-epoch-1-content"
	epoch1Env, err := bob.SendMessage(secretMsg)
	if err != nil {
		t.Fatalf("bob send message failed: %v", err)
	}
	if epoch1Env.EpochID != 1 {
		t.Fatalf("expected envelope epoch 1, got %d", epoch1Env.EpochID)
	}

	// Deliver message frame to Dave and Charlie
	msgData := mustMarshalGroupPacket(t, bob, PortChat, epoch1Env)
	trBob.Send(dave.Address(), msgData)
	trBob.Send(charlie.Address(), msgData)

	msgDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(msgDeadline) {
		testMu.Lock()
		got := daveReceivedPt
		testMu.Unlock()
		if got != "" {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}

	testMu.Lock()
	gotDavePt := daveReceivedPt
	testMu.Unlock()

	// Dave decrypted Epoch 1 message successfully
	if gotDavePt == "" {
		t.Fatal("dave failed to receive and decrypt epoch 1 message")
	}

	// Charlie tries to decrypt with his current room key (Epoch 0 URL key): MUST FAIL!
	_, err = epoch1Env.Decrypt(charlie.RoomKey)
	if err == nil {
		t.Fatal("cryptographic failure: evicted member charlie successfully decrypted epoch 1 message!")
	}
	t.Logf("confirmed: evicted member charlie was locked out with error: %v", err)

	// Charlie tries to send an envelope: Bob and Dave MUST reject it
	charlieEnv, _ := charlie.SendMessage("charlie-rogue-msg")
	charlieData := mustMarshalGroupPacket(t, charlie, PortChat, charlieEnv)

	bobBefore := bobReceivedPt
	trCharlie.Send(bob.Address(), charlieData)
	time.Sleep(30 * time.Millisecond)

	if bobReceivedPt != bobBefore {
		t.Fatal("bob accepted message from evicted member charlie!")
	}
}

// TestEpochRatchet_RotateEpochKey_AdmittedMembersOnly verifies that when an epoch key rotation
// occurs, only admitted members who joined with a signed invite receive the new epoch key.
// Peers who joined with only the room and key (unadmitted) cannot decipher messages.
func TestEpochRatchet_RotateEpochKey_AdmittedMembersOnly(t *testing.T) {
	roomID := "room-ratchet-members-only"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var testMu sync.Mutex
	var bobReceived, charlieReceived, eveReceived string
	alice, trAlice := newTestNode(t, "seed-alice-ratchet-01", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "seed-bob-ratchet-02", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			bobReceived = string(pt)
			testMu.Unlock()
		},
	})
	charlie, trCharlie := newTestNode(t, "seed-charlie-ratchet-03", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			charlieReceived = string(pt)
			testMu.Unlock()
		},
	})
	// Eve joins with only room and key (no invite)
	eve, trEve := newTestNode(t, "seed-eve-ratchet-04", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			eveReceived = string(pt)
			testMu.Unlock()
		},
	})

	// Alice creates channel invite for Bob and Charlie
	inv, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice failed to create invite: %v", err)
	}

	bob.SetChannelInvite(inv)
	charlie.SetChannelInvite(inv)
	// Eve has no invite!

	nodes := []*Node{alice, bob, charlie, eve}
	transports := []*memoryTransport{trAlice, trBob, trCharlie, trEve}
	connectFullMesh(nodes, transports)

	// Verify admitted member status
	if !alice.IsAdmittedMember(bob.Address()) {
		t.Fatal("alice should mark bob as admitted member")
	}
	if !alice.IsAdmittedMember(charlie.Address()) {
		t.Fatal("alice should mark charlie as admitted member")
	}
	if alice.IsAdmittedMember(eve.Address()) {
		t.Fatal("alice must NOT mark uninvited eve as admitted member")
	}

	// Alice rotates the group key to Epoch 1
	commit, err := alice.RotateEpochKey()
	if err != nil {
		t.Fatalf("alice failed to rotate epoch key: %v", err)
	}
	if commit.EpochID != 1 {
		t.Fatalf("expected epoch 1, got %d", commit.EpochID)
	}

	// Verify commit contains MLSCommit
	if commit.MLSCommit == nil {
		t.Fatal("commit missing MLSCommit")
	}
	if commit.MLSCommit.Epoch != 1 {
		t.Fatalf("expected MLSCommit epoch 1, got %d", commit.MLSCommit.Epoch)
	}

	// Deliver commit frame to all peers
	commitData := mustMarshalGroupPacket(t, alice, PortEpochCommit, commit)
	trAlice.Send(bob.Address(), commitData)
	trAlice.Send(charlie.Address(), commitData)
	trAlice.Send(eve.Address(), commitData)

	time.Sleep(50 * time.Millisecond)

	// Bob and Charlie must advance to Epoch 1
	if bob.CurrentEpoch() != 1 {
		t.Fatalf("bob did not advance to epoch 1, current: %d", bob.CurrentEpoch())
	}
	if charlie.CurrentEpoch() != 1 {
		t.Fatalf("charlie did not advance to epoch 1, current: %d", charlie.CurrentEpoch())
	}
	// Eve must stay at Epoch 0
	if eve.CurrentEpoch() != 0 {
		t.Fatalf("eve unexpectedly advanced to epoch %d", eve.CurrentEpoch())
	}

	// Alice sends an envelope at Epoch 1
	msgText := "confidential-group-message-epoch-1"
	env, err := alice.SendMessage(msgText)
	if err != nil {
		t.Fatalf("alice send message failed: %v", err)
	}
	if env.EpochID != 1 {
		t.Fatalf("expected env epoch 1, got %d", env.EpochID)
	}

	msgData := mustMarshalGroupPacket(t, alice, PortChat, env)
	trAlice.Send(bob.Address(), msgData)
	trAlice.Send(charlie.Address(), msgData)
	trAlice.Send(eve.Address(), msgData)

	time.Sleep(50 * time.Millisecond)

	testMu.Lock()
	gotBob := bobReceived
	gotCharlie := charlieReceived
	gotEve := eveReceived
	testMu.Unlock()

	// Bob and Charlie decrypted the message successfully
	if !strings.Contains(gotBob, msgText) {
		t.Fatalf("bob failed to decipher message: got %q", gotBob)
	}
	if !strings.Contains(gotCharlie, msgText) {
		t.Fatalf("charlie failed to decipher message: got %q", gotCharlie)
	}
	// Eve CANNOT decipher the message
	if gotEve != "" {
		t.Fatalf("security violation: uninvited eve was able to decipher epoch 1 text: %q", gotEve)
	}
}

// TestLateJoin_AdmittedMemberReceivesActiveEpochKey_UnadmittedLockedOut verifies that
// when a group is already operating at Epoch 1, a late joining peer presenting a valid
// signed invite automatically receives the active epoch key, whereas an unadmitted peer
// joining with only room and key does not receive it and cannot decipher group texts.
func TestLateJoin_AdmittedMemberReceivesActiveEpochKey_UnadmittedLockedOut(t *testing.T) {
	roomID := "room-late-join-epoch-sync"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	alice, trAlice := newTestNode(t, "seed-alice-late-01", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "seed-bob-late-02", roomID, roomKey, cfg, Hooks{})

	inv, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice failed to create invite: %v", err)
	}
	bob.SetChannelInvite(inv)

	connectFullMesh([]*Node{alice, bob}, []*memoryTransport{trAlice, trBob})

	// Alice rotates to Epoch 1
	commit, err := alice.RotateEpochKey()
	if err != nil {
		t.Fatalf("alice rotate failed: %v", err)
	}
	commitData := mustMarshalGroupPacket(t, alice, PortEpochCommit, commit)
	trAlice.Send(bob.Address(), commitData)
	time.Sleep(30 * time.Millisecond)

	if alice.CurrentEpoch() != 1 || bob.CurrentEpoch() != 1 {
		t.Fatalf("expected both at epoch 1, got alice=%d bob=%d", alice.CurrentEpoch(), bob.CurrentEpoch())
	}

	// Now Dave (late joiner with valid invite) and Eve (with only room & key) connect
	var testMu sync.Mutex
	var daveReceived, eveReceived string
	dave, trDave := newTestNode(t, "seed-dave-late-03", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			daveReceived = string(pt)
			testMu.Unlock()
		},
	})
	dave.SetChannelInvite(inv) // Dave presents Alice's invite

	eve, trEve := newTestNode(t, "seed-eve-late-04", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			testMu.Lock()
			eveReceived = string(pt)
			testMu.Unlock()
		},
	})
	// Eve has no invite!

	// Connect Dave and Eve to Alice
	trAlice.Connect(trDave)
	trAlice.Connect(trEve)
	alice.AddPeer(dave.Address())
	dave.AddPeer(alice.Address())
	alice.AddPeer(eve.Address())
	eve.AddPeer(alice.Address())

	// Connect Dave and Eve to Bob as well
	trBob.Connect(trDave)
	trBob.Connect(trEve)
	bob.AddPeer(dave.Address())
	dave.AddPeer(bob.Address())
	bob.AddPeer(eve.Address())
	eve.AddPeer(bob.Address())

	// Exchange PeerInfo
	alice.BroadcastPeerInfo()
	bob.BroadcastPeerInfo()
	dave.BroadcastPeerInfo()
	eve.BroadcastPeerInfo()

	admitDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(admitDeadline) && dave.CurrentEpoch() == 0 {
		time.Sleep(15 * time.Millisecond)
	}

	// Dave should have received EpochCommit from Alice and advanced to active epoch
	if dave.CurrentEpoch() == 0 {
		t.Fatalf("dave did not advance to active epoch, current: %d", dave.CurrentEpoch())
	}
	// Eve was not sent the key and remains at Epoch 0
	if eve.CurrentEpoch() != 0 {
		t.Fatalf("eve unexpectedly has epoch: %d", eve.CurrentEpoch())
	}
	if dave.CurrentEpoch() != bob.CurrentEpoch() {
		t.Fatalf("epoch mismatch between dave and bob: dave=%d bob=%d", dave.CurrentEpoch(), bob.CurrentEpoch())
	}

	// Bob broadcasts an Epoch 1 message
	msgText := "secret-late-join-epoch-1"
	env, err := bob.SendMessage(msgText)
	if err != nil {
		t.Fatalf("bob send message failed: %v", err)
	}

	msgData := mustMarshalGroupPacket(t, bob, PortChat, env)
	trBob.Send(dave.Address(), msgData)
	trBob.Send(eve.Address(), msgData)

	time.Sleep(50 * time.Millisecond)

	testMu.Lock()
	gotDave := daveReceived
	gotEve := eveReceived
	testMu.Unlock()

	if !strings.Contains(gotDave, msgText) {
		t.Fatalf("dave failed to decipher message: %q", gotDave)
	}
	if gotEve != "" {
		t.Fatalf("unadmitted eve deciphered message: %q", gotEve)
	}
}

// TestEvictionLineage_RogueGroupPartition_NoReAdmittance exercises the multi-party delegation,
// eviction, rogue split-brain isolation, and verifies that unauthorized commits cannot hijack
// or re-admit an evicted peer into the original group.
func TestEvictionLineage_RogueGroupPartition_NoReAdmittance(t *testing.T) {
	roomID := "test-lineage-eviction-room-1234"
	rootKey, err := GenerateRoomKey()
	if err != nil {
		t.Fatalf("failed to generate root key: %v", err)
	}

	cfg := DefaultConfig()
	cfg.ReplayWindow = 5 * time.Second

	idA := newTestIdentityWithSeed(t, "seed-lineage-alice-0000000001")
	idB := newTestIdentityWithSeed(t, "seed-lineage-bob-000000000002")
	idC := newTestIdentityWithSeed(t, "seed-lineage-charlie-00000003")
	idD := newTestIdentityWithSeed(t, "seed-lineage-dave-00000000004")
	idE := newTestIdentityWithSeed(t, "seed-lineage-eve-or-edward-05")
	idX := newTestIdentityWithSeed(t, "seed-lineage-uninvited-x-0006")

	trA := newMemoryTransport(idA.Address())
	trB := newMemoryTransport(idB.Address())
	trC := newMemoryTransport(idC.Address())
	trD := newMemoryTransport(idD.Address())
	trE := newMemoryTransport(idE.Address())
	trX := newMemoryTransport(idX.Address())

	var (
		muA sync.Mutex
		receivedA []string
		muB sync.Mutex
		receivedB []string
		muC sync.Mutex
		receivedC []string
		muD sync.Mutex
		receivedD []string
		muE sync.Mutex
		receivedE []string
		muX sync.Mutex
		receivedX []string
	)

	alice := NewNode(idA, roomID, rootKey, cfg, trA, Hooks{
		Log: func(msg string) {
			t.Logf("[Alice Log] %s", msg)
		},
		OnMessage: func(env *Envelope, pt []byte) {
			muA.Lock()
			receivedA = append(receivedA, string(pt))
			muA.Unlock()
		},
	})
	bob := NewNode(idB, roomID, rootKey, cfg, trB, Hooks{
		Log: func(msg string) {
			t.Logf("[Bob Log] %s", msg)
		},
		OnMessage: func(env *Envelope, pt []byte) {
			muB.Lock()
			receivedB = append(receivedB, string(pt))
			muB.Unlock()
		},
	})
	charlie := NewNode(idC, roomID, rootKey, cfg, trC, Hooks{
		Log: func(msg string) {
			t.Logf("[Charlie Log] %s", msg)
		},
		OnMessage: func(env *Envelope, pt []byte) {
			muC.Lock()
			receivedC = append(receivedC, string(pt))
			muC.Unlock()
		},
	})
	dave := NewNode(idD, roomID, rootKey, cfg, trD, Hooks{
		Log: func(msg string) {
			t.Logf("[Dave Log] %s", msg)
		},
		OnMessage: func(env *Envelope, pt []byte) {
			muD.Lock()
			receivedD = append(receivedD, string(pt))
			muD.Unlock()
		},
	})
	edward := NewNode(idE, roomID, rootKey, cfg, trE, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muE.Lock()
			receivedE = append(receivedE, string(pt))
			muE.Unlock()
		},
	})
	uninvitedX := NewNode(idX, roomID, rootKey, cfg, trX, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muX.Lock()
			receivedX = append(receivedX, string(pt))
			muX.Unlock()
		},
	})

	trA.onData = func(from string, data []byte) { alice.HandleWire(from, data) }
	trB.onData = func(from string, data []byte) { bob.HandleWire(from, data) }
	trC.onData = func(from string, data []byte) { charlie.HandleWire(from, data) }
	trD.onData = func(from string, data []byte) { dave.HandleWire(from, data) }
	trE.onData = func(from string, data []byte) { edward.HandleWire(from, data) }
	trX.onData = func(from string, data []byte) { uninvitedX.HandleWire(from, data) }

	// 1. Genesis: Alice initializes room creator Epoch 1
	if err := alice.InitGenesisEpoch(); err != nil {
		t.Fatalf("alice init genesis epoch failed: %v", err)
	}
	if alice.CurrentEpoch() != 1 {
		t.Fatalf("expected alice epoch 1, got %d", alice.CurrentEpoch())
	}

	// 2. Invites: A invites B; B invites C (with parent invite from A); A invites D
	invB, err := alice.CreateChannelInvite(0)
	if err != nil {
		t.Fatalf("alice create invite for bob failed: %v", err)
	}
	bob.SetChannelInvite(invB)

	invC, err := bob.CreateChannelInvite(0)
	if err != nil {
		t.Fatalf("bob create invite for charlie failed: %v", err)
	}
	if invC.ParentInvite == nil {
		t.Fatalf("expected charlie's invite to carry parent invite from bob/alice")
	}
	charlie.SetChannelInvite(invC)

	invD, err := alice.CreateChannelInvite(0)
	if err != nil {
		t.Fatalf("alice create invite for dave failed: %v", err)
	}
	dave.SetChannelInvite(invD)

	// Connect mesh between A, B, C, D
	nodes := []*Node{alice, bob, charlie, dave}
	transports := []*memoryTransport{trA, trB, trC, trD}
	connectFullMesh(nodes, transports)

	for _, n := range nodes {
		n.BroadcastPeerInfo()
	}
	// Wait for all 4 peers to synchronize to the active epoch
	settleDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(settleDeadline) {
		if alice.CurrentEpoch() >= 4 && bob.CurrentEpoch() == alice.CurrentEpoch() &&
			charlie.CurrentEpoch() == alice.CurrentEpoch() && dave.CurrentEpoch() == alice.CurrentEpoch() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	preEvictEpoch := alice.CurrentEpoch()
	if preEvictEpoch == 0 {
		t.Fatalf("expected active epoch > 0, got %d", preEvictEpoch)
	}

	// Verify all 4 are synchronized to the active epoch
	for _, n := range nodes {
		if n.CurrentEpoch() != preEvictEpoch {
			t.Fatalf("peer %s not at epoch %d (has %d)", n.Address(), preEvictEpoch, n.CurrentEpoch())
		}
		if !alice.IsAdmittedMember(n.Address()) {
			t.Fatalf("alice does not recognize %s as admitted", n.Address())
		}
	}

	// 3. Uninvited peer X connects with only K0 (no invite)
	trA.Connect(trX)
	trB.Connect(trX)
	trC.Connect(trX)
	trD.Connect(trX)
	alice.AddPeer(uninvitedX.Address())
	uninvitedX.AddPeer(alice.Address())
	uninvitedX.BroadcastPeerInfo()
	time.Sleep(50 * time.Millisecond)

	if alice.IsAdmittedMember(uninvitedX.Address()) {
		t.Fatalf("alice marked uninvited peer X as admitted member!")
	}
	if uninvitedX.CurrentEpoch() != 0 {
		t.Fatalf("uninvited X unexpectedly advanced to epoch %d", uninvitedX.CurrentEpoch())
	}

	// Alice sends Epoch 1 message
	msg1 := "epoch-1-confidential-memo"
	env1, err := alice.SendMessage(msg1)
	if err != nil {
		t.Fatalf("alice send msg1 failed: %v", err)
	}
	for _, tr := range transports {
		tr.Broadcast(mustMarshalGroupPacket(t, alice, PortChat, env1))
	}
	trA.Send(uninvitedX.Address(), mustMarshalGroupPacket(t, alice, PortChat, env1))
	time.Sleep(50 * time.Millisecond)

	// B, C, D received msg1
	muB.Lock()
	bGot := len(receivedB) > 0 && strings.Contains(receivedB[0], msg1)
	muB.Unlock()
	muC.Lock()
	cGot := len(receivedC) > 0 && strings.Contains(receivedC[0], msg1)
	muC.Unlock()
	muD.Lock()
	dGot := len(receivedD) > 0 && strings.Contains(receivedD[0], msg1)
	muD.Unlock()
	if !bGot || !cGot || !dGot {
		t.Fatalf("b, c, or d failed to receive msg1: b=%v, c=%v, d=%v", bGot, cGot, dGot)
	}

	// Uninvited X CANNOT decrypt msg1
	muX.Lock()
	xGot := len(receivedX) > 0
	muX.Unlock()
	if xGot {
		t.Fatalf("uninvited peer X deciphered epoch 1 message!")
	}

	// 4. C gets evicted by A -> ratchets to next epoch
	evictEpoch := preEvictEpoch + 1
	evictCommit, err := alice.EvictPeer(charlie.Address(), "malicious activity")
	if err != nil {
		t.Fatalf("alice failed to evict charlie: %v", err)
	}
	if evictCommit.EpochID != evictEpoch {
		t.Fatalf("expected epoch %d, got %d", evictEpoch, evictCommit.EpochID)
	}

	// Deliver evict commit to all
	commitBytes := mustMarshalGroupPacket(t, alice, PortEpochCommit, evictCommit)
	trA.Send(bob.Address(), commitBytes)
	trA.Send(dave.Address(), commitBytes)
	trA.Send(charlie.Address(), commitBytes)
	time.Sleep(100 * time.Millisecond)

	t.Logf("A epoch=%d, B epoch=%d, D epoch=%d, C epoch=%d, C evicted=%v",
		alice.CurrentEpoch(), bob.CurrentEpoch(), dave.CurrentEpoch(), charlie.CurrentEpoch(), charlie.IsPeerEvicted(charlie.Address()))

	if alice.CurrentEpoch() != evictEpoch || bob.CurrentEpoch() != evictEpoch || dave.CurrentEpoch() != evictEpoch {
		t.Fatalf("OG group not at epoch %d: A=%d, B=%d, D=%d", evictEpoch, alice.CurrentEpoch(), bob.CurrentEpoch(), dave.CurrentEpoch())
	}
	if charlie.CurrentEpoch() >= evictEpoch {
		t.Fatalf("evicted charlie unexpectedly advanced to epoch %d", charlie.CurrentEpoch())
	}
	if !charlie.IsPeerEvicted(charlie.Address()) {
		t.Fatalf("charlie does not know he is evicted")
	}

	// 5. Evicted Charlie attempts to create channel invite: MUST FAIL
	_, err = charlie.CreateChannelInvite(0)
	if err == nil {
		t.Fatalf("evicted charlie was able to call CreateChannelInvite without error!")
	}
	t.Logf("confirmed: evicted charlie CreateChannelInvite failed with: %v", err)

	// 6. Suppose Charlie manually signs a forged invite for Edward (E)
	now := time.Now().UnixMilli()
	canonicalForged := CanonicalChannelInvite(roomID, charlie.Address(), rootKey.String(), 1, now+60000)
	forgedSig := hex.EncodeToString(idC.Sign(canonicalForged))
	forgedInv := &ChannelInvite{
		RoomID:     roomID,
		InviterPub: charlie.Address(),
		RoomKey:    rootKey.String(),
		EpochID:    1,
		ExpiresAt:  now + 60000,
		Signature:  forgedSig,
	}

	// E presents this forged invite to Alice and Bob
	if err := alice.VerifyChannelInvite(forgedInv); err == nil {
		t.Fatalf("alice verified invite from evicted charlie!")
	}
	t.Logf("confirmed: alice rejected invite from evicted charlie: %v", err)

	edward.SetChannelInvite(forgedInv)
	trA.Connect(trE)
	trB.Connect(trE)
	trD.Connect(trE)
	edward.BroadcastPeerInfo()
	time.Sleep(50 * time.Millisecond)

	// Alice and Bob must NOT admit Edward
	if alice.IsAdmittedMember(edward.Address()) || bob.IsAdmittedMember(edward.Address()) {
		t.Fatalf("alice or bob admitted edward who was invited by evicted charlie!")
	}

	// 7. Edward attempts an unauthorized EpochCommit (claiming next epoch ratchet)
	rogueEpoch := evictEpoch + 1
	rogueCommit := &EpochCommit{
		EpochID:   rogueEpoch,
		RoomID:    roomID,
		Evictor:   edward.Address(),
		Reason:    "rogue takeover attempt",
		MLSCommit: &MLSCommit{Epoch: uint64(rogueEpoch), CommitterLeaf: 0},
		Timestamp: time.Now().UnixMilli(),
	}
	rogueCanonical := CanonicalEpochCommitFromCommit(rogueCommit)
	rogueCommit.Signature = hex.EncodeToString(idE.Sign(rogueCanonical))

	rogueFrame := mustMarshalGroupPacket(t, edward, PortEpochCommit, rogueCommit)
	trE.Send(alice.Address(), rogueFrame)
	trE.Send(bob.Address(), rogueFrame)
	trE.Send(dave.Address(), rogueFrame)
	time.Sleep(50 * time.Millisecond)

	// OG group MUST reject rogue commit: epoch remains at evictEpoch!
	if alice.CurrentEpoch() != evictEpoch || bob.CurrentEpoch() != evictEpoch || dave.CurrentEpoch() != evictEpoch {
		t.Fatalf("OG group epoch was manipulated by unauthorized edward! A=%d, B=%d, D=%d",
			alice.CurrentEpoch(), bob.CurrentEpoch(), dave.CurrentEpoch())
	}

	// Charlie is NEVER re-admitted to the OG group
	if alice.IsAdmittedMember(charlie.Address()) || bob.IsAdmittedMember(charlie.Address()) {
		t.Fatalf("evicted charlie was re-admitted to the OG group!")
	}

	// OG group exchanges secure Epoch 2 message
	msg2 := "epoch-2-strictly-sealed-group-message"
	env2, err := alice.SendMessage(msg2)
	if err != nil {
		t.Fatalf("alice failed to send msg2: %v", err)
	}
	frame2 := mustMarshalGroupPacket(t, alice, PortChat, env2)
	trA.Send(bob.Address(), frame2)
	trA.Send(dave.Address(), frame2)
	trA.Send(charlie.Address(), frame2)
	trA.Send(edward.Address(), frame2)
	time.Sleep(50 * time.Millisecond)

	// Bob and Dave deciphered msg2
	muB.Lock()
	bGot2 := len(receivedB) > 1 && strings.Contains(receivedB[1], msg2)
	muB.Unlock()
	muD.Lock()
	dGot2 := len(receivedD) > 1 && strings.Contains(receivedD[1], msg2)
	muD.Unlock()
	if !bGot2 || !dGot2 {
		t.Fatalf("bob or dave failed to receive msg2 at epoch 2: b=%v, d=%v", bGot2, dGot2)
	}

	// Charlie and Edward CANNOT decipher msg2
	muC.Lock()
	cGot2 := len(receivedC) > 1
	muC.Unlock()
	muE.Lock()
	eGot2 := len(receivedE) > 0
	muE.Unlock()
	if cGot2 || eGot2 {
		t.Fatalf("security violation: charlie or edward received sealed epoch 2 message! cGot2=%v, eGot2=%v", cGot2, eGot2)
	}
	t.Log("SUCCESS: OG group remained securely isolated on Epoch 2, rogue invites rejected, unauthorized commits dropped, Charlie never re-admitted!")
}

func mustMarshalGroupPacket(t *testing.T, sender *Node, port Port, body any) []byte {
	t.Helper()
	key := sender.BootstrapKey
	epoch := int64(0)
	if port != PortEpochCommit && port != PortGroupPeerInfo {
		key, epoch = sender.activeKeyAndEpoch()
	}
	pkt, err := NewGroupPacket(sender.ID, BroadcastAddr, sender.ChannelHash, epoch, key, port, 3, body)
	if err != nil {
		t.Fatalf("NewGroupPacket failed: %v", err)
	}
	data, err := MarshalPacket(pkt)
	if err != nil {
		t.Fatalf("MarshalPacket failed: %v", err)
	}
	return data
}

// TestMLS_PFS_PCS_StrictEpochIsolation verifies RFC 9420 PFS, PCS, and epoch isolation invariants:
// 1. Pre-Join Forward Secrecy: Late joiners cannot decrypt messages sent in pre-join epochs.
// 2. Reconnection & Catch-Up: Non-evicted peers recovering from offline catch up missed commits sequentially and decrypt missed messages.
// 3. Post-Eviction PCS: Evicted peers cannot decrypt post-eviction messages, cannot commit, and cannot issue valid invites.
func TestMLS_PFS_PCS_StrictEpochIsolation(t *testing.T) {
	roomID := "room-pfs-pcs-strict-isolation"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var muA, muB, muC, muD sync.Mutex
	var receivedA, receivedB, receivedC, receivedD []string

	alice, trA := newTestNode(t, "seed-strict-alice-01", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muA.Lock()
			receivedA = append(receivedA, string(pt))
			muA.Unlock()
		},
	})
	bob, trB := newTestNode(t, "seed-strict-bob-02", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muB.Lock()
			receivedB = append(receivedB, string(pt))
			muB.Unlock()
		},
	})
	charlie, trC := newTestNode(t, "seed-strict-charlie-03", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muC.Lock()
			receivedC = append(receivedC, string(pt))
			muC.Unlock()
		},
	})
	dave, trD := newTestNode(t, "seed-strict-dave-04", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			muD.Lock()
			receivedD = append(receivedD, string(pt))
			muD.Unlock()
		},
	})

	// --- Phase 1: Alice creates room at Epoch 1, sends M1 and F1, then admits Bob (Epoch 1 -> 2) ---
	if err := alice.InitGenesisEpoch(); err != nil {
		t.Fatalf("alice init genesis epoch failed: %v", err)
	}

	// Alice sends M1 and attachment F1 at Epoch 1 BEFORE Bob joins
	msgEpoch1 := "secret-epoch-1-prior-to-bob-join"
	env1, err := alice.SendMessage(msgEpoch1)
	if err != nil {
		t.Fatalf("alice send M1 failed: %v", err)
	}
	if env1.EpochID != 1 {
		t.Fatalf("expected env1 epoch 1, got %d", env1.EpochID)
	}
	metaF1, err := alice.ShareAttachment("epoch1-secret.bin", "application/octet-stream", []byte("epoch-1-confidential-attachment-payload-01"))
	if err != nil {
		t.Fatalf("alice offer F1 failed: %v", err)
	}
	if metaF1.EpochID != 1 {
		t.Fatalf("expected metaF1 epoch 1, got %d", metaF1.EpochID)
	}

	invB, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice failed to create invite for bob: %v", err)
	}
	bob.SetChannelInvite(invB)

	trA.Connect(trB)
	alice.AddPeer(bob.Address())
	bob.AddPeer(alice.Address())
	alice.BroadcastPeerInfo()
	bob.BroadcastPeerInfo()

	// Wait for Alice to admit Bob
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		if alice.CurrentEpoch() >= 2 && bob.CurrentEpoch() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if alice.CurrentEpoch() != 2 || bob.CurrentEpoch() != 2 {
		t.Fatalf("expected alice & bob at epoch 2, got alice=%d, bob=%d", alice.CurrentEpoch(), bob.CurrentEpoch())
	}

	// Verify Bob (joined at Epoch 2) cannot decrypt M1 or download F1, and SyncRequest does not return M1 or F1
	if _, err := env1.Decrypt(bob.RoomKey); err == nil {
		t.Fatal("cryptographic violation: Bob decrypted pre-join Epoch 1 message M1!")
	}
	bob.HandleWire(alice.Address(), mustMarshalGroupPacket(t, alice, PortAttachMeta, metaF1))
	if err := bob.DownloadAttachment(metaF1.FileID); err == nil {
		t.Fatal("security violation: Bob was permitted to download pre-join Epoch 1 attachment F1!")
	}

	// Alice sends message M2 and attachment F2 at Epoch 2
	msgEpoch2 := "secret-epoch-2-prior-to-charlie-join"
	env2, err := alice.SendMessage(msgEpoch2)
	if err != nil {
		t.Fatalf("alice send message failed: %v", err)
	}
	if env2.EpochID != 2 {
		t.Fatalf("expected env2 epoch 2, got %d", env2.EpochID)
	}
	metaF2, err := alice.ShareAttachment("epoch2-secret.bin", "application/octet-stream", []byte("epoch-2-confidential-attachment-payload-02"))
	if err != nil {
		t.Fatalf("alice offer F2 failed: %v", err)
	}
	trA.Send(bob.Address(), mustMarshalGroupPacket(t, alice, PortChat, env2))
	time.Sleep(50 * time.Millisecond)

	muB.Lock()
	bGot2 := len(receivedB) > 0 && strings.Contains(receivedB[0], msgEpoch2)
	muB.Unlock()
	if !bGot2 {
		t.Fatalf("bob failed to receive epoch 2 message")
	}

	// --- Phase 2: Charlie joins late at Epoch 3 (Pre-Join Forward Secrecy) ---
	invC, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice failed to create invite for charlie: %v", err)
	}
	charlie.SetChannelInvite(invC)

	trA.Connect(trC)
	trB.Connect(trC)
	alice.AddPeer(charlie.Address())
	bob.AddPeer(charlie.Address())
	charlie.AddPeer(alice.Address())
	charlie.AddPeer(bob.Address())

	charlie.BroadcastPeerInfo()
	alice.BroadcastPeerInfo()
	bob.BroadcastPeerInfo()

	// Wait for Charlie admission (Epoch 2 -> 3)
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		if charlie.CurrentEpoch() >= 3 && alice.CurrentEpoch() >= 3 && bob.CurrentEpoch() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if charlie.CurrentEpoch() != 3 {
		t.Fatalf("expected charlie at epoch 3, got %d", charlie.CurrentEpoch())
	}
	if charlie.JoinedEpoch() != 3 {
		t.Fatalf("expected charlie joinedEpoch 3, got %d", charlie.JoinedEpoch())
	}

	// Charlie tries to direct-decrypt env1 & env2 with his current room key: MUST FAIL
	if _, err := env1.Decrypt(charlie.RoomKey); err == nil {
		t.Fatalf("cryptographic failure: late-joining charlie successfully decrypted pre-join Epoch 1 message!")
	}
	_, err = env2.Decrypt(charlie.RoomKey)
	if err == nil {
		t.Fatalf("cryptographic failure: late-joining charlie successfully decrypted pre-join Epoch 2 message!")
	}

	// Charlie tries to download pre-join attachments F1 and F2: MUST FAIL
	charlie.HandleWire(alice.Address(), mustMarshalGroupPacket(t, alice, PortAttachMeta, metaF2))
	if err := charlie.DownloadAttachment(metaF2.FileID); err == nil {
		t.Fatalf("security violation: charlie was permitted to download pre-join Epoch 2 attachment F2!")
	}

	// Charlie requests catch-up: Bob and Alice MUST NOT deliver pre-join Epoch 1/2 messages or offers to Charlie
	if err := charlie.RequestCatchUp(); err != nil {
		t.Fatalf("charlie request catch up failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	muC.Lock()
	cGotPreJoin := len(receivedC) > 0
	muC.Unlock()
	if cGotPreJoin {
		t.Fatalf("security violation: charlie received pre-join messages: %v", receivedC)
	}
	if offers := charlie.AttachmentOffers(); len(offers) > 0 {
		t.Fatalf("security violation: charlie received pre-join attachment offers (joined=%d): %+v", charlie.JoinedEpoch(), offers[0])
	}

	// Active chat at Epoch 3: Alice sends message, all 3 receive it
	msgEpoch3 := "active-epoch-3-message"
	env3, err := alice.SendMessage(msgEpoch3)
	if err != nil {
		t.Fatalf("alice send msg3 failed: %v", err)
	}
	trA.Send(bob.Address(), mustMarshalGroupPacket(t, alice, PortChat, env3))
	trA.Send(charlie.Address(), mustMarshalGroupPacket(t, alice, PortChat, env3))
	time.Sleep(50 * time.Millisecond)

	muB.Lock()
	bGot3 := len(receivedB) > 1 && strings.Contains(receivedB[1], msgEpoch3)
	muB.Unlock()
	muC.Lock()
	cGot3 := len(receivedC) > 0 && strings.Contains(receivedC[0], msgEpoch3)
	muC.Unlock()
	if !bGot3 || !cGot3 {
		t.Fatalf("failed to receive epoch 3 message: b=%v, c=%v", bGot3, cGot3)
	}

	// --- Phase 3: Bob goes offline. Alice sends M3_offline (Epoch 3), Dave joins (Epoch 4), Dave sends M4_offline. ---
	trA.Block(bob.Address())
	trB.Block(alice.Address())
	trB.Block(charlie.Address())
	trC.Block(bob.Address())

	msgEpoch3Offline := "alice-epoch-3-message-while-bob-offline"
	env3Offline, err := alice.SendMessage(msgEpoch3Offline)
	if err != nil {
		t.Fatalf("alice send msg3_offline failed: %v", err)
	}
	trA.Send(charlie.Address(), mustMarshalGroupPacket(t, alice, PortChat, env3Offline))
	time.Sleep(30 * time.Millisecond)

	invD, err := alice.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("alice failed to create invite for dave: %v", err)
	}
	dave.SetChannelInvite(invD)

	trA.Connect(trD)
	trC.Connect(trD)
	alice.AddPeer(dave.Address())
	charlie.AddPeer(dave.Address())
	dave.AddPeer(alice.Address())
	dave.AddPeer(charlie.Address())

	dave.BroadcastPeerInfo()
	alice.BroadcastPeerInfo()
	charlie.BroadcastPeerInfo()

	// Wait for Dave admission (Epoch 3 -> 4)
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		if dave.CurrentEpoch() >= 4 && alice.CurrentEpoch() >= 4 && charlie.CurrentEpoch() >= 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dave.CurrentEpoch() != 4 || alice.CurrentEpoch() != 4 {
		t.Fatalf("expected alice & dave at epoch 4, got alice=%d, dave=%d", alice.CurrentEpoch(), dave.CurrentEpoch())
	}

	// Dave sends message while Bob is offline
	msgEpoch4 := "dave-message-sent-at-epoch-4-while-bob-was-offline"
	env4, err := dave.SendMessage(msgEpoch4)
	if err != nil {
		t.Fatalf("dave send msg4 failed: %v", err)
	}
	trD.Send(alice.Address(), mustMarshalGroupPacket(t, dave, PortChat, env4))
	trD.Send(charlie.Address(), mustMarshalGroupPacket(t, dave, PortChat, env4))
	time.Sleep(50 * time.Millisecond)

	muA.Lock()
	aGot4 := len(receivedA) > 0 && strings.Contains(receivedA[0], msgEpoch4)
	muA.Unlock()
	muC.Lock()
	cGot4 := false
	for _, m := range receivedC {
		if strings.Contains(m, msgEpoch4) {
			cGot4 = true
			break
		}
	}
	muC.Unlock()
	if !aGot4 || !cGot4 {
		t.Fatalf("alice or charlie failed to receive epoch 4 message: a=%v, c=%v", aGot4, cGot4)
	}

	// Bob is still at Epoch 3 and has not received msgEpoch3Offline or msgEpoch4
	if bob.CurrentEpoch() != 3 {
		t.Fatalf("bob unexpectedly advanced past epoch 3 while offline: %d", bob.CurrentEpoch())
	}

	// --- Phase 4: Bob reconnects, catches up missed commits and decrypts BOTH msgEpoch3Offline and msgEpoch4 ---
	trA.mu.Lock()
	delete(trA.blocked, bob.Address())
	trA.mu.Unlock()

	trB.mu.Lock()
	delete(trB.blocked, alice.Address())
	delete(trB.blocked, charlie.Address())
	trB.mu.Unlock()

	trC.mu.Lock()
	delete(trC.blocked, bob.Address())
	trC.mu.Unlock()

	trB.Connect(trD)
	bob.AddPeer(dave.Address())
	dave.AddPeer(bob.Address())
	bob.BroadcastPeerInfo()
	dave.BroadcastPeerInfo()

	// Bob triggers catch-up
	if err := bob.RequestCatchUp(); err != nil {
		t.Fatalf("bob request catch up failed: %v", err)
	}

	// Wait for Bob to catch up to Epoch 4 and decrypt both msgEpoch3Offline and msgEpoch4
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		muB.Lock()
		bHasMsg3Off := false
		bHasMsg4 := false
		for _, m := range receivedB {
			if strings.Contains(m, msgEpoch3Offline) {
				bHasMsg3Off = true
			}
			if strings.Contains(m, msgEpoch4) {
				bHasMsg4 = true
			}
		}
		muB.Unlock()
		if bob.CurrentEpoch() >= 4 && bHasMsg3Off && bHasMsg4 {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}

	if bob.CurrentEpoch() != 4 {
		t.Fatalf("bob failed to ratchet to epoch 4 after catch-up, current: %d", bob.CurrentEpoch())
	}
	muB.Lock()
	bHas3Off := false
	bHas4 := false
	for _, m := range receivedB {
		if strings.Contains(m, msgEpoch3Offline) {
			bHas3Off = true
		}
		if strings.Contains(m, msgEpoch4) {
			bHas4 = true
		}
	}
	muB.Unlock()
	if !bHas3Off || !bHas4 {
		t.Fatalf("bob failed to decrypt missed epoch 3/4 messages after reconnecting: bHas3Off=%v, bHas4=%v", bHas3Off, bHas4)
	}

	// --- Phase 5: Alice evicts Charlie (Epoch 4 -> 5, Post-Compromise Security) ---
	evictCommit, err := alice.EvictPeer(charlie.Address(), "violating terms")
	if err != nil {
		t.Fatalf("alice evict charlie failed: %v", err)
	}
	if evictCommit.EpochID != 5 {
		t.Fatalf("expected evict commit epoch 5, got %d", evictCommit.EpochID)
	}

	evictFrame := mustMarshalGroupPacket(t, alice, PortEpochCommit, evictCommit)
	trA.Send(bob.Address(), evictFrame)
	trA.Send(dave.Address(), evictFrame)
	trA.Send(charlie.Address(), evictFrame)
	time.Sleep(50 * time.Millisecond)

	if alice.CurrentEpoch() != 5 || bob.CurrentEpoch() != 5 || dave.CurrentEpoch() != 5 {
		t.Fatalf("remaining peers failed to advance to epoch 5: a=%d, b=%d, d=%d", alice.CurrentEpoch(), bob.CurrentEpoch(), dave.CurrentEpoch())
	}

	// Alice sends message at Epoch 5
	msgEpoch5 := "post-eviction-confidential-epoch-5-message"
	env5, err := alice.SendMessage(msgEpoch5)
	if err != nil {
		t.Fatalf("alice send msg5 failed: %v", err)
	}
	if env5.EpochID != 5 {
		t.Fatalf("expected env5 epoch 5, got %d", env5.EpochID)
	}
	msg5Frame := mustMarshalGroupPacket(t, alice, PortChat, env5)
	trA.Send(bob.Address(), msg5Frame)
	trA.Send(dave.Address(), msg5Frame)
	trA.Send(charlie.Address(), msg5Frame)
	time.Sleep(50 * time.Millisecond)

	// Bob and Dave decrypted msgEpoch5
	muB.Lock()
	bGot5 := false
	for _, m := range receivedB {
		if strings.Contains(m, msgEpoch5) {
			bGot5 = true
			break
		}
	}
	muB.Unlock()
	muD.Lock()
	dGot5 := false
	for _, m := range receivedD {
		if strings.Contains(m, msgEpoch5) {
			dGot5 = true
			break
		}
	}
	muD.Unlock()
	if !bGot5 || !dGot5 {
		t.Fatalf("bob or dave failed to decrypt epoch 5 message: b=%v, d=%v", bGot5, dGot5)
	}

	// Charlie CANNOT decrypt msgEpoch5
	muC.Lock()
	cGot5 := false
	for _, m := range receivedC {
		if strings.Contains(m, msgEpoch5) {
			cGot5 = true
			break
		}
	}
	muC.Unlock()
	if cGot5 {
		t.Fatalf("security violation: evicted charlie deciphered post-eviction Epoch 5 message!")
	}

	// Charlie direct-decrypt test MUST FAIL
	_, err = env5.Decrypt(charlie.RoomKey)
	if err == nil {
		t.Fatalf("security violation: evicted charlie successfully decrypted env5 ciphertext!")
	}

	// Charlie cannot create channel invites
	_, err = charlie.CreateChannelInvite(15 * time.Minute)
	if err == nil {
		t.Fatalf("security violation: evicted charlie was permitted to create channel invite!")
	}

	t.Log("SUCCESS: TestMLS_PFS_PCS_StrictEpochIsolation passed with pre-join PFS, commit catch-up, and post-eviction PCS!")
}

// TestMLS_EvictedEviction_Scenario tests the user's specific scenario:
// A creates a new (burner room)
// A invites B
// B comes in and chats with A
// B invites C
// C joins the chat with A and B
// B gets evicted
// A and C can and continue to chat
// B evicts both A and C -> VERIFY: B CANNOT evict A or C, A and C continue chatting cleanly!
func TestMLS_EvictedEviction_Scenario(t *testing.T) {
	roomID := "room-evicted-eviction-scenario"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var mu sync.Mutex
	var msgsA, msgsB, msgsC []string

	// Node A (Room creator)
	nodeA, trA := newTestNode(t, "seed-alice-ee-scenario", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			mu.Lock()
			msgsA = append(msgsA, string(pt))
			mu.Unlock()
		},
	})
	// Node B
	nodeB, trB := newTestNode(t, "seed-bob-ee-scenario", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			mu.Lock()
			msgsB = append(msgsB, string(pt))
			mu.Unlock()
		},
	})
	// Node C
	nodeC, trC := newTestNode(t, "seed-charlie-ee-scenario", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) {
			mu.Lock()
			msgsC = append(msgsC, string(pt))
			mu.Unlock()
		},
	})

	// 1. A creates a new burner room (Genesis Epoch 1)
	if err := nodeA.InitGenesisEpoch(); err != nil {
		t.Fatalf("A failed to init genesis epoch: %v", err)
	}
	invA, err := nodeA.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("A failed to create invite for B: %v", err)
	}

	// 2. A invites B; B joins
	nodeB.SetChannelInvite(invA)
	trA.Connect(trB)
	nodeA.AddPeer(nodeB.Address())
	nodeB.AddPeer(nodeA.Address())
	nodeA.BroadcastPeerInfo()
	nodeB.BroadcastPeerInfo()

	// Wait for A to admit B (Epoch 1 -> 2)
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		if nodeA.CurrentEpoch() >= 2 && nodeB.CurrentEpoch() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if nodeA.CurrentEpoch() < 2 || nodeB.CurrentEpoch() < 2 {
		t.Fatalf("B was not admitted: A epoch=%d, B epoch=%d", nodeA.CurrentEpoch(), nodeB.CurrentEpoch())
	}

	// 3. B comes in and chats with A
	msgB1 := "Hello from B to A"
	_, err = nodeB.SendMessage(msgB1)
	if err != nil {
		t.Fatalf("B failed to send message: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	aGotB := len(msgsA) > 0 && strings.Contains(msgsA[0], msgB1)
	mu.Unlock()
	if !aGotB {
		t.Fatalf("A did not receive B's message: %v", msgsA)
	}

	// 4. B invites C
	invB, err := nodeB.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("B failed to create invite for C: %v", err)
	}
	nodeC.SetChannelInvite(invB)
	trA.Connect(trC)
	trB.Connect(trC)
	nodeA.AddPeer(nodeC.Address())
	nodeC.AddPeer(nodeA.Address())
	nodeB.AddPeer(nodeC.Address())
	nodeC.AddPeer(nodeB.Address())
	nodeA.BroadcastPeerInfo()
	nodeB.BroadcastPeerInfo()
	nodeC.BroadcastPeerInfo()

	// Wait for C to be admitted (Epoch 2 -> 3)
	for start := time.Now(); time.Since(start) < 2*time.Second; {
		if nodeA.CurrentEpoch() >= 3 && nodeB.CurrentEpoch() >= 3 && nodeC.CurrentEpoch() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if nodeA.CurrentEpoch() < 3 || nodeC.CurrentEpoch() < 3 {
		t.Fatalf("C was not admitted: A epoch=%d, C epoch=%d", nodeA.CurrentEpoch(), nodeC.CurrentEpoch())
	}

	// 5. C joins the chat with A and B
	msgC1 := "Hello from C to everyone"
	_, err = nodeC.SendMessage(msgC1)
	if err != nil {
		t.Fatalf("C failed to send message: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	aGotC := false
	for _, m := range msgsA {
		if strings.Contains(m, msgC1) {
			aGotC = true
		}
	}
	bGotC := false
	for _, m := range msgsB {
		if strings.Contains(m, msgC1) {
			bGotC = true
		}
	}
	mu.Unlock()
	if !aGotC || !bGotC {
		t.Fatalf("A or B did not receive C's message: aGot=%v, bGot=%v", aGotC, bGotC)
	}

	// 6. B gets evicted by A (Epoch 3 -> 4)
	evictCommit, err := nodeA.EvictPeer(nodeB.Address(), "violating terms")
	if err != nil {
		t.Fatalf("A failed to evict B: %v", err)
	}
	if evictCommit.EpochID != 4 {
		t.Fatalf("expected evictCommit epoch 4, got %d", evictCommit.EpochID)
	}
	time.Sleep(60 * time.Millisecond)

	if nodeA.CurrentEpoch() != 4 || nodeC.CurrentEpoch() != 4 {
		t.Fatalf("A or C failed to ratchet to epoch 4 after B evicted: A=%d, C=%d", nodeA.CurrentEpoch(), nodeC.CurrentEpoch())
	}
	if !nodeB.IsPeerEvicted(nodeB.Address()) {
		t.Fatalf("B does not see itself as evicted")
	}

	// 7. A and C can and continue to chat
	msgA2 := "Hello C, B is gone and we are secure at Epoch 4"
	_, err = nodeA.SendMessage(msgA2)
	if err != nil {
		t.Fatalf("A failed to send message: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	cGotA2 := false
	for _, m := range msgsC {
		if strings.Contains(m, msgA2) {
			cGotA2 = true
		}
	}
	bGotA2 := false
	for _, m := range msgsB {
		if strings.Contains(m, msgA2) {
			bGotA2 = true
		}
	}
	mu.Unlock()
	if !cGotA2 {
		t.Fatalf("C did not receive A's post-eviction message")
	}
	if bGotA2 {
		t.Fatalf("security violation: evicted B received post-eviction message!")
	}

	// C broadcasts PeerInfo: A must NOT drop C even though C's inviter B was evicted!
	nodeC.BroadcastPeerInfo()
	time.Sleep(50 * time.Millisecond)

	if !nodeA.IsAdmittedMember(nodeC.Address()) {
		t.Fatalf("regression: A dropped C after C broadcast PeerInfo with evicted inviter!")
	}
	if nodeA.PeerEncKeys()[nodeC.Address()] == "" {
		t.Fatalf("A lost encryption key for C!")
	}

	// C sends message to A; A receives and verifies
	msgC2 := "Hello A, I am still here chatting securely"
	_, err = nodeC.SendMessage(msgC2)
	if err != nil {
		t.Fatalf("C failed to send message: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	aGotC2 := false
	for _, m := range msgsA {
		if strings.Contains(m, msgC2) {
			aGotC2 = true
		}
	}
	mu.Unlock()
	if !aGotC2 {
		t.Fatalf("A did not receive C's message after PeerInfo broadcast")
	}

	// 8. B attempts to evict both A and C
	// First: via API
	_, errEvictA := nodeB.EvictPeer(nodeA.Address(), "B rogue evicts A")
	if errEvictA == nil {
		t.Fatalf("security violation: evicted B was permitted to call EvictPeer(A)!")
	}
	_, errEvictC := nodeB.EvictPeer(nodeC.Address(), "B rogue evicts C")
	if errEvictC == nil {
		t.Fatalf("security violation: evicted B was permitted to call EvictPeer(C)!")
	}

	// Second: via forged EpochCommit frames delivered to A and C
	now := time.Now().UnixMilli()
	commitBA := &EpochCommit{
		EpochID:       5,
		RoomID:        roomID,
		Evictor:       nodeB.Address(),
		EvictorEncPub: nodeB.ID.EncAddress(),
		EvictedPeer:   nodeA.Address(),
		Reason:        "B rogue evicts A",
		Timestamp:     now,
	}
	canonicalBA := CanonicalEpochCommitFromCommit(commitBA)
	commitBA.Signature = hex.EncodeToString(nodeB.ID.Sign(canonicalBA))
	frameBA := mustMarshalGroupPacket(t, nodeB, PortEpochCommit, commitBA)
	nodeA.HandleWire(nodeB.Address(), frameBA)
	nodeC.HandleWire(nodeB.Address(), frameBA)

	commitBC := &EpochCommit{
		EpochID:       6,
		RoomID:        roomID,
		Evictor:       nodeB.Address(),
		EvictorEncPub: nodeB.ID.EncAddress(),
		EvictedPeer:   nodeC.Address(),
		Reason:        "B rogue evicts C",
		Timestamp:     now,
	}
	canonicalBC := CanonicalEpochCommitFromCommit(commitBC)
	commitBC.Signature = hex.EncodeToString(nodeB.ID.Sign(canonicalBC))
	frameBC := mustMarshalGroupPacket(t, nodeB, PortEpochCommit, commitBC)
	nodeA.HandleWire(nodeB.Address(), frameBC)
	nodeC.HandleWire(nodeB.Address(), frameBC)
	time.Sleep(50 * time.Millisecond)

	// Neither A nor C must be evicted! Both remain on Epoch 4.
	if nodeA.IsPeerEvicted(nodeA.Address()) {
		t.Fatalf("vulnerability: A was evicted by rogue commit from evicted B!")
	}
	if nodeC.IsPeerEvicted(nodeC.Address()) {
		t.Fatalf("vulnerability: C was evicted by rogue commit from evicted B!")
	}
	if nodeA.CurrentEpoch() != 4 || nodeC.CurrentEpoch() != 4 {
		t.Fatalf("A or C epoch corrupted by rogue commit from evicted B: A=%d, C=%d", nodeA.CurrentEpoch(), nodeC.CurrentEpoch())
	}

	// 9. A and C continue to chat smoothly!
	msgA3 := "Final confirmation: A and C are chatting peacefully"
	_, err = nodeA.SendMessage(msgA3)
	if err != nil {
		t.Fatalf("A failed to send message: %v", err)
	}
	msgC3 := "Final confirmation: C confirms message from A"
	_, err = nodeC.SendMessage(msgC3)
	if err != nil {
		t.Fatalf("C failed to send message: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	cGotA3 := false
	for _, m := range msgsC {
		if strings.Contains(m, msgA3) {
			cGotA3 = true
		}
	}
	aGotC3 := false
	for _, m := range msgsA {
		if strings.Contains(m, msgC3) {
			aGotC3 = true
		}
	}
	mu.Unlock()
	if !cGotA3 || !aGotC3 {
		t.Fatalf("A and C could not chat after B's rogue eviction attempts: cGotA3=%v, aGotC3=%v", cGotA3, aGotC3)
	}

	t.Log("SUCCESS: TestMLS_EvictedEviction_Scenario verified: B cannot evict A or C, A and C continue chatting cleanly!")
}

// TestRelayedSync_TargetsLivePeersAndAuthenticatesOrigin verifies that:
// 1. RequestCatchUpNextBatch only targets live Transport.Peers(), ignoring stale overlay entries.
// 2. A 2-hop relayed PortSyncReq authenticates pkt.From (not the relay hop) and routes PortSyncRes back to pkt.From.
// 3. A relayed PortSyncReq from an evicted peer via an admitted relay is rejected.
func TestRelayedSync_TargetsLivePeersAndAuthenticatesOrigin(t *testing.T) {
	roomID := "room-relayed-sync-origin"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var aliceGot, daveGot atomic.Int64
	alice, trAlice := newTestNode(t, "seed-relayed-sync-alice-01", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) { aliceGot.Add(1) },
	})
	bob, trBob := newTestNode(t, "seed-relayed-sync-bob-02", roomID, roomKey, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "seed-relayed-sync-charlie-03", roomID, roomKey, cfg, Hooks{})
	dave, trDave := newTestNode(t, "seed-relayed-sync-dave-04", roomID, roomKey, cfg, Hooks{
		OnMessage: func(env *Envelope, pt []byte) { daveGot.Add(1) },
	})

	// Line topology: alice <-> bob <-> charlie, and dave <-> bob
	trAlice.Connect(trBob)
	trBob.Connect(trCharlie)
	trDave.Connect(trBob)
	alice.AddPeer(bob.Address())
	bob.AddPeer(alice.Address())
	bob.AddPeer(charlie.Address())
	charlie.AddPeer(bob.Address())
	dave.AddPeer(bob.Address())
	bob.AddPeer(dave.Address())

	// Poison alice's overlay with disconnected charlie; RequestCatchUpNextBatch must still pick only live bob.
	alice.AddPeer(charlie.Address())
	for round := 0; round < 5; round++ {
		chosen, err := alice.RequestCatchUpNextBatch()
		if err != nil {
			t.Fatalf("round %d RequestCatchUpNextBatch: %v", round, err)
		}
		if len(chosen) != 1 || chosen[0] != bob.Address() {
			t.Fatalf("round %d expected only live peer bob, got %v", round, chosen)
		}
	}

	// Put a message only in charlie's ring buffer and mark dave as evicted on charlie.
	plain, _ := json.Marshal(ChatPayload{Type: "chat", Text: "charlie-only-history"})
	env, err := NewEnvelopeWithEpoch(charlie.ID, roomID, roomKey, 0, plain)
	if err != nil {
		t.Fatalf("NewEnvelopeWithEpoch: %v", err)
	}
	charlie.mu.Lock()
	charlie.RingBuffer.Push(env)
	charlie.seenEnvelopes[env.ID()] = struct{}{}
	charlie.evictedPeers[dave.Address()] = 1
	charlie.mu.Unlock()

	// Alice sends PortSyncReq addressed to charlie (relayed 2 hops through bob).
	reqAlice := SyncRequest{RoomID: roomID}
	if err := alice.sendBootstrapGroupPacket(alice.ChannelState, charlie.Address(), PortSyncReq, reqAlice); err != nil {
		t.Fatalf("alice sendBootstrapGroupPacket: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && aliceGot.Load() == 0 {
		time.Sleep(15 * time.Millisecond)
	}
	if aliceGot.Load() != 1 {
		t.Fatalf("alice received %d messages from 2-hop relayed sync, expected 1", aliceGot.Load())
	}

	// Evicted dave sends PortSyncReq addressed to charlie via admitted relay bob -> must be rejected.
	reqDave := SyncRequest{RoomID: roomID}
	if err := dave.sendBootstrapGroupPacket(dave.ChannelState, charlie.Address(), PortSyncReq, reqDave); err != nil {
		t.Fatalf("dave sendBootstrapGroupPacket: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if daveGot.Load() != 0 {
		t.Fatalf("evicted dave received %d messages via admitted relay bob, expected 0", daveGot.Load())
	}
}

// TestGroupDiscover_ExpandingRingAcrossTwoHopsWithMLS verifies that an Epoch 0 newcomer
// and an Epoch 3 member 2 hops apart discover each other even when an already-connected
// 1-hop room member replies immediately to ttl=1 probes.
func TestGroupDiscover_ExpandingRingAcrossTwoHopsWithMLS(t *testing.T) {
	roomID := "room-group-discover-2hop-mls"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()
	cfg.BroadcastHopTimeout = 25 * time.Millisecond

	var mu sync.Mutex
	daveSawBob := false
	bobSawDave := false

	alice, trAlice := newTestNode(t, "seed-gd-alice-01", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "seed-gd-bob-02", roomID, roomKey, cfg, Hooks{
		OnChannelDiscovered: func(channelID, peer string) {
			mu.Lock()
			if channelID == roomID && peer != "" {
				// checked after dave is created
			}
			mu.Unlock()
		},
	})
	charlie, trCharlie := newTestNode(t, "seed-gd-charlie-03", roomID, roomKey, cfg, Hooks{})
	dave, trDave := newTestNode(t, "seed-gd-dave-04", roomID, roomKey, cfg, Hooks{})

	defer func() {
		alice.StopMeshSupervisor()
		bob.StopMeshSupervisor()
		charlie.StopMeshSupervisor()
		dave.StopMeshSupervisor()
	}()

	bob.Hooks.OnChannelDiscovered = func(channelID, peer string) {
		mu.Lock()
		if channelID == roomID && peer == dave.Address() {
			bobSawDave = true
		}
		mu.Unlock()
	}
	dave.Hooks.OnChannelDiscovered = func(channelID, peer string) {
		mu.Lock()
		if channelID == roomID && peer == bob.Address() {
			daveSawBob = true
		}
		mu.Unlock()
	}

	// Establish MLS Epoch 3 across alice, bob, charlie.
	if err := alice.InitGenesisEpoch(); err != nil {
		t.Fatalf("alice InitGenesisEpoch: %v", err)
	}
	invB, _ := alice.CreateChannelInvite(15 * time.Minute)
	invC, _ := alice.CreateChannelInvite(15 * time.Minute)
	bob.SetChannelInvite(invB)
	charlie.SetChannelInvite(invC)
	connectFullMesh([]*Node{alice, bob, charlie}, []*memoryTransport{trAlice, trBob, trCharlie})

	settle := time.Now().Add(2 * time.Second)
	for time.Now().Before(settle) {
		if alice.CurrentEpoch() >= 3 && bob.CurrentEpoch() == alice.CurrentEpoch() && charlie.CurrentEpoch() == alice.CurrentEpoch() {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if bob.CurrentEpoch() < 3 {
		t.Fatalf("expected bob at MLS epoch >= 3, got %d", bob.CurrentEpoch())
	}

	// Dave joins at Epoch 0 connected only to charlie and alice (NOT bob).
	trDave.Connect(trCharlie)
	trDave.Connect(trAlice)
	dave.AddPeer(charlie.Address())
	charlie.AddPeer(dave.Address())
	dave.AddPeer(alice.Address())
	alice.AddPeer(dave.Address())

	// Trigger expanding-ring group discovery on both bob (Epoch 3) and dave (Epoch 0).
	if err := bob.JoinChannel(roomID); err != nil {
		t.Fatalf("bob JoinChannel: %v", err)
	}
	if err := dave.JoinChannel(roomID); err != nil {
		t.Fatalf("dave JoinChannel: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := daveSawBob && bobSawDave
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("2-hop MLS group discovery failed: daveSawBob=%v bobSawDave=%v", daveSawBob, bobSawDave)
}

type syncCountingTransport struct {
	*memoryTransport
	roomKey    RoomKey
	syncReqs   atomic.Int64
	dropSyncTx atomic.Bool
}

func (s *syncCountingTransport) Send(addr string, data []byte) error {
	if pkt, err := UnmarshalPacket(data); err == nil && pkt.Encrypted && pkt.ChannelHash != 0 {
		if sd, err := OpenGroupPacket(s.roomKey, pkt); err == nil && sd.Port == PortSyncReq {
			s.syncReqs.Add(1)
			if s.dropSyncTx.Load() {
				return nil
			}
		}
	}
	return s.memoryTransport.Send(addr, data)
}

// TestSyncCatchUp_CoalescesFutureEpochBurst verifies two amplification-storm invariants:
// 1. Receiving a burst of 50 undecryptable future-epoch packets coalesces into <= 2 PortSyncReq
//    packets instead of spawning 50 parallel catch-up storms.
// 2. Receiving duplicate PortSyncRes packets carrying already-applied MLS commits and already-seen
//    envelopes emits 0 additional PortSyncReq packets and 0 duplicate OnMessage deliveries.
func TestSyncCatchUp_CoalescesFutureEpochBurst(t *testing.T) {
	roomID := "room-sync-coalesce-burst"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig()

	var daveMsgs atomic.Int64
	alice, trAlice := newTestNode(t, "seed-sync-burst-alice-01", roomID, roomKey, cfg, Hooks{})
	bob, trBob := newTestNode(t, "seed-sync-burst-bob-02", roomID, roomKey, cfg, Hooks{})
	charlie, trCharlie := newTestNode(t, "seed-sync-burst-charlie-03", roomID, roomKey, cfg, Hooks{})

	daveID, _ := NewIdentityFromSeed([]byte("seed-sync-burst-dave-04"))
	daveMem := newMemoryTransport(daveID.Address())
	daveWrap := &syncCountingTransport{memoryTransport: daveMem, roomKey: roomKey}
	dave := NewNode(daveID, roomID, roomKey, cfg, daveWrap, Hooks{
		OnMessage: func(env *Envelope, pt []byte) { daveMsgs.Add(1) },
	})
	daveMem.onData = dave.HandleWire

	defer func() {
		alice.StopMeshSupervisor()
		bob.StopMeshSupervisor()
		charlie.StopMeshSupervisor()
		dave.StopMeshSupervisor()
	}()

	// 1. Establish 4-peer MLS mesh at epoch 4.
	if err := alice.InitGenesisEpoch(); err != nil {
		t.Fatalf("alice InitGenesisEpoch: %v", err)
	}
	invB, _ := alice.CreateChannelInvite(15 * time.Minute)
	invC, _ := alice.CreateChannelInvite(15 * time.Minute)
	invD, _ := alice.CreateChannelInvite(15 * time.Minute)
	bob.SetChannelInvite(invB)
	charlie.SetChannelInvite(invC)
	dave.SetChannelInvite(invD)
	connectFullMesh([]*Node{alice, bob, charlie, dave}, []*memoryTransport{trAlice, trBob, trCharlie, daveMem})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if alice.CurrentEpoch() >= 4 &&
			bob.CurrentEpoch() == alice.CurrentEpoch() &&
			charlie.CurrentEpoch() == alice.CurrentEpoch() &&
			dave.CurrentEpoch() == alice.CurrentEpoch() {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if dave.CurrentEpoch() < 4 {
		t.Fatalf("expected dave at MLS epoch >= 4, got %d", dave.CurrentEpoch())
	}

	// 2. Disconnect dave and ratchet alice/bob/charlie to epoch 5 so dave is 1 epoch behind.
	trAlice.Disconnect(daveMem)
	trBob.Disconnect(daveMem)
	trCharlie.Disconnect(daveMem)
	dave.RemovePeer(alice.Address())
	dave.RemovePeer(bob.Address())
	dave.RemovePeer(charlie.Address())

	commit5, err := alice.RotateEpochKey()
	if err != nil {
		t.Fatalf("RotateEpochKey: %v", err)
	}
	for wait := time.Now(); time.Since(wait) < 2*time.Second; {
		if bob.CurrentEpoch() >= commit5.EpochID && charlie.CurrentEpoch() >= commit5.EpochID {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Build 50 encrypted epoch-5 chat packets on alice (and store them in alice's ring buffer).
	const burstSize = 50
	futurePackets := make([][]byte, 0, burstSize)
	for i := 0; i < burstSize; i++ {
		env, err := alice.SendMessage(fmt.Sprintf("epoch5-burst-%03d", i))
		if err != nil {
			t.Fatalf("SendMessage(%d): %v", i, err)
		}
		alice.mu.RLock()
		pkt, err := NewGroupPacket(alice.ID, BroadcastAddr, alice.ChannelState.ChannelHash, commit5.EpochID, alice.ChannelState.RoomKey, PortChat, 1, env)
		alice.mu.RUnlock()
		if err != nil {
			t.Fatalf("NewGroupPacket(%d): %v", i, err)
		}
		raw, err := MarshalPacket(pkt)
		if err != nil {
			t.Fatalf("MarshalPacket(%d): %v", i, err)
		}
		futurePackets = append(futurePackets, raw)
	}

	// 3. Reconnect dave, drop outgoing PortSyncReq temporarily so dave stays at epoch 4
	// throughout the burst, and feed all 50 future-epoch packets into dave.HandleWire.
	daveWrap.dropSyncTx.Store(true)
	daveWrap.syncReqs.Store(0)
	trAlice.Connect(daveMem)
	trBob.Connect(daveMem)
	trCharlie.Connect(daveMem)
	dave.AddPeer(alice.Address())
	dave.AddPeer(bob.Address())
	dave.AddPeer(charlie.Address())

	for _, raw := range futurePackets {
		dave.HandleWire(alice.Address(), raw)
	}
	time.Sleep(150 * time.Millisecond)

	if gotReqs := daveWrap.syncReqs.Load(); gotReqs > 2 {
		t.Errorf("future-epoch burst amplification storm: dave sent %d PortSyncReq packets for %d future-epoch messages (want <= 2)", gotReqs, burstSize)
	}

	// 4. Allow PortSyncReq through and verify dave catches up to epoch 5 and receives all 50 messages.
	daveWrap.dropSyncTx.Store(false)
	if err := dave.RequestCatchUp(); err != nil {
		t.Fatalf("dave RequestCatchUp: %v", err)
	}
	catchDeadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(catchDeadline) {
		if dave.CurrentEpoch() >= commit5.EpochID && daveMsgs.Load() >= burstSize {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dave.CurrentEpoch() < commit5.EpochID || daveMsgs.Load() != burstSize {
		t.Fatalf("dave failed to catch up: epoch=%d (want %d), msgs=%d (want %d)", dave.CurrentEpoch(), commit5.EpochID, daveMsgs.Load(), burstSize)
	}

	// 5. Deliver 10 duplicate PortSyncRes packets carrying already-applied commit5 and all 50
	// already-seen envelopes; assert 0 additional PortSyncReq packets and 0 duplicate deliveries.
	time.Sleep(100 * time.Millisecond)
	daveWrap.syncReqs.Store(0)
	alice.mu.RLock()
	dupRes := alice.buildSyncResponseLocked(alice.ChannelState, dave.Address(), &SyncRequest{
		RoomID:       roomID,
		CurrentEpoch: commit5.EpochID - 1,
	})
	alice.mu.RUnlock()
	if len(dupRes.Commits) == 0 || len(dupRes.Envelopes) == 0 {
		t.Fatalf("expected non-empty duplicate SyncResponse, got commits=%d envelopes=%d", len(dupRes.Commits), len(dupRes.Envelopes))
	}
	for i := 0; i < 10; i++ {
		dave.handleSyncRes(alice.Address(), &dupRes)
	}
	time.Sleep(150 * time.Millisecond)

	if extraReqs := daveWrap.syncReqs.Load(); extraReqs != 0 {
		t.Errorf("duplicate PortSyncRes commit storm: dave sent %d extra PortSyncReq packets for already-applied commits (want 0)", extraReqs)
	}
	if got := daveMsgs.Load(); got != burstSize {
		t.Errorf("duplicate PortSyncRes delivered duplicate messages: got %d, want %d", got, burstSize)
	}
}
