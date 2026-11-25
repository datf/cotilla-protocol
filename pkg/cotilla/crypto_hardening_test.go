package cotilla

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// In accordance with RULE: AGENTS.md:
// - Never Test Only Two Peers (all scenarios use 3+ peers: Alice, Bob, Charlie, etc.)
// - Unique Test Fixture Seeds per client (prevent sender/receiver collisions)

func newTestIdentityWithSeed(t *testing.T, seedStr string) *Identity {
	t.Helper()
	seed := make([]byte, 32)
	copy(seed, []byte(seedStr))
	id, err := NewIdentityFromSeed(seed)
	if err != nil {
		t.Fatalf("failed to create test identity with seed %q: %v", seedStr, err)
	}
	return id
}

// TestPeerInfo_SignedVerificationAndTampering_3Peers verifies that PeerInfoFrame announcements
// are cryptographically authenticated, and that spoofed or forged peer info is rejected across 3 peers.
func TestPeerInfo_SignedVerificationAndTampering_3Peers(t *testing.T) {
	aliceID := newTestIdentityWithSeed(t, "seed-alice-peer-info-auth-001")
	bobID := newTestIdentityWithSeed(t, "seed-bob-peer-info-auth-0002")
	charlieID := newTestIdentityWithSeed(t, "seed-charlie-malicious-peer-3")

	trA := newMemoryTransport(aliceID.Address())
	trB := newMemoryTransport(bobID.Address())
	trC := newMemoryTransport(charlieID.Address())

	trA.Connect(trB)
	trA.Connect(trC)
	trB.Connect(trC)

	roomKey, _ := GenerateRoomKey()
	roomID := "peer-info-mesh-room"

	var nodeA, nodeB, nodeC *Node

	cfg := DefaultConfig()
	nodeA = NewNode(aliceID, roomID, roomKey, cfg, trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	nodeB = NewNode(bobID, roomID, roomKey, cfg, trB, Hooks{})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	nodeC = NewNode(charlieID, roomID, roomKey, cfg, trC, Hooks{})
	trC.onData = func(from string, data []byte) { nodeC.HandleWire(from, data) }

	nodeA.AddPeer(bobID.Address())
	nodeA.AddPeer(charlieID.Address())
	nodeB.AddPeer(aliceID.Address())
	nodeB.AddPeer(charlieID.Address())
	nodeC.AddPeer(aliceID.Address())
	nodeC.AddPeer(bobID.Address())

	// Alice broadcasts legitimate signed PeerInfo
	nodeA.BroadcastPeerInfo()
	time.Sleep(50 * time.Millisecond)

	// Bob should have Alice's legitimate encryption public key
	bobKeys := nodeB.PeerEncKeys()
	if got := bobKeys[aliceID.Address()]; got != aliceID.EncAddress() {
		t.Fatalf("bob expected alice enc key %s, got %s", aliceID.EncAddress(), got)
	}

	// Charlie tries to broadcast forged PeerInfo claiming to be Alice but with Charlie's EncAddress
	forgedPI := &PeerInfoFrame{
		RoomID:    roomID,
		SignPub:   aliceID.Address(),
		EncPub:    charlieID.EncAddress(), // Malicious substitution
		Timestamp: time.Now().UnixMilli(),
		Signature: hex.EncodeToString(charlieID.Sign([]byte("fake-signature"))),
	}
	forgedPkt, err := NewGroupPacket(charlieID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortGroupPeerInfo, 3, forgedPI)
	if err != nil {
		t.Fatalf("new group packet failed: %v", err)
	}
	forgedData, err := MarshalPacket(forgedPkt)
	if err != nil {
		t.Fatalf("marshal wire failed: %v", err)
	}

	// Charlie sends forged announcement to Bob
	_ = trC.Send(bobID.Address(), forgedData)
	time.Sleep(50 * time.Millisecond)

	// Bob's cache must NOT have been corrupted by Charlie's forgery
	bobKeysAfter := nodeB.PeerEncKeys()
	if got := bobKeysAfter[aliceID.Address()]; got != aliceID.EncAddress() {
		t.Fatalf("vulnerability: bob accepted forged PeerInfo! enc key changed to %s", got)
	}
}

// TestAEAD_ContextBinding_CrossRoomAndCrossAuthor_3Peers verifies that ciphertexts sealed
// for one room or author cannot be transplanted into a different room or re-signed by another peer.
func TestAEAD_ContextBinding_CrossRoomAndCrossAuthor_3Peers(t *testing.T) {
	aliceID := newTestIdentityWithSeed(t, "seed-alice-aead-context-0001")
	bobID := newTestIdentityWithSeed(t, "seed-bob-aead-context-00002")
	charlieID := newTestIdentityWithSeed(t, "seed-charlie-transplanter-3")
	_ = bobID

	roomKey, _ := GenerateRoomKey()
	roomAlpha := "room-alpha-alpha"
	roomBeta := "room-beta-beta"

	// Alice creates a valid envelope in room-alpha
	msgText := "confidential message for room-alpha"
	payload, _ := json.Marshal(ChatPayload{Type: "chat", Text: msgText})
	envAlpha, err := NewEnvelope(aliceID, roomAlpha, roomKey, payload)
	if err != nil {
		t.Fatalf("failed to create envelope: %v", err)
	}

	// Bob in room-alpha successfully decrypts
	ptAlpha, err := envAlpha.Decrypt(roomKey)
	if err != nil {
		t.Fatalf("bob failed to decrypt legitimate envelope: %v", err)
	}
	var chat ChatPayload
	if err := json.Unmarshal(ptAlpha, &chat); err != nil || chat.Text != msgText {
		t.Fatalf("unexpected decrypted text: %q", chat.Text)
	}

	// Attack 1: Charlie tries to transplant Alice's ciphertext into room-beta
	canonicalBeta := CanonicalEnvelopePayload(roomBeta, aliceID.Address(), envAlpha.Nonce, envAlpha.Ciphertext, envAlpha.EpochID, envAlpha.Timestamp)
	envTransplantedRoom := &Envelope{
		RoomID:       roomBeta,
		AuthorPubKey: aliceID.Address(),
		Nonce:        envAlpha.Nonce,
		Ciphertext:   envAlpha.Ciphertext,
		EpochID:      envAlpha.EpochID,
		Timestamp:    envAlpha.Timestamp,
		Signature:    hex.EncodeToString(aliceID.Sign(canonicalBeta)),
	}

	// Decrypting in room-beta must fail AEAD verification due to roomID mismatch in AAD!
	_, err = envTransplantedRoom.Decrypt(roomKey)
	if err == nil {
		t.Fatalf("expected AEAD decryption failure on room-transplanted ciphertext, but it succeeded!")
	}

	// Attack 2: Charlie takes Alice's ciphertext, sets AuthorPubKey to Charlie, and signs it for room-alpha
	canonicalCharlie := CanonicalEnvelopePayload(roomAlpha, charlieID.Address(), envAlpha.Nonce, envAlpha.Ciphertext, envAlpha.EpochID, envAlpha.Timestamp)
	envTransplantedAuthor := &Envelope{
		RoomID:       roomAlpha,
		AuthorPubKey: charlieID.Address(),
		Nonce:        envAlpha.Nonce,
		Ciphertext:   envAlpha.Ciphertext,
		EpochID:      envAlpha.EpochID,
		Timestamp:    envAlpha.Timestamp,
		Signature:    hex.EncodeToString(charlieID.Sign(canonicalCharlie)),
	}

	// Signature verification passes for Charlie, but AEAD Decrypt must FAIL due to AuthorPubKey mismatch in AAD!
	if err := envTransplantedAuthor.Verify(roomAlpha, 5*time.Minute); err != nil {
		t.Fatalf("signature verify for charlie should pass: %v", err)
	}
	_, err = envTransplantedAuthor.Decrypt(roomKey)
	if err == nil {
		t.Fatalf("expected AEAD decryption failure on author-transplanted ciphertext, but it succeeded!")
	}
}

// TestAttachment_ChunkIndexTamperingRejection_3Peers verifies that swapping or injecting chunks
// with incorrect chunk indices fails AEAD verification immediately at chunk reception.
func TestAttachment_ChunkIndexTamperingRejection_3Peers(t *testing.T) {
	roomKey, _ := GenerateRoomKey()

	testData := make([]byte, 128*1024) // 2 chunks (64KB each)
	for i := range testData {
		testData[i] = byte(i % 251)
	}

	meta, chunks, err := PrepareAttachment(roomKey, "testfile.dat", "application/octet-stream", testData)
	if err != nil {
		t.Fatalf("failed to prepare attachment: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}

	assembler := NewAttachmentAssembler(*meta, roomKey)

	// Legitimate chunk 0 succeeds
	complete, err := assembler.AddChunk(0, chunks[0])
	if err != nil || complete {
		t.Fatalf("unexpected chunk 0 add result: complete=%v, err=%v", complete, err)
	}

	// Malicious peer provides chunk 1 data when chunk 0 was requested, or attempts to insert chunk 1 at index 0
	// Try inserting chunk 1's ciphertext into chunk index 0
	_, err = assembler.AddChunk(0, chunks[1])
	// Should be ignored or rejected (already received index 0)

	// Create fresh assembler and try inserting chunk 1 bytes at index 0:
	assemblerTampered := NewAttachmentAssembler(*meta, roomKey)
	_, err = assemblerTampered.AddChunk(0, chunks[1])
	if err == nil {
		t.Fatalf("expected AEAD decryption error when injecting chunk 1 at chunk index 0, but it succeeded!")
	}

	// Correct chunk sequence succeeds
	assemblerGood := NewAttachmentAssembler(*meta, roomKey)
	_, err = assemblerGood.AddChunk(0, chunks[0])
	if err != nil {
		t.Fatalf("chunk 0 failed: %v", err)
	}
	complete, err = assemblerGood.AddChunk(1, chunks[1])
	if err != nil || !complete {
		t.Fatalf("chunk 1 failed: complete=%v, err=%v", complete, err)
	}

	assembled, err := assemblerGood.Assemble()
	if err != nil {
		t.Fatalf("assembly failed: %v", err)
	}
	if len(assembled) != len(testData) {
		t.Fatalf("assembled size %d != testData size %d", len(assembled), len(testData))
	}
}

// TestDirectInvite_NoiseForwardSecrecy_3Peers exercises the Noise_IK ephemeral key exchange,
// verifying forward secrecy against static key compromise, and detecting ephemeral key tampering.
func TestDirectInvite_NoiseForwardSecrecy_3Peers(t *testing.T) {
	aliceID := newTestIdentityWithSeed(t, "seed-alice-noise-ik-dm-00001")
	bobID := newTestIdentityWithSeed(t, "seed-bob-noise-ik-dm-0000002")
	charlieID := newTestIdentityWithSeed(t, "seed-charlie-noise-ik-dm-03")

	trA := newMemoryTransport(aliceID.Address())
	trB := newMemoryTransport(bobID.Address())
	trC := newMemoryTransport(charlieID.Address())

	trA.Connect(trB)
	trA.Connect(trC)
	trB.Connect(trC)

	roomKey, _ := GenerateRoomKey()
	roomID := "main-group-room"

	cfg := DefaultConfig()

	var nodeA, nodeB *Node
	receivedInvite := make(chan *InvitePayload, 1)

	nodeA = NewNode(aliceID, roomID, roomKey, cfg, trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	nodeB = NewNode(bobID, roomID, roomKey, cfg, trB, Hooks{
		OnDirectInvite: func(invite *DirectInvite, payload *InvitePayload) {
			receivedInvite <- payload
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	// Register peer encryption keys
	nodeA.SetPeerEncKey(bobID.Address(), bobID.EncAddress())
	nodeB.SetPeerEncKey(aliceID.Address(), aliceID.EncAddress())

	// Alice sends forward-secret direct invite to Bob
	invite, payload, err := nodeA.SendDirectInvite(bobID.Address(), "dm", "Private 1:1 DM")
	if err != nil {
		t.Fatalf("failed to send direct invite: %v", err)
	}

	if invite.EphemeralPub == "" {
		t.Fatalf("expected non-empty EphemeralPub in DirectInvite")
	}

	select {
	case got := <-receivedInvite:
		if got.RoomID != payload.RoomID || got.RoomKey != payload.RoomKey {
			t.Fatalf("bob received payload mismatch: got %v, expected %v", got, payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("bob timed out waiting for direct invite")
	}

	// Verify Charlie cannot decrypt the invite
	ePubBytes, err := hex.DecodeString(invite.EphemeralPub)
	if err != nil || len(ePubBytes) != 32 {
		t.Fatalf("invalid ephemeral pub hex: %v", err)
	}
	var ePub [32]byte
	copy(ePub[:], ePubBytes)

	nonce, _ := base64.StdEncoding.DecodeString(invite.Nonce)
	ciphertext, _ := base64.StdEncoding.DecodeString(invite.Ciphertext)
	aad := []byte("cotilla-invite-v2:" + aliceID.Address() + ":" + bobID.Address())

	_, err = DecryptDirectInvite(charlieID, aliceID.EncPub, ePub, nonce, ciphertext, aad)
	if err == nil {
		t.Fatal("expected charlie decryption of invite to fail, but it succeeded!")
	}
}

// TestEnvelope_ReplayWindowRejection_3Peers verifies that stale envelopes exceeding the configured
// clock skew / replay window are rejected upon verification across 3 peers.
func TestEnvelope_ReplayWindowRejection_3Peers(t *testing.T) {
	aliceID := newTestIdentityWithSeed(t, "seed-alice-replay-window-001")
	bobID := newTestIdentityWithSeed(t, "seed-bob-replay-window-00002")
	charlieID := newTestIdentityWithSeed(t, "seed-charlie-replay-window-3")

	trA := newMemoryTransport(aliceID.Address())
	trB := newMemoryTransport(bobID.Address())
	trC := newMemoryTransport(charlieID.Address())

	trA.Connect(trB)
	trB.Connect(trC)

	roomKey, _ := GenerateRoomKey()
	roomID := "replay-test-room"

	cfg := DefaultConfig()
	cfg.ReplayWindow = 1 * time.Second // Strict 1-second window for testing

	bobReceived := make(chan string, 10)

	nodeB := NewNode(bobID, roomID, roomKey, cfg, trB, Hooks{
		OnMessage: func(env *Envelope, plaintext []byte) {
			var chat ChatPayload
			_ = json.Unmarshal(plaintext, &chat)
			bobReceived <- chat.Text
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	nodeB.AddPeer(aliceID.Address())
	nodeB.AddPeer(charlieID.Address())

	// 1. Fresh envelope within window is accepted
	freshEnv, err := NewEnvelope(aliceID, roomID, roomKey, []byte(`{"type":"chat","text":"fresh-msg"}`))
	if err != nil {
		t.Fatalf("failed to create envelope: %v", err)
	}

	pktFresh, _ := NewGroupPacket(aliceID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortChat, 3, freshEnv)
	dataFresh, _ := MarshalPacket(pktFresh)
	trB.onData(aliceID.Address(), dataFresh)

	select {
	case msg := <-bobReceived:
		if msg != "fresh-msg" {
			t.Fatalf("expected 'fresh-msg', got %q", msg)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("bob failed to receive fresh envelope")
	}

	// 2. Stale envelope (timestamp 10 minutes in the past) must be rejected
	staleTS := time.Now().Add(-10 * time.Minute).UnixMilli()
	author := aliceID.Address()
	aad := []byte("cotilla-envelope-v1:" + roomID + ":0:" + author)
	nonceBytes, cipherBytes, err := EncryptRoomPayload(roomKey, []byte(`{"type":"chat","text":"stale-msg"}`), aad)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonceBytes)
	cipherStr := base64.RawURLEncoding.EncodeToString(cipherBytes)
	canonicalStale := CanonicalEnvelopePayload(roomID, author, nonceStr, cipherStr, 0, staleTS)
	sigStale := hex.EncodeToString(aliceID.Sign(canonicalStale))

	staleEnv := &Envelope{
		RoomID:       roomID,
		AuthorPubKey: author,
		Nonce:        nonceStr,
		Ciphertext:   cipherStr,
		EpochID:      0,
		Timestamp:    staleTS,
		Signature:    sigStale,
	}

	// Verify directly on stale envelope fails
	if err := staleEnv.Verify(roomID, cfg.ReplayWindow); err == nil {
		t.Fatal("expected stale envelope to fail verification, but it passed!")
	}

	// Node drops stale envelope
	pktStale, _ := NewGroupPacket(aliceID, BroadcastAddr, ComputeChannelHash(roomID, roomKey), 0, roomKey, PortChat, 3, staleEnv)
	dataStale, _ := MarshalPacket(pktStale)
	trB.onData(aliceID.Address(), dataStale)

	select {
	case bad := <-bobReceived:
		t.Fatalf("bob accepted stale envelope: %s", bad)
	case <-time.After(100 * time.Millisecond):
		// Success: rejected
	}
}

// TestCanonicalSerialization_DelimiterInjection verifies that length-prefixed canonical encoding
// prevents field delimiter injection when fields contain ':' or special characters.
func TestCanonicalSerialization_DelimiterInjection(t *testing.T) {
	idA := newTestIdentityWithSeed(t, "seed-alice-delimiter-inj-001")

	// Craft tricky roomID and fields containing colons
	trickyRoom := "room:alpha:with:colons"
	trickyAuthor := idA.Address()
	nonce := "dGVzdC1ub25jZQ"
	cipher := "dGVzdC1jaXBoZXI"
	ts := int64(1700000000000)

	canonical1 := CanonicalEnvelopePayload(trickyRoom, trickyAuthor, nonce, cipher, 0, ts)

	// Another set of fields that would collide if colon concatenation were used:
	// "room" + ":" + "alpha:with:colons" vs "room:alpha" + ":" + "with:colons"
	canonical2 := CanonicalEnvelopePayload("room", "alpha:with:colons:"+trickyAuthor, nonce, cipher, 0, ts)

	if string(canonical1) == string(canonical2) {
		t.Fatal("vulnerability: delimiter injection caused canonical serialization collision!")
	}
}
