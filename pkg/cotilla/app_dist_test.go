package cotilla

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

func createTestNode(seed string) (*Node, *memoryTransport, error) {
	id, err := NewIdentityFromSeed([]byte(seed))
	if err != nil {
		return nil, nil, err
	}
	tr := newMemoryTransport(id.Address())
	cfg := DefaultConfig()
	cfg.SyncTimeout = 500 * time.Millisecond
	cfg.ReplayWindow = 5 * time.Minute

	roomKey, err := GenerateRoomKey()
	if err != nil {
		return nil, nil, err
	}

	node := NewNode(id, "private-genesis-room", roomKey, cfg, tr, Hooks{})
	tr.onData = func(from string, data []byte) {
		node.HandleWire(from, data)
	}
	tr.onClose = func(addr string) {
		node.RemovePeer(addr)
	}
	return node, tr, nil
}

// TestAppDistribution_SwarmSeeding4Peers tests multi-peer app bundle distribution:
// Seeder -> Peer1 & Peer2.
// Then Seeder disconnects.
// Latecomer Peer3 joins and downloads the verified bundle solely from Peer1 and Peer2 via swarm seeding.
func TestAppDistribution_SwarmSeeding4Peers(t *testing.T) {
	pubHex, privHex, err := GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair failed: %v", err)
	}

	// Create 200 KB bundle to test multiple chunks (> 3 chunks of 64KB)
	bundleBytes := make([]byte, 200*1024)
	if _, err := rand.Read(bundleBytes); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}
	// Give it an HTML header
	header := []byte("<!DOCTYPE html><html><!-- cotilla test app --><body>")
	copy(bundleBytes, header)

	manifest, err := SignAppBundle(privHex, "cotilla-chat", "stable", "1.0.0", 1, bundleBytes, "text/html; charset=utf-8", FormatSingleHTMLV1, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle failed: %v", err)
	}

	// Unique seeds for all 4 peers
	seederNode, seederTr, err := createTestNode("seed-seeder-client-000000000000001")
	if err != nil {
		t.Fatalf("create seeder failed: %v", err)
	}
	peer1Node, peer1Tr, err := createTestNode("seed-peer-one-client-000000000000002")
	if err != nil {
		t.Fatalf("create peer1 failed: %v", err)
	}
	peer2Node, peer2Tr, err := createTestNode("seed-peer-two-client-000000000000003")
	if err != nil {
		t.Fatalf("create peer2 failed: %v", err)
	}
	peer3Node, peer3Tr, err := createTestNode("seed-peer-three-client-000000000004")
	if err != nil {
		t.Fatalf("create peer3 failed: %v", err)
	}

	// Register bundle on Seeder
	distRoomKey := DefaultAppDistRoomKey()
	err = seederNode.RegisterAppBundle(DefaultAppDistRoomID, distRoomKey, manifest, bundleBytes, pubHex)
	if err != nil {
		t.Fatalf("RegisterAppBundle on seeder failed: %v", err)
	}

	var peer1Ready, peer2Ready, peer3Ready sync.WaitGroup
	peer1Ready.Add(1)
	peer2Ready.Add(1)
	peer3Ready.Add(1)

	var peer1Received, peer2Received, peer3Received []byte
	var peer1Mu, peer2Mu, peer3Mu sync.Mutex

	peer1Node.Hooks.OnAppBundleReady = func(m *AppManifest, data []byte) {
		peer1Mu.Lock()
		defer peer1Mu.Unlock()
		if peer1Received == nil {
			peer1Received = append([]byte(nil), data...)
			peer1Ready.Done()
		}
	}
	peer2Node.Hooks.OnAppBundleReady = func(m *AppManifest, data []byte) {
		peer2Mu.Lock()
		defer peer2Mu.Unlock()
		if peer2Received == nil {
			peer2Received = append([]byte(nil), data...)
			peer2Ready.Done()
		}
	}
	peer3Node.Hooks.OnAppBundleReady = func(m *AppManifest, data []byte) {
		peer3Mu.Lock()
		defer peer3Mu.Unlock()
		if peer3Received == nil {
			peer3Received = append([]byte(nil), data...)
			peer3Ready.Done()
		}
	}

	// Connect Seeder <-> Peer1, Seeder <-> Peer2, Peer1 <-> Peer2
	seederTr.Connect(peer1Tr)
	seederNode.AddPeer(peer1Node.Address())
	peer1Node.AddPeer(seederNode.Address())

	seederTr.Connect(peer2Tr)
	seederNode.AddPeer(peer2Node.Address())
	peer2Node.AddPeer(seederNode.Address())

	peer1Tr.Connect(peer2Tr)
	peer1Node.AddPeer(peer2Node.Address())
	peer2Node.AddPeer(peer1Node.Address())

	// Peer1 and Peer2 join the app-dist channel
	err = peer1Node.JoinAppDistChannel(DefaultAppDistRoomID, distRoomKey, pubHex, 1)
	if err != nil {
		t.Fatalf("peer1 JoinAppDistChannel failed: %v", err)
	}
	err = peer2Node.JoinAppDistChannel(DefaultAppDistRoomID, distRoomKey, pubHex, 1)
	if err != nil {
		t.Fatalf("peer2 JoinAppDistChannel failed: %v", err)
	}

	// Wait for Peer1 and Peer2 to complete download
	doneChan := make(chan struct{})
	go func() {
		peer1Ready.Wait()
		peer2Ready.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for peer1 and peer2 to download bundle")
	}

	if !bytes.Equal(peer1Received, bundleBytes) {
		t.Fatalf("peer1 received bundle does not match original bytes")
	}
	if !bytes.Equal(peer2Received, bundleBytes) {
		t.Fatalf("peer2 received bundle does not match original bytes")
	}

	// NOW DISCONNECT SEEDER COMPLETELY!
	seederTr.Disconnect(peer1Tr)
	seederTr.Disconnect(peer2Tr)
	peer1Node.RemovePeer(seederNode.Address())
	peer2Node.RemovePeer(seederNode.Address())

	// Verify Seeder is completely removed from peer1 and peer2
	for _, p := range peer1Tr.Peers() {
		if p == seederNode.Address() {
			t.Fatalf("seeder still in peer1 transport peers after disconnect")
		}
	}

	// Latecomer Peer3 now joins! Connect Peer3 <-> Peer1 and Peer3 <-> Peer2
	peer3Tr.Connect(peer1Tr)
	peer3Node.AddPeer(peer1Node.Address())
	peer1Node.AddPeer(peer3Node.Address())

	peer3Tr.Connect(peer2Tr)
	peer3Node.AddPeer(peer2Node.Address())
	peer2Node.AddPeer(peer3Node.Address())

	// Peer3 joins app dist channel
	err = peer3Node.JoinAppDistChannel(DefaultAppDistRoomID, distRoomKey, pubHex, 1)
	if err != nil {
		t.Fatalf("peer3 JoinAppDistChannel failed: %v", err)
	}

	peer3Done := make(chan struct{})
	go func() {
		peer3Ready.Wait()
		close(peer3Done)
	}()

	select {
	case <-peer3Done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for peer3 to download bundle via swarm seeding from peer1 and peer2")
	}

	if !bytes.Equal(peer3Received, bundleBytes) {
		t.Fatalf("peer3 received bundle does not match original bytes")
	}
}

// TestAppDistribution_Isolation tests that app distribution channels do not accept chat envelopes or epoch evictions.
func TestAppDistribution_Isolation(t *testing.T) {
	node1, tr1, err := createTestNode("seed-iso-client-00000000000000001")
	if err != nil {
		t.Fatalf("create node1: %v", err)
	}
	node2, tr2, err := createTestNode("seed-iso-client-00000000000000002")
	if err != nil {
		t.Fatalf("create node2: %v", err)
	}

	tr1.Connect(tr2)
	node1.AddPeer(node2.Address())
	node2.AddPeer(node1.Address())

	distKey := DefaultAppDistRoomKey()
	_ = node1.JoinAppDistChannel(DefaultAppDistRoomID, distKey, "", 0)
	_ = node2.JoinAppDistChannel(DefaultAppDistRoomID, distKey, "", 0)

	// Attempting to evict on app-dist channel should fail
	_, err = node1.EvictPeerInChannel(DefaultAppDistRoomID, node2.Address(), "malicious eviction")
	if err == nil {
		t.Fatalf("expected error when attempting eviction on app distribution channel, got nil")
	}

	// Attempting to rotate epoch key on app-dist channel should fail
	_, err = node1.RotateEpochKeyInChannel(DefaultAppDistRoomID)
	if err == nil {
		t.Fatalf("expected error when attempting rotate epoch key on app distribution channel, got nil")
	}

	// Attempting to inject a chat envelope on app-dist channel should be dropped
	chatEnv, err := NewEnvelope(node1.ID, DefaultAppDistRoomID, distKey, []byte(`{"type":"chat","text":"hello"}`))
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}

	accepted := node2.processEnvelope(chatEnv, 5*time.Minute, false)
	if accepted {
		t.Fatalf("processEnvelope should have rejected chat envelope on app distribution channel")
	}
}

// TestAppDistribution_RollingUpdate tests that peers accept monotonic sequence updates and reject rollbacks.
func TestAppDistribution_RollingUpdate(t *testing.T) {
	pubHex, privHex, err := GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair: %v", err)
	}

	bundleV1 := []byte("<!DOCTYPE html><html><body><h1>Version 1</h1></body></html>")
	manifestV1, err := SignAppBundle(privHex, "cotilla-chat", "stable", "1.0.0", 1, bundleV1, "text/html", FormatSingleHTMLV1, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle V1: %v", err)
	}

	bundleV2 := []byte("<!DOCTYPE html><html><body><h1>Version 2 - Updated</h1></body></html>")
	manifestV2, err := SignAppBundle(privHex, "cotilla-chat", "stable", "2.0.0", 2, bundleV2, "text/html", FormatSingleHTMLV1, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle V2: %v", err)
	}

	now := time.Now().UnixMilli()
	// Peer expects minSeq = 2 (e.g. already knows about V2)
	err = VerifyAppBundle(manifestV1, bundleV1, pubHex, "cotilla-chat", "stable", 2, now)
	if err == nil {
		t.Fatalf("expected error verifying V1 when minSeq is 2, got nil")
	}

	// Verification of V2 succeeds with minSeq = 2
	err = VerifyAppBundle(manifestV2, bundleV2, pubHex, "cotilla-chat", "stable", 2, now)
	if err != nil {
		t.Fatalf("failed verifying V2 with minSeq=2: %v", err)
	}
}
