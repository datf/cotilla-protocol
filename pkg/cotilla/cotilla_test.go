package cotilla

import (
	"crypto/rand"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"
)

// memoryTransport simulates a peer-to-peer transport network for testing without real UDP sockets.
type memoryTransport struct {
	mu      sync.RWMutex
	addr    string
	peers   map[string]*memoryTransport
	blocked map[string]bool // simulated NAT firewall
	onData  func(from string, data []byte)
	onClose func(addr string)
}

func newMemoryTransport(addr string) *memoryTransport {
	return &memoryTransport{
		addr:    addr,
		peers:   make(map[string]*memoryTransport),
		blocked: make(map[string]bool),
	}
}

func (t *memoryTransport) Connect(other *memoryTransport) {
	t.mu.Lock()
	other.mu.Lock()
	defer t.mu.Unlock()
	defer other.mu.Unlock()

	t.peers[other.addr] = other
	other.peers[t.addr] = t
}

func (t *memoryTransport) Disconnect(other *memoryTransport) {
	t.ClosePeer(other.addr)
}

func (t *memoryTransport) ClosePeer(addr string) {
	t.mu.Lock()
	other, ok := t.peers[addr]
	delete(t.peers, addr)
	onClose := t.onClose
	t.mu.Unlock()

	if onClose != nil {
		go onClose(addr)
	}

	if ok && other != nil {
		other.mu.Lock()
		delete(other.peers, t.addr)
		otherOnClose := other.onClose
		other.mu.Unlock()
		if otherOnClose != nil {
			go otherOnClose(t.addr)
		}
	}
}

func (t *memoryTransport) Block(otherAddr string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.blocked[otherAddr] = true
}

func (t *memoryTransport) Send(addr string, data []byte) error {
	t.mu.RLock()
	other, ok := t.peers[addr]
	blocked := t.blocked[addr]
	t.mu.RUnlock()

	if !ok || blocked {
		return errNoPeer
	}

	go func() {
		t.mu.RLock()
		_, stillConnected := t.peers[addr]
		stillBlocked := t.blocked[addr]
		t.mu.RUnlock()
		if !stillConnected || stillBlocked {
			return
		}
		if other.onData != nil {
			other.onData(t.addr, append([]byte(nil), data...))
		}
	}()
	return nil
}

func (t *memoryTransport) Broadcast(data []byte) {
	t.mu.RLock()
	destinations := make([]*memoryTransport, 0, len(t.peers))
	for addr, peer := range t.peers {
		if !t.blocked[addr] {
			destinations = append(destinations, peer)
		}
	}
	t.mu.RUnlock()

	for _, dest := range destinations {
		d := dest
		destAddr := d.addr
		go func() {
			t.mu.RLock()
			_, stillConnected := t.peers[destAddr]
			stillBlocked := t.blocked[destAddr]
			t.mu.RUnlock()
			if !stillConnected || stillBlocked {
				return
			}
			if d.onData != nil {
				d.onData(t.addr, append([]byte(nil), data...))
			}
		}()
	}
}

func (t *memoryTransport) Peers() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []string
	for addr := range t.peers {
		if !t.blocked[addr] {
			out = append(out, addr)
		}
	}
	return out
}

var errNoPeer = &netErr{"destination unreachable or blocked"}

type netErr struct{ msg string }

func (e *netErr) Error() string { return e.msg }

// 1. Single Node Isolation: Proper initialization, local identity creation, and clean lifecycle.
func TestSingleNodeIsolation(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}
	if len(id.Address()) != 64 {
		t.Fatalf("expected 64-char hex address, got %d", len(id.Address()))
	}

	key, err := GenerateRoomKey()
	if err != nil {
		t.Fatalf("failed to generate room key: %v", err)
	}

	roomID := "isolated-room-123"
	tr := newMemoryTransport(id.Address())
	node := NewNode(id, roomID, key, DefaultConfig(), tr, Hooks{})

	// Send message in isolation
	env, err := node.SendMessage("hello self")
	if err != nil {
		t.Fatalf("failed to send message in isolation: %v", err)
	}

	if node.RingBuffer.Len() != 1 {
		t.Fatalf("expected 1 item in ring buffer, got %d", node.RingBuffer.Len())
	}

	if err := env.Verify(roomID, 5*time.Minute); err != nil {
		t.Fatalf("self-verification failed: %v", err)
	}

	pt, err := env.Decrypt(key)
	if err != nil {
		t.Fatalf("self-decryption failed: %v", err)
	}

	var chat ChatPayload
	if err := json.Unmarshal(pt, &chat); err != nil || chat.Text != "hello self" {
		t.Fatalf("unexpected decrypted text: %s", chat.Text)
	}
}

// 2. Room Messaging (3–5 Peers):
// - E2EE message delivery across a full WebRTC mesh.
// - Verification that invalid signatures or mismatched room keys are rejected.
func TestRoomMessaging_3To5Peers(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "mesh-room-456"

	numPeers := 4
	nodes := make([]*Node, numPeers)
	transports := make([]*memoryTransport, numPeers)
	receivedMsgs := make([]chan string, numPeers)

	for i := 0; i < numPeers; i++ {
		idx := i
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		transports[idx] = tr
		receivedMsgs[idx] = make(chan string, 10)

		var n *Node
		n = NewNode(id, roomID, roomKey, DefaultConfig(), tr, Hooks{
			OnMessage: func(env *Envelope, pt []byte) {
				var chat ChatPayload
				_ = json.Unmarshal(pt, &chat)
				receivedMsgs[idx] <- chat.Text
			},
		})
		tr.onData = func(from string, data []byte) {
			n.HandleWire(from, data)
		}
		nodes[idx] = n
	}

	// Connect all peers in a full mesh
	for i := 0; i < numPeers; i++ {
		for j := i + 1; j < numPeers; j++ {
			transports[i].Connect(transports[j])
			nodes[i].AddPeer(nodes[j].Address())
			nodes[j].AddPeer(nodes[i].Address())
		}
	}

	// Peer 0 sends a message
	msgText := "mesh test payload"
	if _, err := nodes[0].SendMessage(msgText); err != nil {
		t.Fatalf("failed to send mesh message: %v", err)
	}

	// Verify peers 1, 2, 3 received and decrypted it
	for i := 1; i < numPeers; i++ {
		select {
		case got := <-receivedMsgs[i]:
			if got != msgText {
				t.Fatalf("peer %d received %q, expected %q", i, got, msgText)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("peer %d timed out waiting for message", i)
		}
	}

	// Verify mismatched room key rejection
	otherKey, _ := GenerateRoomKey()
	eveID, _ := NewIdentity()
	eveEnvelope, _ := NewEnvelope(eveID, roomID, otherKey, []byte(`{"type":"chat","text":"intruder"}`))

	evePkt, _ := NewGroupPacket(eveID, BroadcastAddr, ComputeChannelHash(roomID, otherKey), 0, otherKey, PortChat, 3, eveEnvelope)
	wireData, _ := MarshalPacket(evePkt)
	// Inject Eve's message into Peer 1
	nodes[1].HandleWire(eveID.Address(), wireData)

	// Ensure Peer 1 did NOT accept Eve's message
	select {
	case bad := <-receivedMsgs[1]:
		t.Fatalf("peer 1 accepted message with invalid room key: %s", bad)
	case <-time.After(200 * time.Millisecond):
		// Success: rejected
	}

	// Verify tampered signature rejection
	tampered := *eveEnvelope
	tampered.Signature = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := tampered.Verify(roomID, 5*time.Minute); err == nil {
		t.Fatalf("expected signature verification failure on tampered signature")
	}
}

// 3. Transient Reconnect / Catch-Up:
// - A peer disconnects, other peers exchange 10 messages, peer reconnects and recovers via ring buffer.
func TestTransientReconnect_CatchUp(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "catchup-room-789"

	createPeer := func(name string) (*Node, *memoryTransport, chan string) {
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		msgCh := make(chan string, 50)
		var n *Node
		n = NewNode(id, roomID, roomKey, DefaultConfig(), tr, Hooks{
			OnMessage: func(env *Envelope, pt []byte) {
				var chat ChatPayload
				_ = json.Unmarshal(pt, &chat)
				msgCh <- chat.Text
			},
		})
		tr.onData = func(from string, data []byte) {
			n.HandleWire(from, data)
		}
		return n, tr, msgCh
	}

	alice, aliceTr, _ := createPeer("Alice")
	bob, bobTr, _ := createPeer("Bob")
	charlie, charlieTr, charlieMsgs := createPeer("Charlie")

	// Form mesh
	aliceTr.Connect(bobTr)
	aliceTr.Connect(charlieTr)
	bobTr.Connect(charlieTr)

	alice.AddPeer(bob.Address())
	alice.AddPeer(charlie.Address())
	bob.AddPeer(alice.Address())
	bob.AddPeer(charlie.Address())
	charlie.AddPeer(alice.Address())
	charlie.AddPeer(bob.Address())

	// Charlie disconnects (simulating network blip)
	aliceTr.Block(charlie.Address())
	bobTr.Block(charlie.Address())
	charlieTr.Block(alice.Address())
	charlieTr.Block(bob.Address())

	// Alice and Bob exchange 10 messages
	for i := 1; i <= 10; i++ {
		_, err := alice.SendMessage("offline msg")
		if err != nil {
			t.Fatal(err)
		}
	}

	// Charlie is reconnected!
	aliceTr.mu.Lock()
	delete(aliceTr.blocked, charlie.Address())
	aliceTr.mu.Unlock()

	charlieTr.mu.Lock()
	delete(charlieTr.blocked, alice.Address())
	charlieTr.mu.Unlock()

	// Charlie requests catch-up
	if err := charlie.RequestCatchUp(); err != nil {
		t.Fatalf("catch up request failed: %v", err)
	}

	// Verify Charlie recovers all 10 messages from Alice's ring buffer
	recovered := 0
	deadline := time.After(3 * time.Second)
	for recovered < 10 {
		select {
		case msg := <-charlieMsgs:
			if msg == "offline msg" {
				recovered++
			}
		case <-deadline:
			t.Fatalf("charlie recovered only %d/10 messages before timeout", recovered)
		}
	}
}

// 4. Peer-Assisted NAT Relay:
// - Topology: A <-> C and B <-> C, but A <-x-> B direct link is blocked.
// - Verify Peer C relays encrypted chat frames from A to B.
func TestPeerAssistedNATRelay(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "relay-room-101"

	createNode := func() (*Node, *memoryTransport, chan string) {
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		ch := make(chan string, 10)
		var n *Node
		n = NewNode(id, roomID, roomKey, DefaultConfig(), tr, Hooks{
			OnMessage: func(env *Envelope, pt []byte) {
				var chat ChatPayload
				_ = json.Unmarshal(pt, &chat)
				ch <- chat.Text
			},
		})
		tr.onData = func(from string, data []byte) {
			n.HandleWire(from, data)
		}
		return n, tr, ch
	}

	peerA, trA, _ := createNode()
	peerB, trB, bMsgs := createNode()
	peerC, trC, _ := createNode()

	// A is connected to C
	trA.Connect(trC)
	peerA.AddPeer(peerC.Address())
	peerC.AddPeer(peerA.Address())

	// B is connected to C
	trB.Connect(trC)
	peerB.AddPeer(peerC.Address())
	peerC.AddPeer(peerB.Address())

	// A and B CANNOT connect directly (symmetric NAT)
	// A knows B belongs to the room
	peerA.AddPeer(peerB.Address())
	peerB.AddPeer(peerA.Address())

	// A sends message to room; direct channel to B does not exist, so A routes via C
	testMsg := "hello through peer C!"
	_, err := peerA.SendMessage(testMsg)
	if err != nil {
		t.Fatalf("failed to send relayed message: %v", err)
	}

	select {
	case got := <-bMsgs:
		if got != testMsg {
			t.Fatalf("peer B received %q, expected %q", got, testMsg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("peer B never received relayed message from A")
	}
}

// 5. Scoped Secondary Call Presence & Encrypted Signaling over Relay:
// - Verify encrypted CallPresence + Noise_IK CallSignal route cleanly across 3 peers without
//   exposing call payloads or activating calls on unjoined peers.
func TestCallPresenceAndSignalScopedIsolation(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "scoped-call-room"

	signalReceived := make(chan *CallSignalPayload, 4)
	unjoinedSignal := make(chan *CallSignalPayload, 4)

	idA, _ := NewIdentity()
	trA := newMemoryTransport(idA.Address())
	nodeA := NewNode(idA, roomID, roomKey, DefaultConfig(), trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	idB, _ := NewIdentity()
	trB := newMemoryTransport(idB.Address())
	nodeB := NewNode(idB, roomID, roomKey, DefaultConfig(), trB, Hooks{
		OnCallSignal: func(sig *CallSignalPayload) {
			signalReceived <- sig
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	idC, _ := NewIdentity()
	trC := newMemoryTransport(idC.Address())
	nodeC := NewNode(idC, roomID, roomKey, DefaultConfig(), trC, Hooks{
		OnCallSignal: func(sig *CallSignalPayload) {
			unjoinedSignal <- sig
		},
	})
	trC.onData = func(from string, data []byte) { nodeC.HandleWire(from, data) }

	// A <-> C and B <-> C; A and B signal through overlay relay C.
	trA.Connect(trC)
	trB.Connect(trC)
	nodeA.AddPeer(nodeC.Address())
	nodeC.AddPeer(nodeA.Address())
	nodeB.AddPeer(nodeC.Address())
	nodeC.AddPeer(nodeB.Address())
	nodeA.AddPeer(nodeB.Address())
	nodeB.AddPeer(nodeA.Address())

	nodeA.SetPeerEncKey(nodeB.Address(), idB.EncAddress())
	nodeB.SetPeerEncKey(nodeA.Address(), idA.EncAddress())
	nodeA.SetPeerEncKey(nodeC.Address(), idC.EncAddress())
	nodeC.SetPeerEncKey(nodeA.Address(), idA.EncAddress())

	if _, err := nodeA.JoinCall(roomID, false, CallOptions{Audio: true}); err != nil {
		t.Fatalf("nodeA JoinCall: %v", err)
	}
	if _, err := nodeB.JoinCall(roomID, false, CallOptions{ListenOnly: true}); err != nil {
		t.Fatalf("nodeB JoinCall: %v", err)
	}

	if err := nodeA.SendCallSignal(roomID, nodeB.Address(), "offer", "v=0 fake-sdp"); err != nil {
		t.Fatalf("SendCallSignal A->B failed: %v", err)
	}
	select {
	case sig := <-signalReceived:
		if sig.ScopeID != roomID || sig.Kind != "offer" || sig.Payload != "v=0 fake-sdp" {
			t.Fatalf("unexpected signal payload: %+v", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("node B never received Noise_IK encrypted call signal")
	}

	// Unjoined peer C must reject direct call offers when not in call (privacy gate).
	if err := nodeA.SendCallSignal(roomID, nodeC.Address(), "offer", "v=0 unwanted"); err != nil {
		t.Fatalf("SendCallSignal A->C send err: %v", err)
	}
	select {
	case sig := <-unjoinedSignal:
		t.Fatalf("unjoined peer C accepted call signal unexpectedly: %+v", sig)
	case <-time.After(250 * time.Millisecond):
	}
}

// 6. Direct File Transfer:
// - Chunked transfer and SHA-256 verification of attachments across peers.
func TestDirectFileTransfer(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "file-transfer-room"

	attachmentOffer := make(chan *AttachmentMeta, 1)
	attachmentComplete := make(chan []byte, 1)
	progressUpdates := make(chan int, 100)

	idA, _ := NewIdentity()
	trA := newMemoryTransport(idA.Address())
	nodeA := NewNode(idA, roomID, roomKey, DefaultConfig(), trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	idB, _ := NewIdentity()
	trB := newMemoryTransport(idB.Address())
	nodeB := NewNode(idB, roomID, roomKey, DefaultConfig(), trB, Hooks{
		OnAttachmentOffer: func(meta *AttachmentMeta) {
			attachmentOffer <- meta
		},
		OnAttachmentProgress: func(fileID string, receivedChunks, totalChunks int) {
			progressUpdates <- receivedChunks
		},
		OnAttachment: func(meta *AttachmentMeta, data []byte) {
			attachmentComplete <- data
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	trA.Connect(trB)
	nodeA.AddPeer(nodeB.Address())
	nodeB.AddPeer(nodeA.Address())

	// Generate 180 KB of random payload (> 2 chunks of 64KB)
	fileSize := 180 * 1024
	testData := make([]byte, fileSize)
	_, _ = io.ReadFull(rand.Reader, testData)

	meta, err := nodeA.ShareAttachment("testfile.bin", "application/octet-stream", testData)
	if err != nil {
		t.Fatalf("failed to share attachment: %v", err)
	}
	if meta.TotalChunks != 3 {
		t.Fatalf("expected 3 chunks for 180 KB, got %d", meta.TotalChunks)
	}

	// 1. Verify offer is received, but no chunks are downloaded yet
	var offeredMeta *AttachmentMeta
	select {
	case offeredMeta = <-attachmentOffer:
		if offeredMeta.FileID != meta.FileID {
			t.Fatalf("expected FileID %s, got %s", meta.FileID, offeredMeta.FileID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for attachment offer")
	}

	// Verify nothing in attachmentComplete channel before download is initiated
	select {
	case <-attachmentComplete:
		t.Fatalf("attachment should not be downloaded before DownloadAttachment is invoked!")
	case <-time.After(100 * time.Millisecond):
		// Expected: on-demand behavior means zero chunks transferred yet
	}

	// 2. Now explicitly initiate on-demand download
	if err := nodeB.DownloadAttachment(offeredMeta.FileID); err != nil {
		t.Fatalf("failed to download attachment: %v", err)
	}

	// 3. Verify progress updates and final assembly
	select {
	case receivedData := <-attachmentComplete:
		if len(receivedData) != fileSize {
			t.Fatalf("expected %d bytes, got %d", fileSize, len(receivedData))
		}
		for i := range testData {
			if testData[i] != receivedData[i] {
				t.Fatalf("byte mismatch at index %d", i)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for file transfer completion")
	}

	// Verify GetAttachmentData works on both sender and receiver
	senderData, err := nodeA.GetAttachmentData(meta.FileID)
	if err != nil || len(senderData) != fileSize {
		t.Fatalf("sender GetAttachmentData failed: %v", err)
	}
	recvData, err := nodeB.GetAttachmentData(meta.FileID)
	if err != nil || len(recvData) != fileSize {
		t.Fatalf("receiver GetAttachmentData failed: %v", err)
	}
}

func TestLargeFileTransferWindowed(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "large-file-room"

	attachmentComplete := make(chan []byte, 1)

	idA, _ := NewIdentity()
	trA := newMemoryTransport(idA.Address())
	nodeA := NewNode(idA, roomID, roomKey, DefaultConfig(), trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	idB, _ := NewIdentity()
	trB := newMemoryTransport(idB.Address())
	var nodeB *Node
	nodeB = NewNode(idB, roomID, roomKey, DefaultConfig(), trB, Hooks{
		OnAttachmentOffer: func(meta *AttachmentMeta) {
			// Trigger on-demand download
			_ = nodeB.DownloadAttachment(meta.FileID)
		},
		OnAttachment: func(meta *AttachmentMeta, data []byte) {
			attachmentComplete <- data
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	trA.Connect(trB)
	nodeA.AddPeer(nodeB.Address())
	nodeB.AddPeer(nodeA.Address())

	// 5 MB synthetic test data (> 80 chunks of 64KB) to verify windowed streaming
	fileSize := 5 * 1024 * 1024
	testData := make([]byte, fileSize)
	for i := range testData {
		testData[i] = byte(i % 251)
	}

	meta, err := nodeA.ShareAttachment("large-test.bin", "application/octet-stream", testData)
	if err != nil {
		t.Fatalf("failed to share large attachment: %v", err)
	}
	if meta.TotalChunks < 80 {
		t.Fatalf("expected >= 80 chunks for 5 MB, got %d", meta.TotalChunks)
	}

	select {
	case receivedData := <-attachmentComplete:
		if len(receivedData) != fileSize {
			t.Fatalf("expected %d bytes, got %d", fileSize, len(receivedData))
		}
		for i := range testData {
			if testData[i] != receivedData[i] {
				t.Fatalf("byte mismatch at index %d", i)
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for large file transfer completion")
	}
}

func TestMultiPeerSwarmFileSharingAndLateJoin(t *testing.T) {
	roomKey, _ := GenerateRoomKey()
	roomID := "swarm-room"

	idA, _ := NewIdentity()
	trA := newMemoryTransport(idA.Address())
	nodeA := NewNode(idA, roomID, roomKey, DefaultConfig(), trA, Hooks{})
	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }

	idB, _ := NewIdentity()
	trB := newMemoryTransport(idB.Address())
	bOffers := make(chan *AttachmentMeta, 10)
	bComplete := make(chan []byte, 1)
	nodeB := NewNode(idB, roomID, roomKey, DefaultConfig(), trB, Hooks{
		OnAttachmentOffer: func(meta *AttachmentMeta) {
			bOffers <- meta
		},
		OnAttachment: func(meta *AttachmentMeta, data []byte) {
			bComplete <- data
		},
	})
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }

	idC, _ := NewIdentity()
	trC := newMemoryTransport(idC.Address())
	cOffers := make(chan *AttachmentMeta, 10)
	cComplete := make(chan []byte, 1)
	nodeC := NewNode(idC, roomID, roomKey, DefaultConfig(), trC, Hooks{
		OnAttachmentOffer: func(meta *AttachmentMeta) {
			cOffers <- meta
		},
		OnAttachment: func(meta *AttachmentMeta, data []byte) {
			cComplete <- data
		},
	})
	trC.onData = func(from string, data []byte) { nodeC.HandleWire(from, data) }

	// Connect A, B, C into a full mesh
	trA.Connect(trB)
	trA.Connect(trC)
	trB.Connect(trC)
	nodeA.AddPeer(nodeB.Address())
	nodeA.AddPeer(nodeC.Address())
	nodeB.AddPeer(nodeA.Address())
	nodeB.AddPeer(nodeC.Address())
	nodeC.AddPeer(nodeA.Address())
	nodeC.AddPeer(nodeB.Address())

	// 1. Node A shares File 1 (128 KB)
	file1Size := 128 * 1024
	file1Data := make([]byte, file1Size)
	_, _ = io.ReadFull(rand.Reader, file1Data)

	meta1, err := nodeA.ShareAttachment("file1.bin", "application/octet-stream", file1Data)
	if err != nil {
		t.Fatalf("failed to share file 1: %v", err)
	}

	// Wait for offer on nodeB and nodeC
	select {
	case off := <-bOffers:
		if off.FileID != meta1.FileID {
			t.Fatalf("nodeB expected offer %s, got %s", meta1.FileID, off.FileID)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for nodeB to receive attachment offer")
	}

	// 2. Node B downloads File 1 from Node A
	if err := nodeB.DownloadAttachment(meta1.FileID); err != nil {
		t.Fatalf("nodeB failed to start download: %v", err)
	}

	select {
	case data := <-bComplete:
		if len(data) != file1Size {
			t.Fatalf("nodeB expected %d bytes, got %d", file1Size, len(data))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for nodeB to download file 1")
	}

	// 3. Now simulate Node A disconnecting (leaving the room)
	trA.Disconnect(trB)
	trA.Disconnect(trC)
	nodeB.RemovePeer(nodeA.Address())
	nodeC.RemovePeer(nodeA.Address())

	// 4. Node C now downloads File 1 from Node B (the swarm seeder!)
	if err := nodeC.DownloadAttachment(meta1.FileID); err != nil {
		t.Fatalf("nodeC failed to download file 1 from swarm: %v", err)
	}

	select {
	case data := <-cComplete:
		if len(data) != file1Size {
			t.Fatalf("nodeC expected %d bytes, got %d", file1Size, len(data))
		}
		for i := range file1Data {
			if file1Data[i] != data[i] {
				t.Fatalf("byte mismatch on nodeC at index %d", i)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for nodeC to download file 1 from nodeB swarm seeder")
	}

	// 5. Now Node D joins late (connects to Node B and Node C after File 1 was shared)
	idD, _ := NewIdentity()
	trD := newMemoryTransport(idD.Address())
	dOffers := make(chan *AttachmentMeta, 10)
	dComplete := make(chan []byte, 1)
	nodeD := NewNode(idD, roomID, roomKey, DefaultConfig(), trD, Hooks{
		OnAttachmentOffer: func(meta *AttachmentMeta) {
			dOffers <- meta
		},
		OnAttachment: func(meta *AttachmentMeta, data []byte) {
			dComplete <- data
		},
	})
	trD.onData = func(from string, data []byte) { nodeD.HandleWire(from, data) }

	trB.Connect(trD)
	trC.Connect(trD)
	nodeB.AddPeer(nodeD.Address())
	nodeC.AddPeer(nodeD.Address())
	nodeD.AddPeer(nodeB.Address())
	nodeD.AddPeer(nodeC.Address())

	// Node D requests catchup
	_ = nodeD.RequestCatchUp()

	// Verify Node D receives offer for File 1
	select {
	case off := <-dOffers:
		if off.FileID != meta1.FileID {
			t.Fatalf("nodeD expected offer %s, got %s", meta1.FileID, off.FileID)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for nodeD to receive synchronized offer")
	}

	// Node D downloads File 1 from Node B / C
	if err := nodeD.DownloadAttachment(meta1.FileID); err != nil {
		t.Fatalf("nodeD failed to download file 1: %v", err)
	}

	select {
	case data := <-dComplete:
		if len(data) != file1Size {
			t.Fatalf("nodeD expected %d bytes, got %d", file1Size, len(data))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for nodeD to download file 1")
	}
}
