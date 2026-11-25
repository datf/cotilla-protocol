package cotilla

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestPacket_UnicastAndGroupSealingAndHopVerification(t *testing.T) {
	alice, _ := NewIdentity()
	bob, _ := NewIdentity()
	charlie, _ := NewIdentity()

	// 1. Plain peer_request broadcast survives HopLimit decrement while rejecting tampering
	pkt, err := NewPlainPacket(alice, BroadcastAddr, PortPeerRequest, 4, PeerRequestPayload{WantCount: 6})
	if err != nil {
		t.Fatalf("NewPlainPacket: %v", err)
	}
	pkt.HopLimit = 2
	if err := VerifyPacket(pkt, 20, time.Minute); err != nil {
		t.Fatalf("VerifyPacket after hop decrement failed: %v", err)
	}
	tampered := *pkt
	tampered.HopStart = 5
	if err := VerifyPacket(&tampered, 20, time.Minute); err == nil {
		t.Fatal("expected VerifyPacket to reject mutated HopStart")
	}

	// 2. Unicast encrypted peer_response can only be opened by intended recipient
	uni, err := NewUnicastPacket(bob, alice.Address(), alice.EncAddress(), PortPeerResponse, 4, PeerResponsePayload{
		RequestID: pkt.ID,
		Peers:     []PeerDescriptor{{SignPub: charlie.Address(), EncPub: charlie.EncAddress()}},
	})
	if err != nil {
		t.Fatalf("NewUnicastPacket: %v", err)
	}
	sd, err := OpenUnicastPacket(alice, uni)
	if err != nil || sd.Port != PortPeerResponse {
		t.Fatalf("alice failed to open unicast packet: err=%v", err)
	}
	if _, err := OpenUnicastPacket(charlie, uni); err == nil {
		t.Fatal("charlie must not be able to decrypt unicast packet intended for alice")
	}

	// 3. Group encrypted packet isolates by ChannelHash + PSK
	psk, _ := GenerateRoomKey()
	wrongKey, _ := GenerateRoomKey()
	chHash := ComputeChannelHash("seeder-public", psk)
	grp, err := NewGroupPacket(alice, BroadcastAddr, chHash, 0, psk, PortAppManifestReq, 6, AppManifestRequest{AppID: "cotilla-svelte"})
	if err != nil {
		t.Fatalf("NewGroupPacket: %v", err)
	}
	gsd, err := OpenGroupPacket(psk, grp)
	if err != nil || gsd.Port != PortAppManifestReq {
		t.Fatalf("failed to open group packet: %v", err)
	}
	if _, err := OpenGroupPacket(wrongKey, grp); err == nil {
		t.Fatal("wrong PSK must fail to decrypt group packet")
	}
}

func TestExpandingBroadcaster_DoublesTTLAndFanout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.InitialBroadcastTTL = 1
	cfg.InitialBroadcastFanout = 2
	cfg.MaxBroadcastTTL = 4
	cfg.MaxPeers = 16
	cfg.BroadcastHopTimeout = 15 * time.Millisecond

	b := NewExpandingBroadcaster(cfg)
	defer b.Stop()

	type attempt struct {
		ttl    int
		fanout int
	}
	var mu sync.Mutex
	var got []attempt
	done := make(chan struct{})

	b.Start("peer_request", 4, func(ttl, fanout int) {
		mu.Lock()
		got = append(got, attempt{ttl, fanout})
		n := len(got)
		mu.Unlock()
		if n == 3 {
			b.MarkSatisfied("peer_request")
			close(done)
		}
	})

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for expanding broadcast attempts")
	}

	mu.Lock()
	defer mu.Unlock()
	expected := []attempt{{1, 2}, {2, 4}, {4, 8}}
	if len(got) != len(expected) {
		t.Fatalf("got %v, want %v", got, expected)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("attempt %d: got %+v, want %+v", i, got[i], expected[i])
		}
	}
}

func TestHyParView_MultiPeerRepairAndGroupQuotas(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxPeers = 8
	cfg.MinPrivateGroupPeers = 6
	cfg.MinPublicGroupPeers = 2
	cfg.PassiveViewSize = 20

	selfID, _ := NewIdentity()
	ov := NewOverlayView(selfID.Address(), cfg)

	privKey, _ := GenerateRoomKey()
	pubKey, _ := GenerateRoomKey()
	privHash := ComputeChannelHash("private-room", privKey)
	pubHash := ComputeChannelHash("public-seeder", pubKey)

	// Populate 6 private group peers + 2 public group peers + 2 general overlay peers in active view
	var generalPeers []string
	for i := 0; i < 6; i++ {
		id, _ := NewIdentity()
		ov.AddActive(id.Address(), false)
		ov.MarkChannelPeer(id.Address(), privHash)
	}
	for i := 0; i < 2; i++ {
		id, _ := NewIdentity()
		ov.AddActive(id.Address(), false)
		ov.MarkChannelPeer(id.Address(), pubHash)
	}
	for i := 0; i < 2; i++ {
		id, _ := NewIdentity()
		ov.AddActive(id.Address(), false)
		generalPeers = append(generalPeers, id.Address())
	}

	// Add passive candidates advertising privHash
	passiveID, _ := NewIdentity()
	ov.AddPassive(PeerDescriptor{SignPub: passiveID.Address(), EncPub: passiveID.EncAddress(), ChannelHashes: []uint32{privHash}})

	// PickRotationVictim must only select a general peer, never dropping private (<6) or public (<2) below quota
	mins := map[uint32]int{privHash: cfg.MinPrivateGroupPeers, pubHash: cfg.MinPublicGroupPeers}
	victim := ov.PickRotationVictim(mins, 0)
	if victim != generalPeers[0] && victim != generalPeers[1] {
		t.Fatalf("PickRotationVictim chose protected group peer %s instead of excess general peer", victim)
	}

	// Repair prioritizes passive candidate matching needed private channel
	repair := ov.PickRepairCandidates(map[uint32]bool{privHash: true}, 1)
	if len(repair) != 1 || repair[0].SignPub != passiveID.Address() {
		t.Fatalf("expected passive private-group peer %s, got %+v", passiveID.Address(), repair)
	}
}

func TestPublicAppSeeder_MultiPeerEncryptedManifestAndChunks(t *testing.T) {
	pubHex, privHex, err := GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair: %v", err)
	}
	bundleData := bytes.Repeat([]byte("<html><body>Cotilla Svelte App v2</body></html>"), 2000)
	manifest, err := SignAppBundle(privHex, "cotilla-svelte", "stable", "2.1.0", 5, bundleData, "text/html; charset=utf-8", FormatSingleHTMLV1, time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle: %v", err)
	}

	// 4-peer topology: Seeder <-> Relay <-> ClientA, Relay <-> ClientB (3+ peers per AGENTS.md)
	seederID, _ := NewIdentity()
	relayID, _ := NewIdentity()
	clientAID, _ := NewIdentity()
	clientBID, _ := NewIdentity()

	cfg := DefaultConfig()
	cfg.BroadcastHopTimeout = 20 * time.Millisecond

	bus := newPacketTestBus()
	defer bus.close()

	seederTr := bus.register(seederID.Address())
	relayTr := bus.register(relayID.Address())
	clientATr := bus.register(clientAID.Address())
	clientBTr := bus.register(clientBID.Address())

	seederKey := AppDistRoomKeyFor("cotilla-app-dist-v1")
	seederNode := NewNode(seederID, "cotilla-app-dist-v1", seederKey, cfg, seederTr, Hooks{})
	relayNode := NewNode(relayID, "relay-only", RoomKey{1}, cfg, relayTr, Hooks{})

	gotA := make(chan []byte, 1)
	gotB := make(chan []byte, 1)
	clientANode := NewNode(clientAID, "cotilla-app-dist-v1", seederKey, cfg, clientATr, Hooks{
		OnAppBundleReady: func(m *AppManifest, data []byte) { gotA <- data },
	})
	clientBNode := NewNode(clientBID, "cotilla-app-dist-v1", seederKey, cfg, clientBTr, Hooks{
		OnAppBundleReady: func(m *AppManifest, data []byte) { gotB <- data },
	})

	bus.bind(seederID.Address(), seederNode)
	bus.bind(relayID.Address(), relayNode)
	bus.bind(clientAID.Address(), clientANode)
	bus.bind(clientBID.Address(), clientBNode)

	// Connect through blind relay (Relay does NOT know the seeder group PSK!)
	bus.connect(seederID.Address(), relayID.Address())
	bus.connect(relayID.Address(), clientAID.Address())
	bus.connect(relayID.Address(), clientBID.Address())

	if err := seederNode.RegisterAppBundle("cotilla-app-dist-v1", seederKey, manifest, bundleData, pubHex); err != nil {
		t.Fatalf("RegisterAppBundle: %v", err)
	}

	appCfg := AppBootstrapConfig{
		AppName:         "cotilla-svelte",
		Version:         "2.1.0",
		MinSeq:          5,
		ValidSignatures: []string{pubHex},
		SeederGroup:     SeederGroupConfig{Name: "cotilla-app-dist-v1", Channel: "stable"},
	}
	if _, err := clientANode.BootstrapApp(appCfg); err != nil {
		t.Fatalf("clientA BootstrapApp: %v", err)
	}
	if _, err := clientBNode.BootstrapApp(appCfg); err != nil {
		t.Fatalf("clientB BootstrapApp: %v", err)
	}

	for name, ch := range map[string]chan []byte{"ClientA": gotA, "ClientB": gotB} {
		select {
		case data := <-ch:
			if !bytes.Equal(data, bundleData) {
				t.Fatalf("%s received corrupted bundle bytes", name)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("%s timed out downloading app bundle through blind relay", name)
		}
	}
}

type packetTestBus struct {
	mu    sync.RWMutex
	nodes map[string]*Node
	links map[string]map[string]bool
}

func newPacketTestBus() *packetTestBus {
	return &packetTestBus{
		nodes: make(map[string]*Node),
		links: make(map[string]map[string]bool),
	}
}

func (b *packetTestBus) close() {}

func (b *packetTestBus) register(addr string) Transport {
	b.mu.Lock()
	b.links[addr] = make(map[string]bool)
	b.mu.Unlock()
	return &busTransport{bus: b, self: addr}
}

func (b *packetTestBus) bind(addr string, n *Node) {
	b.mu.Lock()
	b.nodes[addr] = n
	b.mu.Unlock()
}

func (b *packetTestBus) connect(a, c string) {
	b.mu.Lock()
	b.links[a][c] = true
	b.links[c][a] = true
	na, nc := b.nodes[a], b.nodes[c]
	b.mu.Unlock()
	if na != nil {
		na.AddPeer(c)
	}
	if nc != nil {
		nc.AddPeer(a)
	}
}

type busTransport struct {
	bus  *packetTestBus
	self string
}

func (t *busTransport) Send(addr string, data []byte) error {
	t.bus.mu.RLock()
	connected := t.bus.links[t.self][addr]
	dst := t.bus.nodes[addr]
	t.bus.mu.RUnlock()
	if !connected || dst == nil {
		return ErrTreeKEMLeafNotFound
	}
	cp := append([]byte(nil), data...)
	go dst.HandleWire(t.self, cp)
	return nil
}

func (t *busTransport) Broadcast(data []byte) {
	for _, p := range t.Peers() {
		_ = t.Send(p, data)
	}
}

func (t *busTransport) Peers() []string {
	t.bus.mu.RLock()
	defer t.bus.mu.RUnlock()
	out := make([]string, 0, len(t.bus.links[t.self]))
	for p := range t.bus.links[t.self] {
		out = append(out, p)
	}
	return out
}

func (t *busTransport) ClosePeer(addr string) {
	t.bus.mu.Lock()
	delete(t.bus.links[t.self], addr)
	delete(t.bus.links[addr], t.self)
	t.bus.mu.Unlock()
}
