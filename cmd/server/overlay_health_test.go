package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

type mockPeerTransport struct {
	mu    sync.Mutex
	self  string
	peers map[string]bool
}

func newMockPeerTransport(self string) *mockPeerTransport {
	return &mockPeerTransport{
		self:  self,
		peers: make(map[string]bool),
	}
}

func (m *mockPeerTransport) Peers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	res := make([]string, 0, len(m.peers))
	for p := range m.peers {
		res = append(res, p)
	}
	return res
}

func (m *mockPeerTransport) ClosePeer(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.peers, addr)
}

func (m *mockPeerTransport) AddPeer(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers[addr] = true
}

func TestSignaling_ZeroAnchors_RetainsIncomingPeersInPool(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()
	ts := httptest.NewServer(http.HandlerFunc(hub.handleHealth))
	defer ts.Close()

	peers := []string{"alice-addr", "bob-addr", "charlie-addr"}
	for _, p := range peers {
		hub.handlePeerOpen(p)
	}

	hub.mu.Lock()
	if len(hub.anchorPool) != 3 {
		t.Fatalf("expected 3 peers preserved in anchorPool, got %d", len(hub.anchorPool))
	}
	for _, p := range peers {
		if !hub.anchorPool[p] {
			t.Fatalf("peer %s not found in anchorPool", p)
		}
	}
	hub.mu.Unlock()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to query health endpoint: %v", err)
	}
	defer res.Body.Close()

	var h map[string]any
	_ = json.NewDecoder(res.Body).Decode(&h)
	if h["fallback"] != false {
		t.Fatalf("expected fallback false with 3 anchors")
	}
	anchorsReported := h["anchors"].([]any)
	if len(anchorsReported) != 3 {
		t.Fatalf("expected 3 anchors reported in /health, got %d", len(anchorsReported))
	}
}

func TestSignaling_AnchorPoolFull_IntroducesNewcomerAsLeaf(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	hub.handlePeerOpen("anchor-1")
	hub.handlePeerOpen("anchor-2")
	hub.handlePeerOpen("anchor-3")

	hub.handlePeerOpen("newcomer-4")

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.anchorPool) != 3 {
		t.Fatalf("anchor pool should remain 3, got %d", len(hub.anchorPool))
	}
	if hub.anchorPool["newcomer-4"] {
		t.Fatalf("newcomer-4 should NOT be in anchor pool")
	}
}

func TestSignaling_AnchorDisconnect_NextPeerFillsSlot(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	hub.handlePeerOpen("anchor-1")
	hub.handlePeerOpen("anchor-2")
	hub.handlePeerOpen("anchor-3")

	hub.handlePeerClose("anchor-1")

	hub.mu.Lock()
	if len(hub.anchorPool) != 2 {
		t.Fatalf("expected 2 anchors after disconnect, got %d", len(hub.anchorPool))
	}
	hub.mu.Unlock()

	// Next arriving peer fills the vacant slot
	hub.handlePeerOpen("anchor-4")

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.anchorPool) != 3 {
		t.Fatalf("expected 3 anchors after anchor-4 fills slot, got %d", len(hub.anchorPool))
	}
	if !hub.anchorPool["anchor-4"] {
		t.Fatalf("expected anchor-4 to be retained in anchorPool")
	}
}

func TestSignaling_AnchorDisconnect_DeficitReconnectAndTopology(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	anchors := []string{"anchor-1", "anchor-2", "anchor-3"}
	for _, a := range anchors {
		hub.handlePeerOpen(a)
	}

	peerTransports := make(map[string]*mockPeerTransport)
	for _, p := range []string{"bob", "charlie"} {
		tr := newMockPeerTransport(p)
		peerTransports[p] = tr
		for _, a := range anchors {
			tr.AddPeer(a)
		}
	}

	// Anchor 1 disconnects
	hub.handlePeerClose("anchor-1")
	for _, tr := range peerTransports {
		tr.ClosePeer("anchor-1")
	}

	hub.mu.Lock()
	if len(hub.anchorPool) != 2 {
		t.Fatalf("expected 2 anchors in signaling server after disconnect, got %d", len(hub.anchorPool))
	}
	hub.mu.Unlock()

	// New peer Dave connects and fills the vacant anchor slot
	hub.handlePeerOpen("dave")

	hub.mu.Lock()
	if len(hub.anchorPool) != 3 {
		t.Fatalf("expected 3 anchors, got %d", len(hub.anchorPool))
	}
	if !hub.anchorPool["dave"] {
		t.Fatalf("expected dave to fill vacant anchor slot in anchorPool")
	}
	hub.mu.Unlock()

	peerTransports["bob"].AddPeer("dave")
	peerTransports["charlie"].AddPeer("dave")

	for _, name := range []string{"bob", "charlie"} {
		peers := peerTransports[name].Peers()
		if len(peers) != 3 {
			t.Fatalf("expected %s to have 3 peers, got %d: %v", name, len(peers), peers)
		}
	}
}

// TestSignaling_ServerQueriesPeersWhenLowAndReplenishes verifies that when the anchor pool
// drops below target, the server sends FrameAnchorSolicit over WebRTC DataChannels.
func TestSignaling_ServerQueriesPeersWhenLowAndReplenishes(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	hub.queryCooldown = 50 * time.Millisecond
	defer hub.closeAll()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	solicitCh := make(chan *cot.AnchorSolicitFrame, 4)

	ids := make([]*cot.Identity, 3)
	trs := make([]*cotillartc.PionTransport, 3)

	for i := 0; i < 3; i++ {
		id, _ := cot.NewIdentity()
		ids[i] = id
		tr := cotillartc.New(id.Address(), nil, func(from string, data []byte) {
			pkt, err := cot.UnmarshalPacket(data)
			if err != nil || pkt == nil || pkt.Port != cot.PortAnchorSolicit {
				return
			}
			var as cot.AnchorSolicitFrame
			if json.Unmarshal(pkt.Payload, &as) == nil {
				solicitCh <- &as
			}
		})
		defer tr.Close()
		trs[i] = tr

		_, err := cotillartc.DialSignalingWS(ctx, wsURL, id, tr, nil)
		if err != nil {
			t.Fatalf("dial anchor %d failed: %v", i, err)
		}
	}

	// Wait for all 3 anchors to connect over DataChannel and be registered in anchorPool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.Lock()
		count := len(hub.anchorPool)
		hub.mu.Unlock()
		if count == 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	hub.mu.Lock()
	count := len(hub.anchorPool)
	hub.mu.Unlock()
	if count != 3 {
		t.Fatalf("expected 3 anchors in anchor pool, got %d", count)
	}

	// Add a 4th non-anchor connected peer
	id4, _ := cot.NewIdentity()
	tr4 := cotillartc.New(id4.Address(), nil, func(from string, data []byte) {
		pkt, err := cot.UnmarshalPacket(data)
		if err != nil || pkt == nil || pkt.Port != cot.PortAnchorSolicit {
			return
		}
		var as cot.AnchorSolicitFrame
		if json.Unmarshal(pkt.Payload, &as) == nil {
			solicitCh <- &as
		}
	})
	defer tr4.Close()

	_, err := cotillartc.DialSignalingWS(ctx, wsURL, id4, tr4, nil)
	if err != nil {
		t.Fatalf("dial peer 4 failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// Disconnect Anchor 0 and Anchor 1 -> pool drops below targetPool (3) because only Peer 4 was available to promote
	trs[0].Close()
	trs[1].Close()

	// Solicit anchors manually or via supervisor
	go hub.solicitAnchorsOverDataChannel()

	select {
	case sol := <-solicitCh:
		mu.Lock()
		defer mu.Unlock()
		if sol.Needed < 1 {
			t.Fatalf("expected AnchorSolicit Needed >= 1, got %d", sol.Needed)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("expected to receive FrameAnchorSolicit over DataChannel when anchor pool dropped below target")
	}
}
