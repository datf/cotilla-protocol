package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

type turnoverPeerOpts struct {
	markAnchors         bool
	reconnectOnDeficit  bool
	reconnectOnSolicit  bool
	keepRootWSConnected bool
}

type turnoverPeer struct {
	t      *testing.T
	name   string
	roomID string
	wsURL  string
	opts   turnoverPeerOpts

	id   *cot.Identity
	tr   *rtc.PionTransport
	node *cot.Node

	ctx    context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	gatewayAddr string
	msgs        []string
	left        bool
}

func newTurnoverPeer(
	t *testing.T,
	name string,
	seed string,
	roomID string,
	roomKey cot.RoomKey,
	wsURL string,
	isCreator bool,
	invite *cot.ChannelInvite,
	opts turnoverPeerOpts,
) *turnoverPeer {
	t.Helper()

	seedBytes := []byte(fmt.Sprintf("%-32s", seed))[:32]
	id, err := cot.NewIdentityFromSeed(seedBytes)
	if err != nil {
		t.Fatalf("%s identity: %v", name, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &turnoverPeer{
		t:      t,
		name:   name,
		roomID: roomID,
		wsURL:  wsURL,
		opts:   opts,
		id:     id,
		ctx:    ctx,
		cancel: cancel,
	}

	p.tr = rtc.New(id.Address(), nil, func(from string, data []byte) {
		if p.node != nil {
			p.node.HandleWire(from, data)
		}
	})

	p.node = cot.NewNode(id, roomID, roomKey, cot.DefaultConfig(), p.tr, cot.Hooks{
		OnMessage: func(env *cot.Envelope, plaintext []byte) {
			var chat cot.ChatPayload
			if err := json.Unmarshal(plaintext, &chat); err == nil && chat.Text != "" {
				p.mu.Lock()
				p.msgs = append(p.msgs, chat.Text)
				p.mu.Unlock()
			}
		},
		OnChannelDiscovered: func(channelID, peer string) {
			// Channel discovery can arrive over 2+ hops; only tr.OnOpen registers active overlay peers.
		},
		OnAnchorIntro: func(anchors []string, fallback bool) {
			p.maybeCloseLeafGateway()
		},
		OnAnchorDeficit: func(currentAnchors, activePeers int) {
			if !opts.reconnectOnDeficit || p.ctx.Err() != nil {
				return
			}
			t.Logf("[%s] OnAnchorDeficit triggered (anchors=%d activePeers=%d)", p.name, currentAnchors, activePeers)
			go func() {
				_ = p.connectSignaling()
			}()
		},
		OnAnchorSolicit: func(needed int) {
			if !opts.reconnectOnSolicit || p.ctx.Err() != nil {
				return
			}
			p.mu.Lock()
			hasGW := p.gatewayAddr != "" && p.tr.HasActiveOrPending(p.gatewayAddr)
			p.mu.Unlock()
			if hasGW {
				return
			}
			t.Logf("[%s] OnAnchorSolicit triggered (needed=%d)", p.name, needed)
			go func() {
				_ = p.connectSignaling()
			}()
		},
		Log: func(msg string) {
			t.Logf("[%s] %s", name, msg)
		},
	})

	p.tr.OnOpen(func(addr string) {
		p.node.AddPeer(addr)
		if p.node.IsGatewayPeer(addr) {
			return
		}
		_ = p.node.RequestCatchUp()
		go p.node.BroadcastPeerInfo()
		go func() {
			_ = p.node.JoinChannel(p.roomID)
		}()

		p.maybeCloseLeafGateway()
	})
	p.tr.OnClose(func(addr string) {
		p.node.RemovePeer(addr)
	})

	if isCreator {
		if err := p.node.InitGenesisEpoch(); err != nil {
			t.Fatalf("%s InitGenesisEpoch: %v", name, err)
		}
	}
	if invite != nil {
		p.node.SetChannelInvite(invite)
	}
	p.node.StartMeshSupervisor(ctx, 2*time.Second)

	t.Cleanup(func() {
		p.leave()
	})
	return p
}

func (p *turnoverPeer) connectSignaling() error {
	p.mu.Lock()
	if p.left || (p.gatewayAddr != "" && p.tr.HasActiveOrPending(p.gatewayAddr)) {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	serverAddr, err := rtc.DialSignalingWS(p.ctx, p.wsURL, p.id, p.tr, p.node)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.gatewayAddr = serverAddr
	p.mu.Unlock()
	p.maybeCloseLeafGateway()
	return nil
}

func (p *turnoverPeer) maybeCloseLeafGateway() {
	p.mu.Lock()
	gw := p.gatewayAddr
	p.mu.Unlock()
	if gw == "" || p.node.IsAnchorPeer(p.id.Address()) {
		return
	}
	nonGW := 0
	for _, peer := range p.tr.Peers() {
		if !p.node.IsGatewayPeer(peer) {
			nonGW++
		}
	}
	if nonGW >= 2 {
		p.tr.ClosePeer(gw)
		p.mu.Lock()
		if p.gatewayAddr == gw {
			p.gatewayAddr = ""
		}
		p.mu.Unlock()
	}
}

func (p *turnoverPeer) leave() {
	p.mu.Lock()
	if p.left {
		p.mu.Unlock()
		return
	}
	p.left = true
	gw := p.gatewayAddr
	p.gatewayAddr = ""
	p.mu.Unlock()

	p.cancel()
	if p.node != nil {
		p.node.StopMeshSupervisor()
		_ = p.node.Leave()
	}
	if p.tr != nil {
		if gw != "" {
			p.tr.ClosePeer(gw)
		}
		p.tr.Close()
	}
}

func (p *turnoverPeer) hasMsg(substr string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, m := range p.msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func (p *turnoverPeer) role() string {
	if p.node != nil && p.node.IsAnchorPeer(p.id.Address()) {
		return "root"
	}
	return "leaf"
}

func waitForCondition(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for: %s", timeout, desc)
}

func waitForAllChannelPeers(t *testing.T, roomID string, peers []*turnoverPeer, minDirect int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		maxEpoch := int64(0)
		for _, p := range peers {
			if ep := p.node.CurrentEpoch(); ep > maxEpoch {
				maxEpoch = ep
			}
		}
		if maxEpoch > 0 {
			allReady := true
			for _, p := range peers {
				if p.node.CurrentEpoch() < maxEpoch || len(p.tr.Peers()) < minDirect {
					allReady = false
					break
				}
				for _, other := range peers {
					if other == p {
						continue
					}
					found := false
					for _, live := range p.tr.Peers() {
						if live == other.id.Address() {
							found = true
							break
						}
					}
					if !found {
						allReady = false
						break
					}
				}
				if !allReady {
					break
				}
			}
			if allReady {
				return
			}
		}
		time.Sleep(40 * time.Millisecond)
	}
	var diag []string
	for _, p := range peers {
		diag = append(diag, fmt.Sprintf("%s(ep=%d trPeers=%d active=%d)", p.name, p.node.CurrentEpoch(), len(p.tr.Peers()), len(p.node.Peers())))
	}
	t.Fatalf("timed out after %v waiting for all %d peers in %s to reach equal maxEpoch>0 and >=%d direct peers: %s",
		timeout, len(peers), roomID, minDirect, strings.Join(diag, ", "))
}

func sendAndWaitAll(t *testing.T, sender *turnoverPeer, receivers []*turnoverPeer, text string, timeout time.Duration) {
	t.Helper()
	if _, err := sender.node.SendMessage(text); err != nil {
		t.Fatalf("%s SendMessage(%q): %v", sender.name, text, err)
	}
	waitForCondition(t, timeout, fmt.Sprintf("all receivers get %q from %s", text, sender.name), func() bool {
		for _, r := range receivers {
			if !r.hasMsg(text) {
				return false
			}
		}
		return true
	})
}

func runTwoRoomsTurnoverScenario(t *testing.T, opts turnoverPeerOpts) {
	t.Helper()

	hub := newSignalingHubWithTarget(3)
	hub.queryCooldown = 50 * time.Millisecond
	hub.startSupervisor(t.Context(), 100*time.Millisecond)
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", hub.handleHealth)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// 1. A1 creates Room 1, invites B1 & C1, they join, they chat
	key1, err := cot.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey room-1: %v", err)
	}
	room1 := "room-alpha-1"
	a1 := newTurnoverPeer(t, "A1", "seed-turnover-A1-unique", room1, key1, wsURL, true, nil, opts)
	if err := a1.connectSignaling(); err != nil {
		t.Fatalf("A1 connect: %v", err)
	}
	invB1, err := a1.node.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("A1 CreateChannelInvite for B1: %v", err)
	}
	invC1, err := a1.node.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("A1 CreateChannelInvite for C1: %v", err)
	}
	b1 := newTurnoverPeer(t, "B1", "seed-turnover-B1-unique", room1, key1, wsURL, false, invB1, opts)
	c1 := newTurnoverPeer(t, "C1", "seed-turnover-C1-unique", room1, key1, wsURL, false, invC1, opts)
	if err := b1.connectSignaling(); err != nil {
		t.Fatalf("B1 connect: %v", err)
	}
	if err := c1.connectSignaling(); err != nil {
		t.Fatalf("C1 connect: %v", err)
	}

	waitForAllChannelPeers(t, room1, []*turnoverPeer{a1, b1, c1}, 2, 15*time.Second)
	sendAndWaitAll(t, a1, []*turnoverPeer{b1, c1}, "r1-hello-from-A1", 10*time.Second)
	sendAndWaitAll(t, b1, []*turnoverPeer{a1, c1}, "r1-reply-from-B1", 10*time.Second)
	t.Logf("[PHASE 1 OK] A1(%s), B1(%s), C1(%s) chatting in %s (epochs=%d/%d/%d)",
		a1.role(), b1.role(), c1.role(), room1, a1.node.CurrentEpoch(), b1.node.CurrentEpoch(), c1.node.CurrentEpoch())

	// 2. A2 creates Room 2, invites B2 & C2, they join, they chat, they invite D2 (D2 doesn't join yet)
	key2, err := cot.GenerateRoomKey()
	if err != nil {
		t.Fatalf("GenerateRoomKey room-2: %v", err)
	}
	room2 := "room-beta-2"
	a2 := newTurnoverPeer(t, "A2", "seed-turnover-A2-unique", room2, key2, wsURL, true, nil, opts)
	if err := a2.connectSignaling(); err != nil {
		t.Fatalf("A2 connect: %v", err)
	}
	invB2, err := a2.node.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("A2 CreateChannelInvite for B2: %v", err)
	}
	invC2, err := a2.node.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("A2 CreateChannelInvite for C2: %v", err)
	}
	b2 := newTurnoverPeer(t, "B2", "seed-turnover-B2-unique", room2, key2, wsURL, false, invB2, opts)
	c2 := newTurnoverPeer(t, "C2", "seed-turnover-C2-unique", room2, key2, wsURL, false, invC2, opts)
	if err := b2.connectSignaling(); err != nil {
		t.Fatalf("B2 connect: %v", err)
	}
	if err := c2.connectSignaling(); err != nil {
		t.Fatalf("C2 connect: %v", err)
	}

	waitForAllChannelPeers(t, room2, []*turnoverPeer{a2, b2, c2}, 2, 20*time.Second)
	sendAndWaitAll(t, a2, []*turnoverPeer{b2, c2}, "r2-hello-from-A2", 10*time.Second)
	sendAndWaitAll(t, c2, []*turnoverPeer{a2, b2}, "r2-reply-from-C2", 10*time.Second)

	// Verify room 1 did not decrypt room 2 traffic
	if a1.hasMsg("r2-hello-from-A2") || b1.hasMsg("r2-reply-from-C2") {
		t.Fatalf("cryptographic isolation broken: room-1 decrypted room-2 messages")
	}

	// They invite D2 (using C2 or A2), but D2 doesn't join yet
	invD2, err := b2.node.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatalf("B2 CreateChannelInvite for D2: %v", err)
	}
	t.Logf("[PHASE 2 OK] A2(%s), B2(%s), C2(%s) chatting in %s (epochs=%d/%d/%d), invited D2 (not joined yet)",
		a2.role(), b2.role(), c2.role(), room2, a2.node.CurrentEpoch(), b2.node.CurrentEpoch(), c2.node.CurrentEpoch())

	// 3. A1, B1 and C1 leave
	a1.leave()
	b1.leave()
	c1.leave()

	// Allow OnClose / RemovePeer & supervisor ticks to fire
	time.Sleep(2500 * time.Millisecond)

	hub.mu.Lock()
	anchorsAfterLeave := make([]string, 0, len(hub.anchorPool))
	for a := range hub.anchorPool {
		anchorsAfterLeave = append(anchorsAfterLeave, a[:8])
	}
	wsClientsAfterLeave := len(hub.transport.Peers())
	hub.mu.Unlock()
	t.Logf("[PHASE 3 INFO] After A1/B1/C1 left: hub.anchorPool=%v (gateway peers=%d)", anchorsAfterLeave, wsClientsAfterLeave)

	// 4. A2, B2 and C2 continue to chat
	sendAndWaitAll(t, b2, []*turnoverPeer{a2, c2}, "r2-after-room1-left-B2", 10*time.Second)
	sendAndWaitAll(t, a2, []*turnoverPeer{b2, c2}, "r2-after-room1-left-A2", 10*time.Second)
	t.Logf("[PHASE 4 OK] A2, B2, C2 continued chatting after A1/B1/C1 left (epochs=%d/%d/%d)",
		a2.node.CurrentEpoch(), b2.node.CurrentEpoch(), c2.node.CurrentEpoch())

	// 5. D2 joins and tries to chat
	d2 := newTurnoverPeer(t, "D2", "seed-turnover-D2-unique", room2, key2, wsURL, false, invD2, opts)
	if err := d2.connectSignaling(); err != nil {
		t.Fatalf("D2 connect: %v", err)
	}

	waitForAllChannelPeers(t, room2, []*turnoverPeer{a2, b2, c2, d2}, 3, 15*time.Second)
	sendAndWaitAll(t, d2, []*turnoverPeer{a2, b2, c2}, "r2-late-hello-from-D2", 10*time.Second)
	sendAndWaitAll(t, a2, []*turnoverPeer{b2, c2, d2}, "r2-welcome-D2-from-A2", 10*time.Second)
	t.Logf("[PHASE 5 OK] D2 joined, admitted (epoch=%d), and chatted with A2, B2, C2!", d2.node.CurrentEpoch())
}

func TestTwoRooms_Turnover_BrowserWSLifecycle(t *testing.T) {
	runTwoRoomsTurnoverScenario(t, turnoverPeerOpts{
		markAnchors:        true,
		reconnectOnDeficit: true,
		reconnectOnSolicit: true,
	})
}

func TestTwoRooms_Turnover_WithAnchorDeficitReconnect(t *testing.T) {
	runTwoRoomsTurnoverScenario(t, turnoverPeerOpts{
		markAnchors:        true,
		reconnectOnDeficit: true,
		reconnectOnSolicit: true,
	})
}

// TestTwoRooms_Turnover_PartialRootLossReplenishedByServerPeerQuery proves that
// when anchorPool drops from 3 to 2 (leaving >=1 anchor so OnAnchorDeficit does NOT trigger
// on leaves), the signaling server queries connected peers (anchor_query) -> anchors solicit
// WebRTC overlay peers (AnchorSolicit) -> a Room 2 leaf reconnects to /ws -> anchorPool refills to 3.
func TestTwoRooms_Turnover_PartialRootLossReplenishedByServerPeerQuery(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	hub.queryCooldown = 50 * time.Millisecond
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", hub.handleHealth)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	hub.startSupervisor(t.Context(), 100*time.Millisecond)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	opts := turnoverPeerOpts{
		markAnchors:        true,
		reconnectOnDeficit: true,
		reconnectOnSolicit: true,
	}

	key1, _ := cot.GenerateRoomKey()
	room1 := "room-partial-1"
	a1 := newTurnoverPeer(t, "A1", "seed-partial-A1-unique", room1, key1, wsURL, true, nil, opts)
	_ = a1.connectSignaling()
	invB1, _ := a1.node.CreateChannelInvite(15 * time.Minute)
	invC1, _ := a1.node.CreateChannelInvite(15 * time.Minute)
	b1 := newTurnoverPeer(t, "B1", "seed-partial-B1-unique", room1, key1, wsURL, false, invB1, opts)
	c1 := newTurnoverPeer(t, "C1", "seed-partial-C1-unique", room1, key1, wsURL, false, invC1, opts)
	_ = b1.connectSignaling()
	_ = c1.connectSignaling()
	waitForAllChannelPeers(t, room1, []*turnoverPeer{a1, b1, c1}, 2, 15*time.Second)

	key2, _ := cot.GenerateRoomKey()
	room2 := "room-partial-2"
	a2 := newTurnoverPeer(t, "A2", "seed-partial-A2-unique", room2, key2, wsURL, true, nil, opts)
	_ = a2.connectSignaling()
	invB2, _ := a2.node.CreateChannelInvite(15 * time.Minute)
	invC2, _ := a2.node.CreateChannelInvite(15 * time.Minute)
	b2 := newTurnoverPeer(t, "B2", "seed-partial-B2-unique", room2, key2, wsURL, false, invB2, opts)
	c2 := newTurnoverPeer(t, "C2", "seed-partial-C2-unique", room2, key2, wsURL, false, invC2, opts)
	_ = b2.connectSignaling()
	_ = c2.connectSignaling()
	waitForAllChannelPeers(t, room2, []*turnoverPeer{a2, b2, c2}, 2, 20*time.Second)

	invD2, _ := b2.node.CreateChannelInvite(15 * time.Minute)

	// Wait until A2, B2, C2 have closed their leaf gateway channels
	waitForCondition(t, 10*time.Second, "leaf gateway channels closed leaving 3 anchors", func() bool {
		a2.maybeCloseLeafGateway()
		b2.maybeCloseLeafGateway()
		c2.maybeCloseLeafGateway()
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.transport.Peers()) == 3 && len(hub.anchorPool) == 3
	})

	// Only A1 leaves! B1 & C1 remain anchors (liveAnchors >= 1 on leaves so OnAnchorDeficit does NOT fire!)
	a1.leave()

	// Signaling server MUST query B1/C1 -> WebRTC AnchorSolicit -> Room 2 leaf refills anchorPool to 3!
	waitForCondition(t, 6*time.Second, "anchorPool refilled to 3 via server peer query before B1/C1 leave", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		_, hasA2 := hub.anchorPool[a2.id.Address()]
		_, hasB2 := hub.anchorPool[b2.id.Address()]
		_, hasC2 := hub.anchorPool[c2.id.Address()]
		return len(hub.anchorPool) == 3 && (hasA2 || hasB2 || hasC2)
	})

	// Now B1 and C1 leave too -> D2 joins smoothly and chats
	b1.leave()
	c1.leave()

	d2 := newTurnoverPeer(t, "D2", "seed-partial-D2-unique", room2, key2, wsURL, false, invD2, opts)
	if err := d2.connectSignaling(); err != nil {
		t.Fatalf("D2 connect: %v", err)
	}
	waitForAllChannelPeers(t, room2, []*turnoverPeer{a2, b2, c2, d2}, 3, 20*time.Second)
	sendAndWaitAll(t, d2, []*turnoverPeer{a2, b2, c2}, "r2-partial-hello-from-D2", 10*time.Second)
	sendAndWaitAll(t, a2, []*turnoverPeer{b2, c2, d2}, "r2-partial-welcome-from-A2", 10*time.Second)
}
