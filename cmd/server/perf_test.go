package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/datf/cotilla-protocol/internal/perfcheck"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// TestPerf_SignalingServer_MaxClientsChurnAndLeaks measures concurrent real Pion WebRTC
// clients on the signaling server, verifies abandoned /ws handshake cleanup, and checks
// Go 1.27's goroutineleak profile and heap stability.
func TestPerf_SignalingServer_MaxClientsChurnAndLeaks(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	tiers := []int{10, 20}
	if !testing.Short() {
		tiers = []int{25, 50}
		if envC := perfcheck.EnvInt("COTILLA_PERF_CLIENTS", 0); envC > 0 {
			tiers = append(tiers, envC)
		}
	}

	for _, clientCount := range tiers {
		t.Run(fmt.Sprintf("Clients_%d", clientCount), func(t *testing.T) {
			hub := newSignalingHubWithTarget(clientCount)
			supCtx, supCancel := context.WithCancel(context.Background())
			hub.startSupervisor(supCtx, 500*time.Millisecond)

			mux := http.NewServeMux()
			mux.HandleFunc("/ws", hub.handleWS)
			mux.HandleFunc("/health", hub.handleHealth)
			srv := httptest.NewServer(mux)
			wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

			heapBefore := perfcheck.TakeHeapSnapshot()
			start := time.Now()

			type clientConn struct {
				tr *rtc.PionTransport
			}
			clients := make([]*clientConn, clientCount)
			var mu sync.Mutex
			var wg sync.WaitGroup
			var failed atomic.Int64

			// Connect concurrently in bounded waves of 10 to avoid ICE port exhaustion.
			sem := make(chan struct{}, 10)
			for i := 0; i < clientCount; i++ {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					id, _ := cot.NewIdentity()
					tr := rtc.New(id.Address(), nil, func(string, []byte) {})
					ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
					defer cancel()
					if _, err := rtc.DialSignalingWS(ctx, wsURL, id, tr, nil); err != nil {
						failed.Add(1)
						tr.Close()
						return
					}
					mu.Lock()
					clients[idx] = &clientConn{tr: tr}
					mu.Unlock()
				}(i)
			}
			wg.Wait()
			elapsed := time.Since(start)

			if f := failed.Load(); f > 0 {
				t.Fatalf("%d/%d clients failed WebRTC signaling handshake", f, clientCount)
			}

			// Wait until server's WebRTC DataChannels are all open.
			waitForCondition(t, 10*time.Second, fmt.Sprintf("%d server peers open", clientCount), func() bool {
				return len(hub.transport.Peers()) >= clientCount
			})

			heapPeak := perfcheck.TakeHeapSnapshot()
			kbPerClient := float64(int64(heapPeak.HeapAllocKB)-int64(heapBefore.HeapAllocKB)) / float64(clientCount)

			// Exercise abandoned /ws handshakes (register sent, WS closed before answer) -> must not leak PCs.
			for a := 0; a < 5; a++ {
				c, _, err := websocket.Dial(context.Background(), wsURL, nil)
				if err == nil {
					id, _ := cot.NewIdentity()
					ts := time.Now().UnixMilli()
					sig := hex.EncodeToString(id.Sign(cot.CanonicalSignalingMsg("register", id.Address(), "", "", ts)))
					raw, _ := json.Marshal(wsSignalingMessage{Type: "register", Peer: id.Address(), Timestamp: ts, Signature: sig})
					_ = c.Write(context.Background(), websocket.MessageText, raw)
					_, _, _ = c.Read(context.Background()) // read offer
					_ = c.Close(websocket.StatusNormalClosure, "abort")
				}
			}
			time.Sleep(150 * time.Millisecond)

			for _, cl := range clients {
				if cl != nil {
					cl.tr.Close()
				}
			}
			supCancel()
			hub.closeAll()
			srv.Close()

			t.Logf("Signaling %d real WebRTC clients in %v (%.1f clients/s) | %.1f KB/client | Heap: %d -> %d KB",
				clientCount, elapsed, float64(clientCount)/elapsed.Seconds(), kbPerClient, heapBefore.HeapAllocKB, heapPeak.HeapAllocKB)
		})
	}
	baseG.AssertSettled(t, 8, 8*time.Second)
}

// TestPerf_SignalingServer_ReconnectOnZeroPeers verifies that a real Pion WebRTC peer
// whose active P2P links are all severed (even in fallbackMode) reconnects to /ws and
// re-establishes overlay peers without leaks.
func TestPerf_SignalingServer_ReconnectOnZeroPeers(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	hub := newSignalingHubWithTarget(3)
	supCtx, supCancel := context.WithCancel(context.Background())
	defer supCancel()
	hub.startSupervisor(supCtx, 250*time.Millisecond)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", hub.handleHealth)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer hub.closeAll()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	opts := turnoverPeerOpts{markAnchors: true, reconnectOnDeficit: true, reconnectOnSolicit: true}

	roomKey, _ := cot.GenerateRoomKey()
	roomID := "perf-reconnect-room"
	a1 := newTurnoverPeer(t, "A1", "seed-reconn-A1", roomID, roomKey, wsURL, true, nil, opts)
	if err := a1.connectSignaling(); err != nil {
		t.Fatalf("A1 connect: %v", err)
	}
	invB, _ := a1.node.CreateChannelInvite(15 * time.Minute)
	invC, _ := a1.node.CreateChannelInvite(15 * time.Minute)
	invD, _ := a1.node.CreateChannelInvite(15 * time.Minute)
	b1 := newTurnoverPeer(t, "B1", "seed-reconn-B1", roomID, roomKey, wsURL, false, invB, opts)
	c1 := newTurnoverPeer(t, "C1", "seed-reconn-C1", roomID, roomKey, wsURL, false, invC, opts)
	d1 := newTurnoverPeer(t, "D1", "seed-reconn-D1", roomID, roomKey, wsURL, false, invD, opts)
	_ = b1.connectSignaling()
	_ = c1.connectSignaling()
	_ = d1.connectSignaling()

	waitForAllChannelPeers(t, roomID, []*turnoverPeer{a1, b1, c1, d1}, 2, 15*time.Second)

	// Put D1 in fallbackMode and sever all its peers so it has 0 peers; OnAnchorDeficit must trigger /ws reconnect.
	d1.node.SetFallbackMode(true)
	for _, p := range d1.tr.Peers() {
		d1.tr.ClosePeer(p)
		d1.node.RemovePeer(p)
	}
	waitForCondition(t, 12*time.Second, "D1 reconnected to mesh after zero-peer isolation", func() bool {
		return len(d1.tr.Peers()) >= 2
	})

	a1.leave()
	b1.leave()
	c1.leave()
	d1.leave()
	supCancel()
	hub.closeAll()
	srv.Close()
	baseG.AssertSettled(t, 12, 4*time.Second)
}
