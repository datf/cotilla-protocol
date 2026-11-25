package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/datf/cotilla-protocol/internal/perfcheck"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// TestPerf_NodeDaemon_PeerExhaustionReconnectAndLeaks verifies that a NodeDaemon whose
// active WebRTC peers are all closed automatically reconnects to signaling via /ws,
// rejoins the mesh without forming an island, and shuts down with 0 goroutine leaks.
func TestPerf_NodeDaemon_PeerExhaustionReconnectAndLeaks(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	hubID, _ := cot.NewIdentity()
	var hubTr *rtc.PionTransport
	var hubNode *cot.Node
	hubTr = rtc.New(hubID.Address(), nil, func(from string, data []byte) {
		if hubNode != nil {
			hubNode.HandleWire(from, data)
		}
	})
	hubNode = cot.NewNode(hubID, "", cot.RoomKey{}, cot.DefaultConfig(), hubTr, cot.Hooks{})
	hubTr.OnOpen(func(peer string) {
		hubNode.AddPeer(peer)
		intro := cot.RootIntroFrame{AnchorPeers: hubTr.Peers(), IsAnchor: true}
		if pkt, err := cot.NewPlainPacket(hubID, peer, cot.PortRootIntro, 1, intro); err == nil {
			if raw, err := cot.MarshalPacket(pkt); err == nil {
				_ = hubTr.Send(peer, raw)
			}
		}
	})
	hubTr.OnClose(func(peer string) { hubNode.RemovePeer(peer) })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_, rawReg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var reg struct{ Peer string }
		if json.Unmarshal(rawReg, &reg) != nil || reg.Peer == "" {
			return
		}
		sdp, err := hubTr.CreateOffer(reg.Peer)
		if err != nil {
			return
		}
		ts := time.Now().UnixMilli()
		sig := hex.EncodeToString(hubID.Sign(cot.CanonicalSignalingMsg("offer", hubID.Address(), reg.Peer, sdp, ts)))
		b, _ := json.Marshal(map[string]any{"type": "offer", "peer": hubID.Address(), "target": reg.Peer, "sdp": sdp, "timestamp": ts, "signature": sig})
		if err := conn.Write(ctx, websocket.MessageText, b); err != nil {
			return
		}
		_, rawAns, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var ans struct{ SDP string }
		if json.Unmarshal(rawAns, &ans) != nil || ans.SDP == "" {
			return
		}
		if err := hubTr.AcceptAnswer(reg.Peer, ans.SDP); err != nil {
			return
		}
		okB, _ := json.Marshal(map[string]any{"type": "ok", "peer": hubID.Address()})
		_ = conn.Write(ctx, websocket.MessageText, okB)
	}))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	roomID := "node-perf-reconnect"
	roomKey, _ := cot.GenerateRoomKey()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const count = 4
	daemons := make([]*NodeDaemon, count)
	for i := 0; i < count; i++ {
		id, _ := cot.NewIdentity()
		d := newNodeDaemon(id, wsURL, nil, roomID, roomKey, cot.Hooks{})
		go d.bootstrapLoop(ctx)
		d.node.StartMeshSupervisor(ctx, 500*time.Millisecond)
		daemons[i] = d
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(daemons[3].transport.Peers()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(daemons[3].transport.Peers()) < 2 {
		t.Fatalf("daemon[3] initial peers=%d, want >=2", len(daemons[3].transport.Peers()))
	}

	// Sever all peers on daemon[3] and put it in fallbackMode -> must reconnect via /ws and heal.
	daemons[3].node.SetFallbackMode(true)
	for _, p := range daemons[3].transport.Peers() {
		daemons[3].transport.ClosePeer(p)
		daemons[3].node.RemovePeer(p)
	}

	healDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(healDeadline) {
		if len(daemons[3].transport.Peers()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(daemons[3].transport.Peers()) < 2 {
		t.Fatalf("daemon[3] failed to reconnect after peer exhaustion (peers=%d)", len(daemons[3].transport.Peers()))
	}

	cancel()
	for _, d := range daemons {
		d.node.StopMeshSupervisor()
		d.media.Close()
		d.transport.Close()
	}
	hubNode.StopMeshSupervisor()
	hubTr.Close()
	srv.Close()

	baseG.AssertSettled(t, 12, 8*time.Second)
}
