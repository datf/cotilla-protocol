package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// TestSignaling_WSRejectsUnauthenticatedAndGossipMessages checks that /ws:
// 1. Rejects unsigned / spoofed Peer offers or registrations with an error.
// 2. Does NOT relay Cotilla gossip frames to connected peers.
// 3. Enforces replay window on signaling timestamps.
func TestSignaling_WSRejectsUnauthenticatedAndGossipMessages(t *testing.T) {
	hub := newSignalingHub()
	defer hub.closeAll()
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", hub.handleHealth)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect an authenticated listener peer (Bob) over WebRTC DataChannel via /ws
	bobID, _ := cot.NewIdentity()
	var mu sync.Mutex
	bobReceived := make([]string, 0)
	bobTr := cotillartc.New(bobID.Address(), nil, func(from string, data []byte) {
		mu.Lock()
		bobReceived = append(bobReceived, string(data))
		mu.Unlock()
	})
	defer bobTr.Close()

	_, err := cotillartc.DialSignalingWS(ctx, wsURL, bobID, bobTr, nil)
	if err != nil {
		t.Fatalf("dial bob ws failed: %v", err)
	}

	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws failed: %v", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	// 1. Send unauthenticated message spoofing an arbitrary victim peer identity
	victimID, _ := cot.NewIdentity()
	spoofedMsg := wsSignalingMessage{
		Type: "register",
		Peer: victimID.Address(),
	}
	raw, _ := json.Marshal(spoofedMsg)
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatalf("ws write failed: %v", err)
	}

	readCtx, readCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, respBytes, err := conn.Read(readCtx)
	readCancel()
	if err != nil {
		t.Fatalf("VULNERABILITY: signaling /ws did not reject unauthenticated spoofed message cleanly: %v", err)
	}
	var resp wsSignalingMessage
	if err := json.Unmarshal(respBytes, &resp); err != nil || resp.Type != "error" {
		t.Fatalf("expected error response for unauthenticated /ws request, got: %s", string(respBytes))
	}

	// 2. Gossip frame sent over /ws must be rejected
	conn2, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws failed: %v", err)
	}
	defer conn2.Close(websocket.StatusNormalClosure, "")

	gossipBytes, _ := json.Marshal(map[string]any{
		"type":          "wire_gossip",
		"channel_query": map[string]any{"query_id": "q1", "channel_id": "room-1"},
	})
	_ = conn2.Write(ctx, websocket.MessageText, gossipBytes)
	gossipCtx, gossipCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, gRespBytes, gErr := conn2.Read(gossipCtx)
	gossipCancel()
	if gErr != nil {
		t.Fatalf("expected error reply for gossip over /ws, got err: %v", gErr)
	}
	var gResp wsSignalingMessage
	if err := json.Unmarshal(gRespBytes, &gResp); err != nil || gResp.Type != "error" {
		t.Fatalf("VULNERABILITY: /ws accepted or failed to reject non-negotiation gossip payload: %s", string(gRespBytes))
	}

	// 3. Expired timestamp outside replay window must be rejected
	conn3, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial ws failed: %v", err)
	}
	defer conn3.Close(websocket.StatusNormalClosure, "")

	eveID, _ := cot.NewIdentity()
	expiredTS := time.Now().Add(-10 * time.Minute).UnixMilli()
	expSig := hex.EncodeToString(eveID.Sign(cot.CanonicalSignalingMsg("register", eveID.Address(), "", "", expiredTS)))
	expMsg := wsSignalingMessage{
		Type:      "register",
		Peer:      eveID.Address(),
		Timestamp: expiredTS,
		Signature: expSig,
	}
	expRaw, _ := json.Marshal(expMsg)
	_ = conn3.Write(ctx, websocket.MessageText, expRaw)

	expCtx, expCancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	_, expRespBytes, expErr := conn3.Read(expCtx)
	expCancel()
	if expErr != nil {
		t.Fatalf("expected error for expired timestamp, got: %v", expErr)
	}
	var expResp wsSignalingMessage
	if json.Unmarshal(expRespBytes, &expResp) != nil || expResp.Type != "error" {
		t.Fatalf("expected error for expired timestamp, got: %s", string(expRespBytes))
	}

	// 4. Bob must not receive any leaked gossip from the server
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	msgs := append([]string(nil), bobReceived...)
	mu.Unlock()
	for _, m := range msgs {
		if strings.Contains(m, "wire_gossip") || strings.Contains(m, "channel_query") {
			t.Fatalf("VULNERABILITY: gossip frame leaked to Bob: %s", m)
		}
	}
}
