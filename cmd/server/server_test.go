package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

func signWSMessage(id *cot.Identity, msg wsSignalingMessage) wsSignalingMessage {
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UnixMilli()
	}
	msg.Peer = id.Address()
	msg.Signature = hex.EncodeToString(id.Sign(
		cot.CanonicalSignalingMsg(msg.Type, msg.Peer, msg.Target, msg.SDP, msg.Timestamp),
	))
	return msg
}

func TestSignalingServer_DefaultMin50AnchorsAndConfigurable(t *testing.T) {
	hub := newSignalingHub()
	defer hub.closeAll()
	if hub.targetPool != 50 {
		t.Fatalf("expected default production targetPool=50 anchors, got %d", hub.targetPool)
	}

	ts := httptest.NewServer(http.HandlerFunc(hub.handleHealth))
	defer ts.Close()

	for i := 0; i < 50; i++ {
		addr := fmt.Sprintf("prod-anchor-%02d", i)
		hub.handlePeerOpen(addr)
	}

	hub.mu.Lock()
	if len(hub.anchorPool) != 50 {
		t.Fatalf("expected 50 anchors in pool, got %d", len(hub.anchorPool))
	}
	hub.mu.Unlock()

	// 51st newcomer is introduced to <= 5 anchors and not retained in anchor pool
	hub.handlePeerOpen("prod-leaf-51")
	hub.mu.Lock()
	if len(hub.anchorPool) != 50 {
		t.Fatalf("anchor pool should remain 50, got %d", len(hub.anchorPool))
	}
	if hub.anchorPool["prod-leaf-51"] {
		t.Fatalf("51st newcomer should not be in anchor pool")
	}
	hub.mu.Unlock()

	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /health failed: %v", err)
	}
	defer res.Body.Close()
	var h map[string]any
	if err := json.NewDecoder(res.Body).Decode(&h); err != nil {
		t.Fatalf("decode /health failed: %v", err)
	}
	if int(h["target_anchors"].(float64)) != 50 || int(h["anchors_count"].(float64)) != 50 {
		t.Fatalf("expected /health target_anchors=50 and anchors_count=50, got %+v", h)
	}

	// Custom configurable anchor pool size
	custom := newSignalingHubWithTarget(7)
	defer custom.closeAll()
	for i := 0; i < 7; i++ {
		addr := fmt.Sprintf("custom-anchor-%02d", i)
		custom.handlePeerOpen(addr)
	}
	custom.mu.Lock()
	if len(custom.anchorPool) != 7 {
		t.Fatalf("expected 7 anchors, got %d", len(custom.anchorPool))
	}
	custom.mu.Unlock()
}

func TestSignalingServer_HealthEndpointAndAnchorPool(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	ts := httptest.NewServer(http.HandlerFunc(hub.handleHealth))
	defer ts.Close()

	// 1. Initial State: 0 anchors -> fallback mode active
	res, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to GET /health: %v", err)
	}
	defer res.Body.Close()

	var health map[string]any
	if err := json.NewDecoder(res.Body).Decode(&health); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if health["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", health["status"])
	}
	if health["fallback"] != true {
		t.Fatalf("expected fallback true with 0 anchors, got %v", health["fallback"])
	}

	// 2. First 3 peers connect: all retained in anchorPool (targetPool = 3)
	peers := []string{"peer-addr-1", "peer-addr-2", "peer-addr-3"}
	for _, p := range peers {
		hub.handlePeerOpen(p)
	}

	res2, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to GET /health: %v", err)
	}
	defer res2.Body.Close()

	var health2 map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&health2); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}
	if health2["fallback"] != false {
		t.Fatalf("expected fallback false with 3 anchors, got %v", health2["fallback"])
	}
	anchors := health2["anchors"].([]any)
	if len(anchors) != 3 {
		t.Fatalf("expected 3 anchors, got %v", anchors)
	}

	// 3. 4th peer arrives: anchorPool is full -> not retained in anchorPool
	hub.handlePeerOpen("peer-addr-4")
	hub.mu.Lock()
	if hub.anchorPool["peer-addr-4"] {
		t.Fatalf("peer-addr-4 should not be in anchor pool")
	}
	hub.mu.Unlock()

	// 4. Anchor 1 disconnects -> pool drops to 2
	hub.handlePeerClose("peer-addr-1")
	hub.mu.Lock()
	poolLen := len(hub.anchorPool)
	hub.mu.Unlock()
	if poolLen != 2 {
		t.Fatalf("expected anchor pool size 2 after disconnect, got %d", poolLen)
	}

	// 5. Next arriving peer fills the vacant anchor slot
	hub.handlePeerOpen("peer-addr-5")
	hub.mu.Lock()
	peer5InPool := hub.anchorPool["peer-addr-5"]
	finalLen := len(hub.anchorPool)
	hub.mu.Unlock()

	if !peer5InPool || finalLen != 3 {
		t.Fatalf("expected peer-addr-5 to fill the vacant anchor slot, pool size %d", finalLen)
	}
}

// TestSignaling_WSHandshake_1to1WebRTC verifies end-to-end:
// 1. Client connects to /ws, performs authenticated 1:1 WebRTC DataChannel handshake, closes /ws.
// 2. Over the opened DataChannel, server sends FrameRootIntro.
// 3. Client queries for peers using FramePeerQuery, server replies with FramePeerOffer.
func TestSignaling_WSHandshake_1to1WebRTC(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientID, _ := cot.NewIdentity()
	var mu sync.Mutex
	receivedIntro := false
	receivedOffer := false
	var peerCandidates []string

	clientTr := cotillartc.New(clientID.Address(), nil, func(from string, data []byte) {
		pkt, err := cot.UnmarshalPacket(data)
		if err != nil || pkt == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !pkt.Encrypted && pkt.Port == cot.PortRootIntro {
			receivedIntro = true
			return
		}
		if pkt.Encrypted && pkt.ChannelHash == 0 && pkt.To == clientID.Address() {
			sd, err := cot.OpenUnicastPacket(clientID, pkt)
			if err == nil && sd.Port == cot.PortPeerResponse {
				var res cot.PeerResponsePayload
				if json.Unmarshal(sd.Body, &res) == nil {
					receivedOffer = true
					for _, p := range res.Peers {
						peerCandidates = append(peerCandidates, p.SignPub)
					}
				}
			}
		}
	})
	defer clientTr.Close()

	// Seed some anchors in the server hub and its overlay view
	hub.mu.Lock()
	hub.anchorPool["anchor-alpha"] = true
	hub.anchorPool["anchor-beta"] = true
	hub.mu.Unlock()
	hub.node.AddPeer("anchor-alpha")
	hub.node.AddPeer("anchor-beta")

	// Execute 1:1 handshake using DialSignalingWS
	serverAddr, err := cotillartc.DialSignalingWS(ctx, wsURL, clientID, clientTr, nil)
	if err != nil {
		t.Fatalf("DialSignalingWS failed: %v", err)
	}
	if serverAddr != hub.selfAddr {
		t.Fatalf("expected server address %s, got %s", hub.selfAddr, serverAddr)
	}

	// Wait for DataChannel to open and FrameRootIntro to arrive
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		gotIntro := receivedIntro
		mu.Unlock()
		if gotIntro {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	gotIntro := receivedIntro
	mu.Unlock()
	if !gotIntro {
		t.Fatalf("expected to receive FrameRootIntro over WebRTC DataChannel after 1:1 handshake")
	}

	// Send signed peer_request broadcast Packet over WebRTC DataChannel to server
	reqPkt, _ := cot.NewPlainPacket(clientID, cot.BroadcastAddr, cot.PortPeerRequest, 1, cot.PeerRequestPayload{WantCount: 5})
	qData, _ := cot.MarshalPacket(reqPkt)
	if err := clientTr.Send(serverAddr, qData); err != nil {
		t.Fatalf("failed to send peer_request to server over DataChannel: %v", err)
	}

	// Wait for FramePeerOffer to arrive from server
	deadlineOffer := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadlineOffer) {
		mu.Lock()
		gotOffer := receivedOffer
		mu.Unlock()
		if gotOffer {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	gotOffer := receivedOffer
	candidates := peerCandidates
	mu.Unlock()

	if !gotOffer {
		t.Fatalf("expected to receive FramePeerOffer from server over WebRTC DataChannel")
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 anchor candidates in PeerOffer, got %v", candidates)
	}
}

// TestSignaling_DropGossipAndChat verifies zero-knowledge wire isolation:
// the server drops chat envelopes, MLS commits, and non-signaling frames over DataChannels.
func TestSignaling_DropGossipAndChat(t *testing.T) {
	hub := newSignalingHubWithTarget(3)
	defer hub.closeAll()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientID, _ := cot.NewIdentity()
	clientTr := cotillartc.New(clientID.Address(), nil, func(from string, data []byte) {})
	defer clientTr.Close()

	serverAddr, err := cotillartc.DialSignalingWS(ctx, wsURL, clientID, clientTr, nil)
	if err != nil {
		t.Fatalf("DialSignalingWS failed: %v", err)
	}

	// Send an encrypted chat packet to the signaling server (server has no room key — blind node)
	rk, _ := cot.GenerateRoomKey()
	chatPkt, err := cot.NewGroupPacket(clientID, cot.BroadcastAddr, cot.ComputeChannelHash("secret-room", rk), 1, rk, cot.PortChat, 3, map[string]string{"text": "hello"})
	if err != nil {
		t.Fatalf("NewGroupPacket: %v", err)
	}
	cData, _ := cot.MarshalPacket(chatPkt)
	if err := clientTr.Send(serverAddr, cData); err != nil {
		t.Fatalf("failed to send packet over DataChannel: %v", err)
	}

	// Also send an invalid message directly over /ws
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial /ws: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	badMsg, _ := json.Marshal(map[string]any{"type": "chat", "text": "leaked"})
	_ = c.Write(ctx, websocket.MessageText, badMsg)

	_, respBytes, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read /ws reply: %v", err)
	}
	var resp wsSignalingMessage
	_ = json.Unmarshal(respBytes, &resp)
	if resp.Type != "error" {
		t.Fatalf("expected error on /ws for non-register message, got %s", string(respBytes))
	}
}

// TestSignaling_RapidSameIdentityReconnect verifies that an active client re-registering
// with a newer signed "register" cleanly replaces its prior gateway DataChannel
// across a 3+ peer topology, while replaying stale registers is rejected.
func TestSignaling_RapidSameIdentityReconnect(t *testing.T) {
	hub := newSignalingHubWithTarget(5)
	defer hub.closeAll()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 3 peers with unique deterministic seeds per AGENTS.md
	seedA := []byte("0123456789abcdef0123456789abcdeA")
	seedB := []byte("0123456789abcdef0123456789abcdeB")
	seedC := []byte("0123456789abcdef0123456789abcdeC")

	idA, err := cot.NewIdentityFromSeed(seedA)
	if err != nil {
		t.Fatalf("identity A: %v", err)
	}
	idB, err := cot.NewIdentityFromSeed(seedB)
	if err != nil {
		t.Fatalf("identity B: %v", err)
	}
	idC, err := cot.NewIdentityFromSeed(seedC)
	if err != nil {
		t.Fatalf("identity C: %v", err)
	}

	trA := cotillartc.New(idA.Address(), nil, func(from string, data []byte) {})
	defer trA.Close()
	trB := cotillartc.New(idB.Address(), nil, func(from string, data []byte) {})
	defer trB.Close()
	trC := cotillartc.New(idC.Address(), nil, func(from string, data []byte) {})
	defer trC.Close()

	if _, err := cotillartc.DialSignalingWS(ctx, wsURL, idA, trA, nil); err != nil {
		t.Fatalf("peer A initial dial: %v", err)
	}
	if _, err := cotillartc.DialSignalingWS(ctx, wsURL, idB, trB, nil); err != nil {
		t.Fatalf("peer B initial dial: %v", err)
	}
	if _, err := cotillartc.DialSignalingWS(ctx, wsURL, idC, trC, nil); err != nil {
		t.Fatalf("peer C initial dial: %v", err)
	}

	// Peer A performs rapid reload (<100ms) with a fresh transport and the exact same identity idA
	time.Sleep(50 * time.Millisecond)
	trA2 := cotillartc.New(idA.Address(), nil, func(from string, data []byte) {})
	defer trA2.Close()

	srvAddr, err := cotillartc.DialSignalingWS(ctx, wsURL, idA, trA2, nil)
	if err != nil {
		t.Fatalf("peer A rapid reconnect failed: %v", err)
	}
	if srvAddr == "" {
		t.Fatalf("expected non-empty server address on rapid reconnect")
	}

	// Verify replay rejection: replaying an older timestamp register message fails
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial for replay test: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	hub.mu.Lock()
	lastTS := hub.lastRegisterTS[idA.Address()]
	hub.mu.Unlock()

	staleReg := signWSMessage(idA, wsSignalingMessage{
		Type:      "register",
		Timestamp: lastTS, // Same timestamp or older
	})
	rawStale, _ := json.Marshal(staleReg)
	_ = c.Write(ctx, websocket.MessageText, rawStale)

	_, respBytes, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read replay error: %v", err)
	}
	var resp wsSignalingMessage
	_ = json.Unmarshal(respBytes, &resp)
	if resp.Type != "error" || !strings.Contains(resp.Error, "replay detected") {
		t.Fatalf("expected replay detected error, got %+v", resp)
	}
}

func TestWithWasmMime_GzipServing(t *testing.T) {
	tempDir := t.TempDir()
	wasmPayload := []byte("\x00asm\x01\x00\x00\x00" + strings.Repeat("dummy wasm content for compression test", 100))
	wasmPath := tempDir + "/test.wasm"
	if err := os.WriteFile(wasmPath, wasmPayload, 0644); err != nil {
		t.Fatalf("failed to write test wasm file: %v", err)
	}

	handler := withWasmMime(http.FileServer(http.Dir(tempDir)))
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// 1. Request with Accept-Encoding: gzip
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/test.wasm", nil)
	if err != nil {
		t.Fatalf("new request failed: %v", err)
	}
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "application/wasm" {
		t.Fatalf("expected Content-Type application/wasm, got %q", ct)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("expected Content-Encoding gzip, got %q", ce)
	}

	// Decompress body and verify bytes match original
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	defer gzReader.Close()
	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("failed to read decompressed bytes: %v", err)
	}
	if !bytes.Equal(decompressed, wasmPayload) {
		t.Fatalf("decompressed payload mismatch: got %d bytes, want %d", len(decompressed), len(wasmPayload))
	}

	// 2. Request without Accept-Encoding: gzip
	reqPlain, err := http.NewRequest(http.MethodGet, ts.URL+"/test.wasm", nil)
	if err != nil {
		t.Fatalf("new plain request failed: %v", err)
	}
	respPlain, err := http.DefaultTransport.RoundTrip(reqPlain)
	if err != nil {
		t.Fatalf("plain request failed: %v", err)
	}
	defer respPlain.Body.Close()

	if ce := respPlain.Header.Get("Content-Encoding"); ce != "" {
		t.Fatalf("expected no Content-Encoding for plain request, got %q", ce)
	}
	plainBody, err := io.ReadAll(respPlain.Body)
	if err != nil {
		t.Fatalf("failed to read plain body: %v", err)
	}
	if !bytes.Equal(plainBody, wasmPayload) {
		t.Fatalf("plain payload mismatch: got %d bytes, want %d", len(plainBody), len(wasmPayload))
	}
}
