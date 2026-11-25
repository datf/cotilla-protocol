package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// testSignalingPeer represents an active client peer connecting to the distribution overlay via /ws.
type testSignalingPeer struct {
	id          *cotilla.Identity
	wsURL       string
	transport   *cotillartc.PionTransport
	node        *cotilla.Node
	ctx         context.Context
	cancel      context.CancelFunc
	wsConn      *websocket.Conn
	mu          sync.Mutex
	offered     map[string]bool
	bundleDone  chan struct{}
	bundleBytes []byte
}

func newTestSignalingPeer(t *testing.T, seedHex string, wsURL, distRoomID string, distRoomKey cotilla.RoomKey, pinnedPub string) *testSignalingPeer {
	seedBytes, _ := hex.DecodeString(seedHex)
	id, err := cotilla.NewIdentityFromSeed(seedBytes)
	if err != nil {
		t.Fatalf("NewIdentityFromSeed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	p := &testSignalingPeer{
		id:         id,
		wsURL:      wsURL,
		ctx:        ctx,
		cancel:     cancel,
		offered:    make(map[string]bool),
		bundleDone: make(chan struct{}, 1),
	}

	p.transport = cotillartc.New(id.Address(), nil, func(from string, data []byte) {
		if p.node != nil {
			p.node.HandleWire(from, data)
		}
	})

	cfg := cotilla.DefaultConfig()
	cfg.SyncTimeout = 500 * time.Millisecond
	p.node = cotilla.NewNode(id, distRoomID, distRoomKey, cfg, p.transport, cotilla.Hooks{
		OnAppBundleReady: func(m *cotilla.AppManifest, data []byte) {
			p.mu.Lock()
			if p.bundleBytes == nil {
				p.bundleBytes = append([]byte(nil), data...)
				select {
				case p.bundleDone <- struct{}{}:
				default:
				}
			}
			p.mu.Unlock()
		},
	})

	p.transport.OnOpen(func(peerAddr string) {
		p.node.AddPeer(peerAddr)
		_ = p.node.RequestCatchUp()
		go p.node.BroadcastPeerInfo()
	})
	p.transport.OnClose(func(peerAddr string) {
		p.node.RemovePeer(peerAddr)
	})

	err = p.node.JoinAppDistChannel(distRoomID, distRoomKey, pinnedPub, 1)
	if err != nil {
		t.Fatalf("JoinAppDistChannel: %v", err)
	}

	return p
}

func (p *testSignalingPeer) connectSignaling(t *testing.T) {
	serverAddr, err := cotillartc.DialSignalingWS(p.ctx, p.wsURL, p.id, p.transport, p.node)
	if err != nil {
		t.Fatalf("DialSignalingWS failed: %v", err)
	}
	p.node.AddPeer(serverAddr)
	p.node.QueryPeers()
}

func (p *testSignalingPeer) Close() {
	p.cancel()
	if p.wsConn != nil {
		_ = p.wsConn.Close(websocket.StatusNormalClosure, "done")
	}
	p.node.StopMeshSupervisor()
	p.transport.Close()
}

// TestSeederDaemon_MultiPeerSwarmSeeding exercises the seeder daemon and 3+ client peers over WebRTC:
// 1. SeederDaemon serves the signed app bundle.
// 2. Client 1 and Client 2 connect and download the bundle over WebRTC.
// 3. SeederDaemon is stopped (simulating departure).
// 4. Latecomer Client 3 connects, requests manifest, and downloads the bundle from Client 1 and Client 2 via swarm seeding.
func TestSeederDaemon_MultiPeerSwarmSeeding(t *testing.T) {
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "app.html")
	manifestPath := filepath.Join(tmpDir, "app.manifest.json")

	// Generate 180 KB random payload (3 chunks of 64KB) with HTML header
	bundleBytes := make([]byte, 180*1024)
	if _, err := rand.Read(bundleBytes); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	copy(bundleBytes, []byte("<!DOCTYPE html><html><body><h1>MultiPeer Test App</h1></body></html>"))

	pubHex, privHex, err := cotilla.GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair: %v", err)
	}

	manifest, err := cotilla.SignAppBundle(privHex, "cotilla-chat", "stable", "1.0.0", 1, bundleBytes, "text/html; charset=utf-8", cotilla.FormatSingleHTMLV1, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle: %v", err)
	}

	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatalf("WriteFile bundle: %v", err)
	}
	mJSON, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, mJSON, 0644); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	// Setup local test signaling hub
	sigHub := newTestSignalingHub()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			sigHub.handleWS(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	wsURL := "ws://" + server.Listener.Addr().String() + "/ws"
	distRoomID := "cotilla-app-dist-v1"
	distRoomKey := cotilla.AppDistRoomKeyFor(distRoomID)

	// 1. Start SeederDaemon
	seederCtx, seederCancel := context.WithCancel(context.Background())
	defer seederCancel()

	seeder, err := NewSeederDaemon(SeederOptions{
		SignalingURL: wsURL,
		Seed:         "1111111111111111111111111111111111111111111111111111111111111111",
		BundlePath:   bundlePath,
		ManifestPath: manifestPath,
		DistRoomID:   distRoomID,
		DistRoomKey:  distRoomKey,
	})
	if err != nil {
		t.Fatalf("NewSeederDaemon failed: %v", err)
	}
	seeder.Start(seederCtx)
	defer seeder.Close()

	// 2. Start Client 1 & Client 2
	peer1 := newTestSignalingPeer(t, "2222222222222222222222222222222222222222222222222222222222222222", wsURL, distRoomID, distRoomKey, pubHex)
	defer peer1.Close()
	peer2 := newTestSignalingPeer(t, "3333333333333333333333333333333333333333333333333333333333333333", wsURL, distRoomID, distRoomKey, pubHex)
	defer peer2.Close()

	peer1.connectSignaling(t)
	peer2.connectSignaling(t)

	// Wait for peer1 and peer2 to download the bundle from seeder
	select {
	case <-peer1.bundleDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("peer1 timed out waiting for bundle download from seeder")
	}

	select {
	case <-peer2.bundleDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("peer2 timed out waiting for bundle download from seeder")
	}

	if !bytes.Equal(peer1.bundleBytes, bundleBytes) {
		t.Fatalf("peer1 downloaded bytes mismatch")
	}
	if !bytes.Equal(peer2.bundleBytes, bundleBytes) {
		t.Fatalf("peer2 downloaded bytes mismatch")
	}

	// 3. Stop SeederDaemon (simulating publisher departure)
	seederCancel()
	seeder.Close()
	time.Sleep(200 * time.Millisecond)

	// 4. Latecomer Client 3 joins after seeder departure
	peer3 := newTestSignalingPeer(t, "4444444444444444444444444444444444444444444444444444444444444444", wsURL, distRoomID, distRoomKey, pubHex)
	defer peer3.Close()
	peer3.connectSignaling(t)

	// Trigger manifest query from peer3 to discover swarm seeders
	go func() {
		for i := 0; i < 5; i++ {
			time.Sleep(500 * time.Millisecond)
			peer3.node.RequestAppManifest(distRoomID, "cotilla-chat", "stable", 1)
		}
	}()

	select {
	case <-peer3.bundleDone:
	case <-time.After(12 * time.Second):
		t.Fatalf("latecomer peer3 timed out waiting for swarm bundle download from peer1/peer2")
	}

	if !bytes.Equal(peer3.bundleBytes, bundleBytes) {
		t.Fatalf("peer3 downloaded swarm bundle bytes mismatch")
	}

	// Verify bundle verification on peer3
	if err := cotilla.VerifyAppBundle(manifest, peer3.bundleBytes, pubHex, "cotilla-chat", "stable", 1, time.Now().UnixMilli()); err != nil {
		t.Fatalf("peer3 bundle verification failed: %v", err)
	}
}

// Minimal in-test signaling hub implementation matching cmd/server behavior for testing.
type testHub struct {
	id         *cotilla.Identity
	tr         *cotillartc.PionTransport
	mu         sync.Mutex
	anchorPool map[string]bool
}

func newTestSignalingHub() *testHub {
	id, _ := cotilla.NewIdentity()
	h := &testHub{
		id:         id,
		anchorPool: make(map[string]bool),
	}
	var hubNode *cotilla.Node
	h.tr = cotillartc.New(id.Address(), nil, func(from string, data []byte) {
		if hubNode != nil {
			hubNode.HandleWire(from, data)
		}
	})
	hubNode = cotilla.NewNode(id, "", cotilla.RoomKey{}, cotilla.DefaultConfig(), h.tr, cotilla.Hooks{})
	h.tr.OnOpen(func(peer string) {
		hubNode.AddPeer(peer)
		h.mu.Lock()
		var anchors []string
		for a := range h.anchorPool {
			if a != peer {
				anchors = append(anchors, a)
			}
		}
		isAnchor := len(h.anchorPool) < 3
		h.anchorPool[peer] = true
		h.mu.Unlock()
		intro := cotilla.RootIntroFrame{AnchorPeers: anchors, IsAnchor: isAnchor}
		if pkt, err := cotilla.NewPlainPacket(id, peer, cotilla.PortRootIntro, 1, intro); err == nil {
			if raw, err := cotilla.MarshalPacket(pkt); err == nil {
				_ = h.tr.Send(peer, raw)
			}
		}
	})
	h.tr.OnClose(func(peer string) {
		hubNode.RemovePeer(peer)
		h.mu.Lock()
		delete(h.anchorPool, peer)
		h.mu.Unlock()
	})
	return h
}

func (h *testHub) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// 1. Read register
	_, rawReg, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var regMsg struct {
		Type      string `json:"type"`
		Peer      string `json:"peer"`
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rawReg, &regMsg); err != nil || regMsg.Type != "register" {
		return
	}
	canonicalReg := cotilla.CanonicalSignalingMsg("register", regMsg.Peer, "", "", regMsg.Timestamp)
	if !cotilla.Verify(regMsg.Peer, canonicalReg, regMsg.Signature) {
		return
	}

	clientAddr := regMsg.Peer

	// 2. Create offer to client
	offerSDP, err := h.tr.CreateOffer(clientAddr)
	if err != nil {
		return
	}
	offerNow := time.Now().UnixMilli()
	offerSig := hex.EncodeToString(h.id.Sign(cotilla.CanonicalSignalingMsg("offer", h.id.Address(), clientAddr, offerSDP, offerNow)))
	offerMsg := map[string]any{
		"type":      "offer",
		"peer":      h.id.Address(),
		"target":    clientAddr,
		"sdp":       offerSDP,
		"timestamp": offerNow,
		"signature": offerSig,
	}
	rawOffer, _ := json.Marshal(offerMsg)
	if err := conn.Write(ctx, websocket.MessageText, rawOffer); err != nil {
		return
	}

	// 3. Read answer
	_, rawAns, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var ansMsg struct {
		Type      string `json:"type"`
		Peer      string `json:"peer"`
		Target    string `json:"target"`
		SDP       string `json:"sdp"`
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(rawAns, &ansMsg); err != nil || ansMsg.Type != "answer" {
		return
	}
	canonicalAns := cotilla.CanonicalSignalingMsg("answer", ansMsg.Peer, ansMsg.Target, ansMsg.SDP, ansMsg.Timestamp)
	if !cotilla.Verify(ansMsg.Peer, canonicalAns, ansMsg.Signature) {
		return
	}

	if err := h.tr.AcceptAnswer(clientAddr, ansMsg.SDP); err != nil {
		return
	}

	// 4. Send ok
	okMsg := map[string]string{"type": "ok"}
	rawOk, _ := json.Marshal(okMsg)
	_ = conn.Write(ctx, websocket.MessageText, rawOk)
}

// TestSeederDaemon_SvelteBundleDistribution exercises seeding the real compiled Svelte single-file
// application bundle (dist/cotilla-svelte.html) over WebRTC to 3+ client peers.
func TestSeederDaemon_SvelteBundleDistribution(t *testing.T) {
	bundlePath := filepath.Join("..", "..", "dist", "cotilla-svelte.html")
	manifestPath := filepath.Join("..", "..", "dist", "cotilla-svelte.manifest.json")

	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Skipf("dist/cotilla-svelte.html not present (run make svelte-bundle): %v", err)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read dist/cotilla-svelte.manifest.json: %v", err)
	}

	var manifest cotilla.AppManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}

	if manifest.AppID != "cotilla-svelte" {
		t.Fatalf("expected app_id cotilla-svelte, got %s", manifest.AppID)
	}
	if manifest.Format != cotilla.FormatSingleHTMLV1 {
		t.Fatalf("expected format %s, got %s", cotilla.FormatSingleHTMLV1, manifest.Format)
	}

	// Verify the Svelte bundle properties
	if !bytes.Contains(bundleBytes, []byte(`id="app"`)) {
		t.Fatalf("svelte bundle must contain #app mount container")
	}
	if bytes.Contains(bundleBytes, []byte("_app/immutable")) {
		t.Fatalf("svelte singlefile bundle must not reference multi-file _app/immutable chunks")
	}

	// Setup local test signaling hub
	sigHub := newTestSignalingHub()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			sigHub.handleWS(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	wsURL := "ws://" + server.Listener.Addr().String() + "/ws"
	distRoomID := "cotilla-app-dist-v1"
	distRoomKey := cotilla.AppDistRoomKeyFor(distRoomID)

	seederCtx, seederCancel := context.WithCancel(context.Background())
	defer seederCancel()

	seeder, err := NewSeederDaemon(SeederOptions{
		SignalingURL: wsURL,
		Seed:         "4444444444444444444444444444444444444444444444444444444444444444",
		BundlePath:   bundlePath,
		ManifestPath: manifestPath,
		DistRoomID:   distRoomID,
		DistRoomKey:  distRoomKey,
	})
	if err != nil {
		t.Fatalf("NewSeederDaemon failed: %v", err)
	}
	seeder.Start(seederCtx)
	defer seeder.Close()

	// Invariant: 3+ peers
	peer1 := newTestSignalingPeer(t, "5555555555555555555555555555555555555555555555555555555555555555", wsURL, distRoomID, distRoomKey, manifest.PubKey)
	defer peer1.Close()
	peer2 := newTestSignalingPeer(t, "6666666666666666666666666666666666666666666666666666666666666666", wsURL, distRoomID, distRoomKey, manifest.PubKey)
	defer peer2.Close()
	peer3 := newTestSignalingPeer(t, "7777777777777777777777777777777777777777777777777777777777777777", wsURL, distRoomID, distRoomKey, manifest.PubKey)
	defer peer3.Close()

	peer1.connectSignaling(t)
	peer2.connectSignaling(t)
	peer3.connectSignaling(t)

	// All 3 peers must download and verify the Svelte bundle from the seeder
	peers := []*testSignalingPeer{peer1, peer2, peer3}
	for i, p := range peers {
		select {
		case <-p.bundleDone:
			if !bytes.Equal(p.bundleBytes, bundleBytes) {
				t.Fatalf("peer %d downloaded bundle mismatch with source", i+1)
			}
		case <-time.After(15 * time.Second):
			t.Fatalf("peer %d timed out downloading svelte bundle from seeder", i+1)
		}
	}
}
