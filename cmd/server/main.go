// Command server is the Cotilla zero-knowledge WebRTC signaling rendezvous gateway and static asset server.
//
// In accordance with the pure WebRTC signaling isolation architecture:
//   - /ws strictly handles the 1:1 authenticated WebRTC negotiation (register -> offer -> answer)
//     to establish a direct WebRTC DataChannel connection between the newcomer and the server.
//   - Once the WebRTC DataChannel is opened, /ws is immediately closed.
//   - All peer discovery (FramePeerQuery -> FramePeerOffer / FrameRootIntro) and WebRTC overlay peering
//     (FramePeerSignal) happen exclusively through the Cotilla protocol over WebRTC DataChannels.
//   - The server maintains up to targetPool connections as active anchors and never touches Cotilla
//     room gossip, room keys, chat envelopes, or MLS commits.
package main

import (
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/datf/cotilla-protocol/internal/buildinfo"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

const (
	defaultMinAnchors        = 50
	defaultIntroFanout       = 5
	defaultAnchorQueryPeriod = 2 * time.Second
)

type wsSignalingMessage struct {
	Type      string `json:"type"`                // "register" | "offer" | "answer" | "ok" | "error"
	Peer      string `json:"peer"`                // sender Ed25519 public address
	Target    string `json:"target,omitempty"`    // target Ed25519 address (for "offer" / "answer")
	SDP       string `json:"sdp,omitempty"`       // bundled WebRTC SDP offer/answer description
	Timestamp int64  `json:"timestamp,omitempty"` // unix ms for replay protection
	Signature string `json:"signature,omitempty"` // Ed25519 hex signature over CanonicalSignalingMsg
	Error     string `json:"error,omitempty"`     // error description
}

func writeWS(ctx context.Context, conn *websocket.Conn, msg wsSignalingMessage) error {
	if conn == nil {
		return nil
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return conn.Write(wctx, websocket.MessageText, raw)
}

type signalingHub struct {
	mu             sync.Mutex
	id             *cot.Identity
	selfAddr       string
	node           *cot.Node
	transport      *cotillartc.PionTransport
	anchorPool     map[string]bool // Active anchor peers connected over WebRTC DataChannel
	targetPool     int             // Minimum target anchor pool size (default: 50 in production)
	introFanout    int             // Max anchors introduced per newcomer (default: 5)
	queryCooldown  time.Duration   // Minimum interval between anchor solicitations
	lastQueryAt    time.Time
	lastRegisterTS map[string]int64
	replayWindow   time.Duration // default: 5 minutes
}

func newSignalingHub() *signalingHub {
	return newSignalingHubWithTarget(defaultMinAnchors)
}

func newSignalingHubWithTarget(targetPool int) *signalingHub {
	return newSignalingHubWithConfig(targetPool, defaultIntroFanout, nil)
}

func newSignalingHubWithConfig(targetPool, introFanout int, stunURLs []string) *signalingHub {
	if targetPool <= 0 {
		targetPool = defaultMinAnchors
	}
	if introFanout <= 0 {
		introFanout = defaultIntroFanout
	}
	id, err := cot.NewIdentity()
	if err != nil {
		log.Fatalf("failed to generate signaling server identity: %v", err)
	}
	selfAddr := id.Address()

	hub := &signalingHub{
		id:             id,
		selfAddr:       selfAddr,
		anchorPool:     make(map[string]bool),
		targetPool:     targetPool,
		introFanout:    introFanout,
		queryCooldown:  defaultAnchorQueryPeriod,
		lastRegisterTS: make(map[string]int64),
		replayWindow:   cot.DefaultConfig().ReplayWindow,
	}

	tr := cotillartc.New(selfAddr, stunURLs, func(from string, data []byte) {
		if hub.node != nil {
			hub.node.HandleWire(from, data)
		}
	})
	cfg := cot.DefaultConfig()
	cfg.MaxPeers = targetPool
	cfg.GossipFanout = introFanout
	hub.node = cot.NewNode(id, "", cot.RoomKey{}, cfg, tr, cot.Hooks{})

	tr.OnOpen(func(peerAddr string) {
		hub.handlePeerOpen(peerAddr)
	})
	tr.OnClose(func(peerAddr string) {
		hub.handlePeerClose(peerAddr)
	})
	hub.transport = tr

	return hub
}

func (h *signalingHub) verifyMessage(msg *wsSignalingMessage) error {
	if msg == nil {
		return errors.New("empty signaling message")
	}
	if msg.Type != "register" && msg.Type != "offer" && msg.Type != "answer" {
		return errors.New("unsupported signaling message type; only register, offer, and answer allowed on /ws")
	}
	if msg.Peer == "" || msg.Signature == "" {
		return errors.New("missing peer address or signature")
	}
	now := time.Now().UnixMilli()
	diff := now - msg.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > h.replayWindow.Milliseconds() {
		return errors.New("signaling message timestamp outside replay window")
	}
	canonical := cot.CanonicalSignalingMsg(msg.Type, msg.Peer, msg.Target, msg.SDP, msg.Timestamp)
	if !cot.Verify(msg.Peer, canonical, msg.Signature) {
		return errors.New("invalid Ed25519 signature on signaling message")
	}
	if (msg.Type == "offer" || msg.Type == "answer") && (msg.Target == "" || msg.SDP == "") {
		return errors.New("missing target or sdp on offer/answer")
	}
	return nil
}

func (h *signalingHub) selectAnchorCandidatesLocked(max int, exclude string) []string {
	addrs := make([]string, 0, len(h.anchorPool))
	for a := range h.anchorPool {
		if a != exclude {
			addrs = append(addrs, a)
		}
	}
	mrand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	if max > 0 && len(addrs) > max {
		addrs = addrs[:max]
	}
	return addrs
}

func (h *signalingHub) handlePeerOpen(peerAddr string) {
	h.node.AddPeer(peerAddr)

	h.mu.Lock()
	isAnchor := false
	if len(h.anchorPool) < h.targetPool {
		h.anchorPool[peerAddr] = true
		isAnchor = true
		log.Printf("[signaling] retained peer %s in anchor pool (active pool size: %d/%d)", short(peerAddr), len(h.anchorPool), h.targetPool)
	}
	anchors := h.selectAnchorCandidatesLocked(h.introFanout, peerAddr)
	h.mu.Unlock()

	descs := make([]cot.PeerDescriptor, 0, len(anchors))
	for _, a := range anchors {
		descs = append(descs, cot.PeerDescriptor{SignPub: a, EncPub: h.node.Overlay().EncKey(a)})
	}
	intro := cot.RootIntroFrame{
		AnchorPeers: anchors,
		Anchors:     descs,
		Fallback:    len(anchors) == 0,
		IsAnchor:    isAnchor,
	}
	if pkt, err := cot.NewPlainPacket(h.id, peerAddr, cot.PortRootIntro, 1, intro); err == nil {
		if data, err := cot.MarshalPacket(pkt); err == nil {
			_ = h.transport.Send(peerAddr, data)
		}
	}
}

func (h *signalingHub) handlePeerClose(peerAddr string) {
	// Signaling server never dials disconnected clients back from passive view; clients reconnect via /ws.
	h.node.Overlay().RemoveActive(peerAddr, false)

	h.mu.Lock()
	wasAnchor := h.anchorPool[peerAddr]
	delete(h.anchorPool, peerAddr)
	if wasAnchor {
		log.Printf("[signaling] Anchor Node %s disconnected (remaining anchors: %d/%d)", short(peerAddr), len(h.anchorPool), h.targetPool)
		peers := h.transport.Peers()
		for _, p := range peers {
			if len(h.anchorPool) >= h.targetPool {
				break
			}
			if !h.anchorPool[p] && p != peerAddr && p != h.selfAddr {
				h.anchorPool[p] = true
				log.Printf("[signaling] promoted connected peer %s to anchor pool (active pool size: %d/%d)", short(p), len(h.anchorPool), h.targetPool)
			}
		}
	}
	needReplenish := len(h.anchorPool) < h.targetPool
	h.mu.Unlock()

	if needReplenish {
		go h.solicitAnchorsOverDataChannel()
	}
}

func (h *signalingHub) solicitAnchorsOverDataChannel() {
	h.mu.Lock()
	needed := h.targetPool - len(h.anchorPool)
	if needed <= 0 {
		h.mu.Unlock()
		return
	}
	if !h.lastQueryAt.IsZero() && time.Since(h.lastQueryAt) < h.queryCooldown {
		h.mu.Unlock()
		return
	}
	h.lastQueryAt = time.Now()
	allAnchors := make([]string, 0, len(h.anchorPool))
	for a := range h.anchorPool {
		allAnchors = append(allAnchors, a)
	}
	h.mu.Unlock()

	h.node.SolicitAnchors(needed, allAnchors)
}

func (h *signalingHub) startSupervisor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = defaultAnchorQueryPeriod
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.mu.Lock()
				h.pruneLastRegisterTSLocked()
				h.mu.Unlock()
				h.solicitAnchorsOverDataChannel()
			}
		}
	}()
}

func (h *signalingHub) pruneLastRegisterTSLocked() {
	cutoff := time.Now().Add(-h.replayWindow).UnixMilli()
	for peer, ts := range h.lastRegisterTS {
		if ts < cutoff {
			delete(h.lastRegisterTS, peer)
		}
	}
}

func (h *signalingHub) closeAll() {
	if h.node != nil {
		h.node.StopMeshSupervisor()
	}
	if h.transport != nil {
		h.transport.Close()
	}
}

func (h *signalingHub) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(1 << 20)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	defer conn.Close(websocket.StatusNormalClosure, "")

	// 1. Read register from client
	_, data, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var regMsg wsSignalingMessage
	if err := json.Unmarshal(data, &regMsg); err != nil || regMsg.Type != "register" {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: "expected register message"})
		return
	}
	if err := h.verifyMessage(&regMsg); err != nil {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: err.Error()})
		return
	}
	clientAddr := regMsg.Peer

	h.mu.Lock()
	if len(h.lastRegisterTS) >= 4096 {
		h.pruneLastRegisterTSLocked()
	}
	prevTS := h.lastRegisterTS[clientAddr]
	if prevTS > 0 && regMsg.Timestamp <= prevTS {
		h.mu.Unlock()
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: "replay detected on register"})
		return
	}
	h.lastRegisterTS[clientAddr] = regMsg.Timestamp
	h.mu.Unlock()

	handshakeOK := false
	defer func() {
		if !handshakeOK {
			h.transport.ClosePeer(clientAddr)
		}
	}()

	// If client already has an active or pending connection (e.g. rapid page refresh or reconnect),
	// close the stale peer connection first so CreateOffer succeeds immediately.
	if h.transport.HasActiveOrPending(clientAddr) {
		h.transport.ClosePeer(clientAddr)
	}

	// 2. Server creates WebRTC offer for client
	offerSDP, err := h.transport.CreateOffer(clientAddr)
	if err != nil {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: fmt.Sprintf("create offer: %v", err)})
		return
	}
	now := time.Now().UnixMilli()
	canonical := cot.CanonicalSignalingMsg("offer", h.selfAddr, clientAddr, offerSDP, now)
	sig := hex.EncodeToString(h.id.Sign(canonical))
	offerMsg := wsSignalingMessage{
		Type:      "offer",
		Peer:      h.selfAddr,
		Target:    clientAddr,
		SDP:       offerSDP,
		Timestamp: now,
		Signature: sig,
	}
	if err := writeWS(ctx, conn, offerMsg); err != nil {
		return
	}

	// 3. Read answer from client
	_, ansData, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var ansMsg wsSignalingMessage
	if err := json.Unmarshal(ansData, &ansMsg); err != nil || ansMsg.Type != "answer" {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: "expected answer message"})
		return
	}
	if ansMsg.Peer != clientAddr || ansMsg.Target != h.selfAddr {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: "peer or target mismatch on answer"})
		return
	}
	if err := h.verifyMessage(&ansMsg); err != nil {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: err.Error()})
		return
	}

	// 4. Server accepts answer from client
	if err := h.transport.AcceptAnswer(clientAddr, ansMsg.SDP); err != nil {
		_ = writeWS(ctx, conn, wsSignalingMessage{Type: "error", Peer: h.selfAddr, Error: fmt.Sprintf("accept answer: %v", err)})
		return
	}

	// 5. Send ok and complete WebSocket handshake. WebRTC DataChannel handles everything from here!
	handshakeOK = true
	_ = writeWS(ctx, conn, wsSignalingMessage{Type: "ok", Peer: h.selfAddr})
	_ = conn.Close(websocket.StatusNormalClosure, "handshake complete")
}

func (h *signalingHub) handleHealth(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	anchors := make([]string, 0, len(h.anchorPool))
	for a := range h.anchorPool {
		anchors = append(anchors, a)
	}
	sort.Strings(anchors)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         "ok",
		"self":           h.selfAddr,
		"anchors":        anchors,
		"anchors_count":  len(anchors),
		"target_anchors": h.targetPool,
		"fallback":       len(h.anchorPool) == 0,
	})
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func envIntOrDefault(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gzWriter *gzip.Writer
}

func (w *gzipResponseWriter) WriteHeader(statusCode int) {
	w.Header().Del("Content-Length")
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.Header().Del("Content-Length")
	return w.gzWriter.Write(b)
}

func withWasmMime(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".wasm") {
			w.Header().Set("Content-Type", "application/wasm")
			if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Add("Vary", "Accept-Encoding")
				gz := gzip.NewWriter(w)
				defer gz.Close()
				gzw := &gzipResponseWriter{ResponseWriter: w, gzWriter: gz}
				next.ServeHTTP(gzw, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func runServer(ctx context.Context, addr string, webDir string, minAnchors, introAnchors int, stunURLs []string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return runServerWithListenerAndSTUN(ctx, ln, webDir, minAnchors, introAnchors, stunURLs)
}

func runServerWithListener(ctx context.Context, ln net.Listener, webDir string, minAnchors, introAnchors int) error {
	return runServerWithListenerAndSTUN(ctx, ln, webDir, minAnchors, introAnchors, nil)
}

func runServerWithListenerAndSTUN(ctx context.Context, ln net.Listener, webDir string, minAnchors, introAnchors int, stunURLs []string) error {
	hub := newSignalingHubWithConfig(minAnchors, introAnchors, stunURLs)
	hub.startSupervisor(ctx, defaultAnchorQueryPeriod)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", hub.handleWS)
	mux.HandleFunc("/health", hub.handleHealth)

	fs := http.FileServer(http.Dir(webDir))
	mux.Handle("/", withWasmMime(fs))

	srv := &http.Server{
		Handler: mux,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
	}

	shutdownDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		log.Println("Shutting down signaling server...")
		hub.closeAll()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	log.Printf("Cotilla zero-knowledge WebRTC signaling gateway running on %s (min-anchors=%d, intro-anchors=%d)", ln.Addr().String(), hub.targetPool, hub.introFanout)
	if _, err := os.Stat(webDir); err != nil {
		log.Printf("warning: web dir %q not found", webDir)
	}

	err := srv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-shutdownDone
	return nil
}

func main() {
	showVersion := flag.Bool("version", false, "print build version and exit")
	addr := flag.String("addr", ":8080", "listen address")
	webDir := flag.String("web", "dist/web", "directory of static client assets")
	defaultSTUN := "stun:stun.l.google.com:19302"
	if envSTUN, ok := os.LookupEnv("COTILLA_STUN"); ok {
		defaultSTUN = envSTUN
	}
	stunServer := flag.String("stun", defaultSTUN, "optional STUN server hint")
	minAnchors := flag.Int("min-anchors", envIntOrDefault("COTILLA_MIN_ANCHORS", defaultMinAnchors), "minimum number of root/anchor nodes retained by server")
	introAnchors := flag.Int("intro-anchors", envIntOrDefault("COTILLA_INTRO_ANCHORS", defaultIntroFanout), "maximum number of anchors introduced per newcomer")
	pprofAddr := flag.String("pprof", "", "optional pprof HTTP listen address (e.g. 127.0.0.1:6060)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cotilla-server %s\n", buildinfo.String())
		return
	}

	if *pprofAddr != "" {
		go startPprofServer(*pprofAddr)
	}

	var stunURLs []string
	if *stunServer != "" {
		stunURLs = []string{*stunServer}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := runServer(ctx, *addr, *webDir, *minAnchors, *introAnchors, stunURLs); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func startPprofServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	log.Printf("[pprof] listening on %s (/debug/pprof/goroutineleak, /debug/pprof/heap)", addr)
	if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("[pprof] error: %v", err)
	}
}
