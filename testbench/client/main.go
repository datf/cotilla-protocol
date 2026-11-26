package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
	"github.com/pion/webrtc/v4"
)

type ReceivedMessage struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

type ReceivedAttachment struct {
	FileID   string `json:"file_id"`
	Name     string `json:"name"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Verified bool   `json:"verified"`
}

type ReceivedInvite struct {
	InviteID  string `json:"invite_id"`
	From      string `json:"from"`
	RoomID    string `json:"room_id"`
	RoomKey   string `json:"room_key"`
	Title     string `json:"title,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

type ReceivedCallFrame struct {
	ScopeID    string `json:"scope_id"`
	From       string `json:"from"`
	MediaKind  string `json:"media_kind"`
	KID        uint64 `json:"kid"`
	PayloadB64 string `json:"payload_b64"`
	Size       int    `json:"size"`
	Timestamp  int64  `json:"timestamp"`
}

type signalPayload struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type filterTransport struct {
	base    *rtc.PionTransport
	mu      sync.RWMutex
	blocked map[string]bool
}

func (t *filterTransport) Block(peer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.blocked[peer] = true
}

func (t *filterTransport) Unblock(peer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.blocked, peer)
}

func (t *filterTransport) Send(addr string, data []byte) error {
	t.mu.RLock()
	isBlocked := t.blocked[addr]
	t.mu.RUnlock()
	if isBlocked {
		return fmt.Errorf("transport: direct connection to %s is blocked (simulated firewall)", addr)
	}
	return t.base.Send(addr, data)
}

func (t *filterTransport) Broadcast(data []byte) {
	for _, p := range t.Peers() {
		_ = t.Send(p, data)
	}
}

func (t *filterTransport) Peers() []string {
	all := t.base.Peers()
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []string
	for _, p := range all {
		if !t.blocked[p] {
			out = append(out, p)
		}
	}
	return out
}

func (t *filterTransport) ClosePeer(addr string) {
	if t.base != nil {
		t.base.ClosePeer(addr)
	}
}

func (t *filterTransport) CreateOffer(peerAddr string) (string, error) {
	if t.base != nil {
		return t.base.CreateOffer(peerAddr)
	}
	return "", fmt.Errorf("no base transport")
}

func (t *filterTransport) AcceptOffer(peerAddr, offerSDP string) (string, error) {
	if t.base != nil {
		return t.base.AcceptOffer(peerAddr, offerSDP)
	}
	return "", fmt.Errorf("no base transport")
}

func (t *filterTransport) AcceptAnswer(peerAddr, answerSDP string) error {
	if t.base != nil {
		return t.base.AcceptAnswer(peerAddr, answerSDP)
	}
	return fmt.Errorf("no base transport")
}

type dmRelayTransport struct {
	app  *ClientApp
	base *filterTransport
}

func (t *dmRelayTransport) ClosePeer(addr string) {
	if t.base != nil {
		t.base.ClosePeer(addr)
	}
}

func (t *dmRelayTransport) Send(addr string, data []byte) error {
	// Try direct DM transport first
	if err := t.base.Send(addr, data); err == nil {
		return nil
	}
	// Fallback to relaying through main channel peer network
	if t.app.node != nil {
		return t.app.node.SendViaRelay(addr, "dm", data)
	}
	return fmt.Errorf("dm transport: failed to send to %s", addr)
}

func (t *dmRelayTransport) Broadcast(data []byte) {
	t.app.mu.RLock()
	peer := t.app.dmPeer
	t.app.mu.RUnlock()
	if peer != "" {
		_ = t.Send(peer, data)
	}
}

func (t *dmRelayTransport) Peers() []string {
	t.app.mu.RLock()
	peer := t.app.dmPeer
	t.app.mu.RUnlock()
	if peer != "" {
		return []string{peer}
	}
	return nil
}

type ClientApp struct {
	name         string
	apiAddr      string
	signalingURL string
	roomID       string
	roomKey      cot.RoomKey

	id        *cot.Identity
	node      *cot.Node
	pion      *rtc.PionTransport
	transport *filterTransport

	mu               sync.RWMutex
	wsConnectMu      sync.Mutex
	gatewayAddr      string
	supervisorCancel context.CancelFunc
	disconnected     bool
	lastSolicit      time.Time
	messages     []ReceivedMessage
	offers       []cot.AttachmentMeta
	attachments  []ReceivedAttachment
	autoDownload bool

	// Secondary WebRTC A/V call media transport & direct invites
	media             *rtc.CallMediaTransport
	channelCallFrames []ReceivedCallFrame
	receivedInvites   []ReceivedInvite
	rawInvites        map[string]*cot.DirectInvite

	// Secondary 1:1 DM session
	dmPeer       string
	dmRoomID     string
	dmRoomKey    cot.RoomKey
	dmNode       *cot.Node
	dmPion       *rtc.PionTransport
	dmTransport  *filterTransport
	dmMessages   []ReceivedMessage
	dmCallFrames []ReceivedCallFrame
}

func newClientApp(name, apiAddr, signalingURL, roomID, keyStr string) (*ClientApp, error) {
	key, err := cot.ParseRoomKey(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid room key: %w", err)
	}

	id, err := cot.NewIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	app := &ClientApp{
		name:         name,
		apiAddr:      apiAddr,
		signalingURL: signalingURL,
		roomID:       roomID,
		roomKey:      key,
		id:           id,
		autoDownload: true,
		rawInvites:   make(map[string]*cot.DirectInvite),
	}

	app.initNode()
	return app, nil
}

func (a *ClientApp) initNode() {
	a.mu.Lock()
	oldNode := a.node
	oldMedia := a.media
	oldSupCancel := a.supervisorCancel
	a.supervisorCancel = nil
	a.media = nil
	a.mu.Unlock()
	if oldSupCancel != nil {
		oldSupCancel()
	}
	if oldMedia != nil {
		oldMedia.Close()
	}
	if oldNode != nil {
		oldNode.StopMeshSupervisor()
	}

	pion := rtc.New(a.id.Address(), nil, func(from string, data []byte) {
		a.mu.RLock()
		node := a.node
		a.mu.RUnlock()
		if node != nil {
			node.HandleWire(from, data)
		}
	})
	a.pion = pion

	tr := &filterTransport{
		base:    pion,
		blocked: make(map[string]bool),
	}
	a.transport = tr

	var node *cot.Node
	media := rtc.NewCallMediaTransport(a.id.Address(), nil, func(scopeID, target, kind, payload string) error {
		a.mu.RLock()
		curNode := node
		a.mu.RUnlock()
		if curNode == nil {
			return fmt.Errorf("node not initialized")
		}
		return curNode.SendCallSignal(scopeID, target, kind, payload)
	})
	media.OnError(func(scopeID, peerAddr, op string, err error) {
		log.Printf("[%s] secondary call error scope=%s peer=%s op=%s: %v", a.name, shortID(scopeID), shortID(peerAddr), op, err)
	})
	media.OnPeerState(func(scopeID, peerAddr string, st webrtc.PeerConnectionState) {
		if st == webrtc.PeerConnectionStateConnected || st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateDisconnected || st == webrtc.PeerConnectionStateClosed {
			log.Printf("[%s] secondary call state scope=%s peer=%s state=%s", a.name, shortID(scopeID), shortID(peerAddr), st.String())
		}
	})
	media.OnMediaFrame(func(scopeID, fromPeer, mediaKind string, kid uint64, plaintext []byte) {
		rec := ReceivedCallFrame{
			ScopeID:    scopeID,
			From:       fromPeer,
			MediaKind:  mediaKind,
			KID:        kid,
			PayloadB64: base64.StdEncoding.EncodeToString(plaintext),
			Size:       len(plaintext),
			Timestamp:  time.Now().UnixMilli(),
		}
		a.mu.Lock()
		isDM := scopeID != "" && scopeID == a.dmRoomID
		if isDM {
			a.dmCallFrames = append(a.dmCallFrames, rec)
		} else {
			a.channelCallFrames = append(a.channelCallFrames, rec)
		}
		a.mu.Unlock()
		log.Printf("[%s] received SFrame %s frame in scope %s from %s (%d bytes)", a.name, mediaKind, scopeID[:min(8, len(scopeID))], fromPeer[:min(8, len(fromPeer))], len(plaintext))
	})

	pion.OnOpen(func(addr string) {
		log.Printf("[%s] direct WebRTC DataChannel opened with %s", a.name, addr[:8])
		if node != nil {
			node.AddPeer(addr)
			if node.IsGatewayPeer(addr) {
				go node.QueryPeers()
				return
			}
			_ = node.RequestCatchUp()
			_ = node.JoinChannel(a.roomID)
			go node.BroadcastPeerInfo()
		}
	})

	pion.OnClose(func(addr string) {
		log.Printf("[%s] direct WebRTC DataChannel closed with %s", a.name, addr[:8])
		if node != nil {
			node.RemovePeer(addr)
		}
	})

	cfg := cot.DefaultConfig()

	hooks := cot.Hooks{
		OnChannelDiscovered: func(channelID string, peer string) {
			log.Printf("[%s] discovered channel peer %s in %s", a.name, peer[:8], channelID)
		},
		OnAnchorDeficit: func(currentAnchors, activePeers int) {
			a.mu.RLock()
			skip := a.disconnected || a.node != node
			gwAddr := a.gatewayAddr
			pion := a.pion
			a.mu.RUnlock()
			if skip {
				return
			}
			if gwAddr != "" && pion != nil && pion.HasActiveOrPending(gwAddr) {
				go node.QueryPeers()
				return
			}
			log.Printf("[%s] anchor deficit detected (anchors: %d, active: %d); reconnecting to signaling", a.name, currentAnchors, activePeers)
			go func() { _ = a.connectSignaling() }()
		},
		OnAnchorSolicit: func(needed int) {
			a.mu.Lock()
			skip := a.disconnected || a.node != node || time.Since(a.lastSolicit) < 1500*time.Millisecond
			gwAddr := a.gatewayAddr
			pion := a.pion
			if !skip {
				a.lastSolicit = time.Now()
			}
			a.mu.Unlock()
			if skip {
				return
			}
			if gwAddr != "" && pion != nil && pion.HasActiveOrPending(gwAddr) {
				go node.QueryPeers()
				return
			}
			log.Printf("[%s] received anchor solicit (needed: %d); reconnecting to signaling", a.name, needed)
			go func() { _ = a.connectSignaling() }()
		},
		OnAnchorIntro: func(anchors []string, fallback bool) {
			log.Printf("[%s] received anchor intro (%d anchors, fallback=%v)", a.name, len(anchors), fallback)
		},
		OnMessage: func(env *cot.Envelope, plaintext []byte) {
			var chat cot.ChatPayload
			_ = json.Unmarshal(plaintext, &chat)
			a.mu.Lock()
			a.messages = append(a.messages, ReceivedMessage{
				Author:    env.AuthorPubKey,
				Text:      chat.Text,
				Timestamp: env.Timestamp,
			})
			a.mu.Unlock()
			log.Printf("[%s] received message from %s: %s", a.name, env.AuthorPubKey[:8], chat.Text)
		},
		OnAttachmentOffer: func(meta *cot.AttachmentMeta) {
			a.mu.Lock()
			a.offers = append(a.offers, *meta)
			auto := a.autoDownload
			a.mu.Unlock()
			log.Printf("[%s] received attachment offer %s (%s, %d bytes)", a.name, meta.Name, meta.FileID, meta.Size)
			if auto && a.node != nil {
				_ = a.node.DownloadAttachment(meta.FileID)
			}
		},
		OnAttachment: func(meta *cot.AttachmentMeta, data []byte) {
			h := sha256.Sum256(data)
			hashHex := hex.EncodeToString(h[:])
			verified := (hashHex == meta.Hash)

			a.mu.Lock()
			a.attachments = append(a.attachments, ReceivedAttachment{
				FileID:   meta.FileID,
				Name:     meta.Name,
				Hash:     meta.Hash,
				Size:     int64(len(data)),
				Verified: verified,
			})
			a.mu.Unlock()
			log.Printf("[%s] received attachment %s (%d bytes, verified=%v)", a.name, meta.Name, len(data), verified)
		},
		OnDirectInvite: func(inv *cot.DirectInvite, payload *cot.InvitePayload) {
			a.mu.Lock()
			if a.rawInvites == nil {
				a.rawInvites = make(map[string]*cot.DirectInvite)
			}
			a.rawInvites[inv.InviteID] = inv
			a.receivedInvites = append(a.receivedInvites, ReceivedInvite{
				InviteID:  inv.InviteID,
				From:      inv.FromSignPub,
				RoomID:    payload.RoomID,
				RoomKey:   payload.RoomKey,
				Title:     payload.Title,
				Timestamp: inv.Timestamp,
			})
			a.mu.Unlock()
			log.Printf("[%s] received direct invite %s from %s for room %s", a.name, inv.InviteID[:8], inv.FromSignPub[:8], payload.RoomID[:8])
		},
		OnInviteResponse: func(res *cot.InviteResponse) {
			log.Printf("[%s] received invite response for %s from %s: accepted=%v", a.name, res.InviteID[:8], res.FromSignPub[:8], res.Accepted)
			if res.Accepted {
				go a.initiateDMP2P(res.FromSignPub)
			}
		},
		OnRelayPayload: func(from, relayType string, payload []byte) {
			if relayType == "dm" {
				a.mu.RLock()
				dmNode := a.dmNode
				a.mu.RUnlock()
				if dmNode != nil {
					dmNode.HandleWire(from, payload)
				}
			} else if relayType == "dm_signal" {
				var s signalPayload
				if err := json.Unmarshal(payload, &s); err == nil {
					a.handleDMSignalPayload(from, s)
				}
			}
		},
	}
	hooks = media.AttachNode(nil, hooks)
	node = cot.NewNode(a.id, a.roomID, a.roomKey, cfg, tr, hooks)

	supCtx, supCancel := context.WithCancel(context.Background())
	a.mu.Lock()
	a.node = node
	a.media = media
	a.supervisorCancel = supCancel
	a.mu.Unlock()
	node.StartMeshSupervisor(supCtx, 1*time.Second)
}

func (a *ClientApp) initDMSession(dmPeer, roomID, keyStr string) error {
	key, err := cot.ParseRoomKey(keyStr)
	if err != nil {
		return fmt.Errorf("invalid DM room key: %w", err)
	}

	a.mu.Lock()
	a.dmPeer = dmPeer
	a.dmRoomID = roomID
	a.dmRoomKey = key
	a.dmMessages = nil
	a.dmCallFrames = nil
	mainNode := a.node
	a.mu.Unlock()

	if mainNode != nil && dmPeer != "" {
		if err := mainNode.RegisterDMScope(roomID, dmPeer, key); err != nil {
			return err
		}
	}

	pion := rtc.New(a.id.Address(), nil, func(from string, data []byte) {
		a.mu.RLock()
		dmNode := a.dmNode
		a.mu.RUnlock()
		if dmNode != nil {
			dmNode.HandleWire(from, data)
		}
	})
	a.dmPion = pion

	tr := &filterTransport{
		base:    pion,
		blocked: make(map[string]bool),
	}
	a.dmTransport = tr

	pion.OnOpen(func(addr string) {
		log.Printf("[%s] direct DM WebRTC DataChannel opened with %s", a.name, addr[:8])
		a.mu.RLock()
		dmNode := a.dmNode
		a.mu.RUnlock()
		if dmNode != nil {
			dmNode.AddPeer(addr)
		}
	})

	dmRelayTr := &dmRelayTransport{
		app:  a,
		base: tr,
	}

	a.dmNode = cot.NewNode(a.id, roomID, key, cot.DefaultConfig(), dmRelayTr, cot.Hooks{
		OnMessage: func(env *cot.Envelope, plaintext []byte) {
			var chat cot.ChatPayload
			_ = json.Unmarshal(plaintext, &chat)
			a.mu.Lock()
			a.dmMessages = append(a.dmMessages, ReceivedMessage{
				Author:    env.AuthorPubKey,
				Text:      chat.Text,
				Timestamp: env.Timestamp,
			})
			a.mu.Unlock()
			log.Printf("[%s] received DM message from %s: %s", a.name, env.AuthorPubKey[:8], chat.Text)
		},
	})

	if dmPeer != "" {
		a.dmNode.AddPeer(dmPeer)
	}

	return nil
}

func (a *ClientApp) connectSignaling() error {
	a.wsConnectMu.Lock()
	defer a.wsConnectMu.Unlock()

	a.mu.RLock()
	active := a.disconnected
	gwAddr := a.gatewayAddr
	pion := a.pion
	node := a.node
	a.mu.RUnlock()
	if active {
		return nil
	}
	if gwAddr != "" && pion != nil && pion.HasActiveOrPending(gwAddr) {
		if node != nil {
			go node.QueryPeers()
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	serverAddr, err := rtc.DialSignalingWS(ctx, a.signalingURL, a.id, a.pion, a.node)
	if err != nil {
		return fmt.Errorf("dial signaling ws: %w", err)
	}

	log.Printf("[%s] connected to signaling gateway %s via WebRTC DataChannel", a.name, serverAddr[:8])
	a.mu.Lock()
	a.gatewayAddr = serverAddr
	a.mu.Unlock()
	a.node.AddPeer(serverAddr)
	a.node.QueryPeers()
	return nil
}

func (a *ClientApp) initiateDMP2P(targetPeer string) {
	a.mu.RLock()
	dmPion := a.dmPion
	a.mu.RUnlock()
	if dmPion == nil {
		return
	}
	sdp, err := dmPion.CreateOffer(targetPeer)
	if err != nil {
		log.Printf("[%s] DM create offer to %s error: %v", a.name, targetPeer[:8], err)
		return
	}
	a.sendDMSignal(targetPeer, "offer", sdp)
}

func (a *ClientApp) sendDMSignal(to, sigType, sdp string) {
	sigBytes, _ := json.Marshal(signalPayload{Type: sigType, SDP: sdp})
	if a.node != nil {
		_ = a.node.SendViaRelay(to, "dm_signal", sigBytes)
	}
}

func (a *ClientApp) handleDMSignalPayload(from string, s signalPayload) {
	a.mu.RLock()
	dmPion := a.dmPion
	a.mu.RUnlock()
	if dmPion == nil {
		return
	}

	if s.Type == "offer" {
		answerSDP, err := dmPion.AcceptOffer(from, s.SDP)
		if err != nil {
			log.Printf("[%s] DM accept offer from %s error: %v", a.name, from[:8], err)
			return
		}
		a.sendDMSignal(from, "answer", answerSDP)
	} else if s.Type == "answer" {
		if err := dmPion.AcceptAnswer(from, s.SDP); err != nil {
			log.Printf("[%s] DM accept answer from %s error: %v", a.name, from[:8], err)
		}
	}
}

func (a *ClientApp) disconnect() {
	a.mu.Lock()
	a.disconnected = true
	a.gatewayAddr = ""
	supCancel := a.supervisorCancel
	a.supervisorCancel = nil
	node := a.node
	media := a.media
	a.media = nil
	a.mu.Unlock()

	if supCancel != nil {
		supCancel()
	}
	if media != nil {
		media.Close()
	}
	if node != nil {
		node.StopMeshSupervisor()
	}
	if a.pion != nil {
		a.pion.Close()
	}
	if a.dmPion != nil {
		a.dmPion.Close()
	}
}

func (a *ClientApp) reconnect() error {
	a.disconnect()
	a.mu.Lock()
	a.disconnected = false
	a.mu.Unlock()
	a.initNode()
	return a.connectSignaling()
}

// HTTP API Handlers

func (a *ClientApp) handleStatus(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	msgCount := len(a.messages)
	attCount := len(a.attachments)
	invCount := len(a.receivedInvites)
	chanCallCount := len(a.channelCallFrames)
	dmMsgCount := len(a.dmMessages)
	dmCallCount := len(a.dmCallFrames)
	dmRoomID := a.dmRoomID
	dmPeer := a.dmPeer
	media := a.media
	node := a.node
	a.mu.RUnlock()

	var dmPeers []string
	if a.dmNode != nil {
		dmPeers = a.dmNode.Peers()
	}

	var callStats rtc.CallMediaStats
	var chanCallPeers, dmCallPeers []string
	if media != nil {
		callStats = media.Stats()
		chanCallPeers = media.ConnectedPeers(a.roomID)
		if dmRoomID != "" {
			dmCallPeers = media.ConnectedPeers(dmRoomID)
		}
	}

	rawDirectPeers := a.transport.Peers()
	directPeers := make([]string, 0, len(rawDirectPeers))
	for _, p := range rawDirectPeers {
		if node != nil && node.IsGatewayPeer(p) {
			continue
		}
		directPeers = append(directPeers, p)
	}

	status := map[string]any{
		"name":                a.name,
		"address":             a.id.Address(),
		"enc_address":         a.id.EncAddress(),
		"room_id":             a.roomID,
		"peers":               node.Peers(),
		"direct_peers":        directPeers,
		"messages_count":      msgCount,
		"attach_count":        attCount,
		"invites_count":       invCount,
		"channel_call_frames": chanCallCount,
		"channel_call_peers":  chanCallPeers,
		"dm_room_id":          dmRoomID,
		"dm_peer":             dmPeer,
		"dm_peers":            dmPeers,
		"dm_messages_count":   dmMsgCount,
		"dm_call_frames":      dmCallCount,
		"dm_call_peers":       dmCallPeers,
		"call_stats":          callStats,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func (a *ClientApp) handleSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	env, err := a.node.SendMessage(body.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "sent",
		"msg_id": env.ID(),
	})
}

func (a *ClientApp) handleMessages(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.messages)
}

func (a *ClientApp) handleShareFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		SizeBytes int    `json:"size_bytes"`
		DataB64   string `json:"data_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	const maxGeneratedAttachmentSize = 10 * 1024 * 1024

	var data []byte
	if body.DataB64 != "" {
		d, err := base64.StdEncoding.DecodeString(body.DataB64)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data = d
	} else {
		if body.SizeBytes <= 0 {
			body.SizeBytes = 128 * 1024
		}
		if body.SizeBytes > maxGeneratedAttachmentSize {
			http.Error(w, "Requested attachment is too large", http.StatusBadRequest)
			return
		}
		data = make([]byte, body.SizeBytes)
		_, _ = io.ReadFull(rand.Reader, data)
	}

	if body.Name == "" {
		body.Name = "test-payload.bin"
	}

	meta, err := a.node.ShareAttachment(body.Name, "application/octet-stream", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(meta)
}

func (a *ClientApp) handleAttachments(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.attachments)
}

func (a *ClientApp) handleOffers(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.offers)
}

func (a *ClientApp) handleDownloadFile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		FileID string `json:"file_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.node == nil {
		http.Error(w, "node not initialized", http.StatusInternalServerError)
		return
	}
	if err := a.node.DownloadAttachment(body.FileID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "downloading", "file_id": body.FileID})
}

func (a *ClientApp) handleSetAutoDownload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AutoDownload bool `json:"auto_download"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.autoDownload = body.AutoDownload
	a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"auto_download": body.AutoDownload})
}

func (a *ClientApp) handleBlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.transport.Block(body.Peer)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"blocked"}`))
}

func (a *ClientApp) handleUnblock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.transport.Unblock(body.Peer)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"unblocked"}`))
}

func (a *ClientApp) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	a.disconnect()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"disconnected"}`))
}

func (a *ClientApp) handleReconnect(w http.ResponseWriter, r *http.Request) {
	if err := a.reconnect(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"reconnected"}`))
}

func (a *ClientApp) handleInvites(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.receivedInvites)
}

func (a *ClientApp) handleDmInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	inv, payload, err := a.node.SendDirectInvite(body.Target, "dm", "1:1 DM with "+a.name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.initDMSession(body.Target, payload.RoomID, payload.RoomKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "invited",
		"invite_id": inv.InviteID,
		"room_id":   payload.RoomID,
		"room_key":  payload.RoomKey,
		"target":    body.Target,
	})
}

func (a *ClientApp) handleDmAccept(w http.ResponseWriter, r *http.Request) {
	var body struct {
		InviteID string `json:"invite_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	inv, ok := a.rawInvites[body.InviteID]
	var foundRec *ReceivedInvite
	for i := range a.receivedInvites {
		if a.receivedInvites[i].InviteID == body.InviteID {
			foundRec = &a.receivedInvites[i]
			break
		}
	}
	a.mu.RUnlock()

	if !ok || foundRec == nil {
		http.Error(w, "invite not found", http.StatusNotFound)
		return
	}

	if err := a.node.RespondDirectInvite(inv, true); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.initDMSession(foundRec.From, foundRec.RoomID, foundRec.RoomKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "accepted",
		"room_id": foundRec.RoomID,
		"target":  foundRec.From,
	})
}

func (a *ClientApp) handleDmSend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	a.mu.RLock()
	dmNode := a.dmNode
	a.mu.RUnlock()
	if dmNode == nil {
		http.Error(w, "no active DM session", http.StatusBadRequest)
		return
	}

	env, err := dmNode.SendMessage(body.Text)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "sent",
		"msg_id": env.ID(),
	})
}

func (a *ClientApp) handleDmMessages(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.dmMessages)
}

func (a *ClientApp) resolveCallScope(reqScope string, forceDM bool) (string, bool, *cot.Node, *rtc.CallMediaTransport) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	scopeID := reqScope
	isDM := forceDM
	if scopeID == "" {
		if forceDM {
			scopeID = a.dmRoomID
		} else {
			scopeID = a.roomID
		}
	} else if !isDM && a.dmRoomID != "" && scopeID == a.dmRoomID {
		isDM = true
	}
	return scopeID, isDM, a.node, a.media
}

func (a *ClientApp) makeCallJoinHandler(defaultDM bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ScopeID    string `json:"scope_id"`
			IsDM       bool   `json:"is_dm"`
			Audio      bool   `json:"audio"`
			Video      bool   `json:"video"`
			Screen     bool   `json:"screen"`
			ListenOnly bool   `json:"listen_only"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		scopeID, isDM, node, media := a.resolveCallScope(body.ScopeID, defaultDM || body.IsDM)
		if node == nil || scopeID == "" {
			http.Error(w, "missing call scope or node", http.StatusBadRequest)
			return
		}
		opts := cot.CallOptions{
			Audio:      !body.ListenOnly && body.Audio,
			Video:      !body.ListenOnly && body.Video,
			Screen:     !body.ListenOnly && body.Screen,
			ListenOnly: body.ListenOnly,
		}
		bundle, err := node.JoinCall(scopeID, isDM, opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		active := node.ActiveCallPeers(scopeID)
		if media != nil {
			media.InitiateCallPeers(scopeID, active)
		}
		log.Printf("[%s] joined call scope=%s isDM=%v epoch=%d activePeers=%d", a.name, shortID(scopeID), isDM, bundle.Epoch, len(active))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "joined",
			"scope_id": scopeID,
			"is_dm":    isDM,
			"epoch":    bundle.Epoch,
		})
	}
}

func (a *ClientApp) makeCallLeaveHandler(defaultDM bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ScopeID     string `json:"scope_id"`
			ClearFrames bool   `json:"clear_frames"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err != io.EOF {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		scopeID, isDM, node, media := a.resolveCallScope(body.ScopeID, defaultDM)
		if node != nil && scopeID != "" {
			_ = node.LeaveCall(scopeID)
		}
		if media != nil && scopeID != "" {
			media.CloseScope(scopeID)
		}
		if body.ClearFrames {
			a.mu.Lock()
			if isDM {
				a.dmCallFrames = nil
			} else {
				a.channelCallFrames = nil
			}
			a.mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "left", "scope_id": scopeID})
	}
}

func (a *ClientApp) makeCallSendMediaHandler(defaultDM bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ScopeID string `json:"scope_id"`
			Kind    string `json:"kind"`
			Payload string `json:"payload"`
			Count   int    `json:"count"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.Kind == "" {
			body.Kind = "audio"
		}
		if body.Count <= 0 {
			body.Count = 1
		}
		var data []byte
		if body.Payload != "" {
			var err error
			data, err = base64.StdEncoding.DecodeString(body.Payload)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			data = make([]byte, 32)
			_, _ = rand.Read(data)
		}

		scopeID, _, _, media := a.resolveCallScope(body.ScopeID, defaultDM)
		if media == nil || scopeID == "" {
			http.Error(w, "no active call scope or media transport", http.StatusBadRequest)
			return
		}
		for i := 0; i < body.Count; i++ {
			var err error
			if body.Kind == "video" {
				err = media.WriteVideoFrame(scopeID, data, 33*time.Millisecond)
			} else {
				err = media.WriteAudioFrame(scopeID, data, 20*time.Millisecond)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if i+1 < body.Count {
				time.Sleep(20 * time.Millisecond)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":   "sent",
			"scope_id": scopeID,
			"kind":     body.Kind,
			"count":    body.Count,
		})
	}
}

func (a *ClientApp) makeCallFramesHandler(defaultDM bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a.mu.RLock()
		defer a.mu.RUnlock()
		src := a.channelCallFrames
		if defaultDM {
			src = a.dmCallFrames
		}
		out := make([]ReceivedCallFrame, len(src))
		copy(out, src)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func (a *ClientApp) handleCallStats(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	node := a.node
	media := a.media
	dmRoomID := a.dmRoomID
	a.mu.RUnlock()

	resp := map[string]any{
		"channel_call_peers": []string{},
		"dm_call_peers":      []string{},
		"active_call_peers":  []string{},
	}
	if media != nil {
		resp["stats"] = media.Stats()
		resp["channel_call_peers"] = media.ConnectedPeers(a.roomID)
		if dmRoomID != "" {
			resp["dm_call_peers"] = media.ConnectedPeers(dmRoomID)
		}
	}
	if node != nil {
		resp["active_call_peers"] = node.ActiveCallPeers(a.roomID)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (a *ClientApp) handleDmBlock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.dmTransport != nil {
		a.dmTransport.Block(body.Peer)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"dm_blocked"}`))
}

func (a *ClientApp) handleDmUnblock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Peer string `json:"peer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if a.dmTransport != nil {
		a.dmTransport.Unblock(body.Peer)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"dm_unblocked"}`))
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func getEnv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func main() {
	name := flag.String("name", getEnv("CLIENT_NAME", "client"), "client name")
	apiPort := flag.String("port", getEnv("PORT", "8080"), "HTTP API listen port")
	signalingURL := flag.String("signaling", getEnv("SIGNALING_URL", "ws://signaling:8080/ws"), "signaling WebSocket URL")
	roomID := flag.String("room", getEnv("ROOM_ID", "bench-room-0000"), "burner room ID")
	roomKey := flag.String("key", getEnv("ROOM_KEY", ""), "burner room 256-bit key")
	flag.Parse()

	if *roomKey == "" {
		// Generate default test room key if omitted
		k, _ := cot.GenerateRoomKey()
		*roomKey = k.String()
	}

	app, err := newClientApp(*name, ":"+*apiPort, *signalingURL, *roomID, *roomKey)
	if err != nil {
		log.Fatalf("failed to initialize client: %v", err)
	}

	defer app.disconnect()

	// Connect to signaling
	if err := app.connectSignaling(); err != nil {
		log.Printf("initial signaling connection failed (will retry): %v", err)
		go func() {
			for {
				time.Sleep(2 * time.Second)
				if err := app.connectSignaling(); err == nil {
					break
				}
			}
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":      "ok",
			"name":        app.name,
			"address":     app.id.Address(),
			"enc_address": app.id.EncAddress(),
		})
	})
	mux.HandleFunc("/status", app.handleStatus)
	mux.HandleFunc("/send", app.handleSend)
	mux.HandleFunc("/messages", app.handleMessages)
	mux.HandleFunc("/share-file", app.handleShareFile)
	mux.HandleFunc("/attachments", app.handleAttachments)
	mux.HandleFunc("/offers", app.handleOffers)
	mux.HandleFunc("/download-file", app.handleDownloadFile)
	mux.HandleFunc("/set-auto-download", app.handleSetAutoDownload)
	mux.HandleFunc("/block", app.handleBlock)
	mux.HandleFunc("/unblock", app.handleUnblock)
	mux.HandleFunc("/disconnect", app.handleDisconnect)
	mux.HandleFunc("/reconnect", app.handleReconnect)

	// Direct invites and DM routes
	mux.HandleFunc("/invites", app.handleInvites)
	mux.HandleFunc("/dm/invite", app.handleDmInvite)
	mux.HandleFunc("/dm/accept", app.handleDmAccept)
	mux.HandleFunc("/dm/send", app.handleDmSend)
	mux.HandleFunc("/dm/messages", app.handleDmMessages)
	mux.HandleFunc("/dm/call/join", app.makeCallJoinHandler(true))
	mux.HandleFunc("/dm/call/leave", app.makeCallLeaveHandler(true))
	mux.HandleFunc("/dm/call/send-media", app.makeCallSendMediaHandler(true))
	mux.HandleFunc("/dm/call/frames", app.makeCallFramesHandler(true))
	mux.HandleFunc("/dm/block", app.handleDmBlock)
	mux.HandleFunc("/dm/unblock", app.handleDmUnblock)

	// Secondary WebRTC call routes
	mux.HandleFunc("/call/join", app.makeCallJoinHandler(false))
	mux.HandleFunc("/call/leave", app.makeCallLeaveHandler(false))
	mux.HandleFunc("/call/send-media", app.makeCallSendMediaHandler(false))
	mux.HandleFunc("/call/frames", app.makeCallFramesHandler(false))
	mux.HandleFunc("/call/stats", app.handleCallStats)

	log.Printf("[%s] E2E test client listening on :%s (address %s)", *name, *apiPort, app.id.Address()[:8])
	log.Fatal(http.ListenAndServe(":"+*apiPort, mux))
}
