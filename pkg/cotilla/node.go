package cotilla

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Transport defines the communication interface for sending packets over WebRTC DataChannels.
type Transport interface {
	Send(addr string, data []byte) error
	Broadcast(data []byte)
	Peers() []string
	ClosePeer(addr string)
}

// WebRTCTransport extends Transport with SDP offer/answer handshake methods.
type WebRTCTransport interface {
	Transport
	CreateOffer(peerAddr string) (string, error)
	AcceptOffer(peerAddr, offerSDP string) (string, error)
	AcceptAnswer(peerAddr, answerSDP string) error
}

// Hooks defines event callbacks for incoming room, overlay, call, and app distribution activities.
type Hooks struct {
	OnMessage            func(env *Envelope, plaintext []byte)
	OnAttachmentOffer    func(meta *AttachmentMeta)
	OnAttachment         func(meta *AttachmentMeta, data []byte)
	OnAttachmentProgress func(fileID string, receivedChunks, totalChunks int)
	OnCallPresence       func(scopeID string, isDM bool, from string, payload *CallPresencePayload)
	OnCallSignal         func(sig *CallSignalPayload)
	OnSFrameKeysUpdated  func(scopeID string, isDM bool, bundle *SFrameKeyBundle)
	OnCallPeerClosed     func(scopeID string, peerAddr string)
	OnDirectInvite       func(invite *DirectInvite, payload *InvitePayload)
	OnInviteResponse     func(res *InviteResponse)
	OnPeerJoined         func(addr string)
	OnPeerLeft           func(addr string)
	OnRelayPayload       func(from, relayType string, payload []byte)
	OnMemberEvicted      func(evictedPeer, evictor, reason string, epochID int64)
	OnEpochCommit        func(commit *EpochCommit)
	OnAnchorIntro        func(anchors []string, fallback bool)
	OnAnchorDeficit      func(currentAnchors int, activePeers int)
	OnAnchorSolicit      func(needed int)
	OnChannelDiscovered  func(channelID string, peer string)
	OnPeerCandidate      func(peers []string)
	OnAppManifest        func(manifest *AppManifest, from string)
	OnAppBundleReady     func(manifest *AppManifest, data []byte)
	Log                  func(msg string)
}

// ChatPayload is the plaintext content of an encrypted chat message envelope.
type ChatPayload struct {
	Type string `json:"type"` // "chat"
	Text string `json:"text"`
}

const (
	maxGossipCacheEntries   = 5000
	maxPendingCommitsPerCh  = 256
	maxSeenEnvelopesTracked = 10000
	maxGossipTTL            = 20
)

// Node is a participant in the Cotilla Meshtastic-inspired gossip mesh and MLS channels.
type Node struct {
	mu          sync.RWMutex
	admissionMu sync.Mutex
	ID          *Identity
	Cfg         Config
	Transport   Transport
	Hooks       Hooks

	// Embedded primary channel keeps convenient direct accessors on Node.
	*ChannelState
	channels       map[string]*ChannelState
	channelsByHash map[uint32]*ChannelState
	channelPeers   map[string]map[string]bool

	// Core mesh engines
	overlay     *OverlayView
	broadcaster *ExpandingBroadcaster
	packetCache *PacketCache

	// Public app seeding store
	seededApps map[string]*seededAppBundle

	// Anchor & gateway tracking
	anchorPeers        map[string]bool
	fallbackMode       bool
	gatewayPeersMu     sync.RWMutex
	gatewayPeers       map[string]bool
	supervisorStop     chan struct{}
	supervisorStopOnce sync.Once
	lastShuffleAt      time.Time

	// Scoped Secondary WebRTC Calls & DM scopes
	dmScopes    map[string]*dmScope
	activeCalls map[string]*callSession
	callRoster  map[string]map[string]*CallPeerState
}

// NewNode initializes a Cotilla mesh node with its primary private channel.
func NewNode(id *Identity, roomID string, roomKey RoomKey, cfg Config, tr Transport, hooks Hooks) *Node {
	cfg = cfg.withDefaults()
	myKp, _ := NewKeyPackage(id)
	primary := newChannelState(roomID, roomKey, ChannelPrivate, myKp, cfg)

	n := &Node{
		ID:             id,
		Cfg:            cfg,
		Transport:      tr,
		Hooks:          hooks,
		ChannelState:   primary,
		channels:       make(map[string]*ChannelState),
		channelsByHash: make(map[uint32]*ChannelState),
		channelPeers:   make(map[string]map[string]bool),
		overlay:        NewOverlayView(id.Address(), cfg),
		broadcaster:    NewExpandingBroadcaster(cfg),
		packetCache:    NewPacketCache(cfg.GossipCacheTTL, maxGossipCacheEntries),
		seededApps:     make(map[string]*seededAppBundle),
		anchorPeers:    make(map[string]bool),
		gatewayPeers:   make(map[string]bool),
		supervisorStop: make(chan struct{}),
		dmScopes:       make(map[string]*dmScope),
		activeCalls:    make(map[string]*callSession),
		callRoster:     make(map[string]map[string]*CallPeerState),
	}
	if roomID != "" {
		n.channels[roomID] = primary
		n.channelsByHash[primary.ChannelHash] = primary
	}
	return n
}

// Address returns this node's hex Ed25519 public address.
func (n *Node) Address() string { return n.ID.Address() }

func (n *Node) log(format string, args ...any) {
	if n.Hooks.Log != nil {
		n.Hooks.Log(fmt.Sprintf(format, args...))
	}
}

func (n *Node) channelLocked(channelID string) *ChannelState {
	if channelID == "" || channelID == n.RoomID {
		return n.ChannelState
	}
	return n.channels[channelID]
}

func (n *Node) channelByHash(chHash uint32) *ChannelState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.channelsByHash[chHash]
}

func (n *Node) isEvictedEverywhere(addr string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.isEvictedEverywhereLocked(addr)
}

func (n *Node) isEvictedEverywhereLocked(addr string) bool {
	if addr == "" || len(n.channels) == 0 {
		return false
	}
	for _, ch := range n.channels {
		if ch.evictedPeers[addr] == 0 {
			return false
		}
	}
	return true
}

// Overlay returns the node's HyParView membership view.
func (n *Node) Overlay() *OverlayView { return n.overlay }

// AddGatewayPeer marks addr as a signaling gateway DataChannel peer.
func (n *Node) AddGatewayPeer(addr string) {
	if addr == "" {
		return
	}
	n.gatewayPeersMu.Lock()
	n.gatewayPeers[addr] = true
	n.gatewayPeersMu.Unlock()
	n.overlay.AddActive(addr, true)
}

// RemoveGatewayPeer unmarks addr as a gateway peer.
func (n *Node) RemoveGatewayPeer(addr string) {
	n.gatewayPeersMu.Lock()
	delete(n.gatewayPeers, addr)
	n.gatewayPeersMu.Unlock()
}

// IsGatewayPeer reports whether addr is a signaling gateway peer.
func (n *Node) IsGatewayPeer(addr string) bool {
	n.gatewayPeersMu.RLock()
	defer n.gatewayPeersMu.RUnlock()
	return n.gatewayPeers[addr]
}

// AddPeer records an open WebRTC peer in HyParView and triggers initial offer sync.
func (n *Node) AddPeer(addr string) {
	if addr == "" || addr == n.Address() {
		return
	}
	isNew := n.overlay.AddActive(addr, n.IsGatewayPeer(addr))
	if isNew && !n.IsGatewayPeer(addr) {
		if n.Hooks.OnPeerJoined != nil {
			n.Hooks.OnPeerJoined(addr)
		}
		go n.syncOffersToPeer(addr)
		go n.syncCallPresenceToPeer(addr)
	}
}

// RemovePeer removes a disconnected peer and triggers HyParView repair from the passive view.
func (n *Node) RemovePeer(addr string) {
	wasActive := n.overlay.RemoveActive(addr, !n.isEvictedEverywhere(addr))
	n.mu.Lock()
	for _, m := range n.channelPeers {
		delete(m, addr)
	}
	n.mu.Unlock()
	if wasActive && !n.IsGatewayPeer(addr) {
		if n.Hooks.OnPeerLeft != nil {
			n.Hooks.OnPeerLeft(addr)
		}
		go n.repairMeshFromPassive()
	}
}

// Peers returns currently active non-gateway peer addresses.
func (n *Node) Peers() []string { return n.overlay.ActivePeers() }

// liveNonGatewayPeers returns currently connected non-gateway peers from Transport.Peers().
func (n *Node) liveNonGatewayPeers() []string {
	if n.Transport == nil {
		return nil
	}
	raw := n.Transport.Peers()
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p == "" || p == n.Address() || n.isGatewayOrSignaling(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// SetPeerEncKey records a peer's X25519 encryption public key.
func (n *Node) SetPeerEncKey(signPub, encPub string) { n.overlay.SetEncKey(signPub, encPub) }

// PeerEncKeys returns a snapshot of known SignPub -> EncPub mappings.
func (n *Node) PeerEncKeys() map[string]string { return n.overlay.EncKeysSnapshot() }

// JoinPublicChannel joins a PSK-encrypted public group (2 target peers, longer TTL).
func (n *Node) JoinPublicChannel(name string, psk RoomKey) error {
	return n.joinTypedChannel(name, psk, ChannelPublic, nil)
}

// JoinPrivateChannel joins an MLS-encrypted private group (>=6 target peers, short TTL).
func (n *Node) JoinPrivateChannel(roomID string, key RoomKey, invite *ChannelInvite) error {
	return n.joinTypedChannel(roomID, key, ChannelPrivate, invite)
}

// JoinChannelWithKey registers and discovers a private channel.
func (n *Node) JoinChannelWithKey(channelID string, key RoomKey) error {
	return n.joinTypedChannel(channelID, key, ChannelPrivate, nil)
}

// JoinChannel triggers expanding-ring discovery for an already-registered channel.
func (n *Node) JoinChannel(channelID string) error {
	n.mu.RLock()
	ch := n.channelLocked(channelID)
	n.mu.RUnlock()
	if ch == nil {
		return fmt.Errorf("cotilla: channel %s not registered", channelID)
	}
	n.startGroupDiscovery(ch)
	return nil
}

func (n *Node) joinTypedChannel(roomID string, key RoomKey, kind ChannelKind, invite *ChannelInvite) error {
	if roomID == "" {
		return errors.New("cotilla: channel ID cannot be empty")
	}
	n.mu.Lock()
	ch := n.channels[roomID]
	if ch == nil {
		myKp := n.myKeyPackage
		if myKp == nil {
			myKp, _ = NewKeyPackage(n.ID)
		}
		ch = newChannelState(roomID, key, kind, myKp, n.Cfg)
		n.channels[roomID] = ch
		n.channelsByHash[ch.ChannelHash] = ch
	} else {
		ch.Kind = kind
	}
	if invite != nil {
		ch.channelInvite = invite
	}
	n.mu.Unlock()

	go n.BroadcastPeerInfo()
	n.startGroupDiscovery(ch)
	return nil
}

func (n *Node) startGroupDiscovery(ch *ChannelState) {
	tag := fmt.Sprintf("group:%d", ch.ChannelHash)
	maxTTL := n.Cfg.GroupTTL(ch.Kind)
	want := n.Cfg.GroupTargetPeers(ch.Kind)
	n.broadcaster.Start(tag, maxTTL, func(ttl, fanout int) {
		n.mu.RLock()
		key := ch.BootstrapKey
		roomID := ch.RoomID
		chHash := ch.ChannelHash
		n.mu.RUnlock()
		gd := GroupDiscoverPayload{RoomID: roomID, Want: want}
		pkt, err := NewGroupPacket(n.ID, BroadcastAddr, chHash, 0, key, PortGroupDiscover, ttl, gd)
		if err != nil {
			return
		}
		n.broadcastPacketWithFanout(pkt, fanout)
	})
}

func (n *Node) addChannelPeer(channelID, peer string) {
	if channelID == "" || peer == "" || peer == n.Address() {
		return
	}
	n.mu.Lock()
	if n.channelPeers[channelID] == nil {
		n.channelPeers[channelID] = make(map[string]bool)
	}
	n.channelPeers[channelID][peer] = true
	n.mu.Unlock()
}

// ChannelPeers returns directly connected peers in channelID.
func (n *Node) ChannelPeers(channelID string) []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	m := n.channelPeers[channelID]
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	return out
}

// ActiveChannels returns the list of joined channel IDs.
func (n *Node) ActiveChannels() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.channels))
	for id := range n.channels {
		out = append(out, id)
	}
	return out
}

// AnchorPeers returns known anchor peer addresses.
func (n *Node) AnchorPeers() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]string, 0, len(n.anchorPeers))
	for a := range n.anchorPeers {
		out = append(out, a)
	}
	return out
}

// AddAnchorPeer registers addr as an anchor peer.
func (n *Node) AddAnchorPeer(addr string) {
	if addr == "" || addr == n.Address() {
		return
	}
	n.mu.Lock()
	n.anchorPeers[addr] = true
	n.mu.Unlock()
	n.overlay.MarkAnchor(addr, true)
}

// IsAnchorPeer reports whether addr is currently marked as an anchor peer.
func (n *Node) IsAnchorPeer(addr string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.anchorPeers[addr]
}

// IsFallbackMode reports whether the node is in signaling fallback mode.
func (n *Node) IsFallbackMode() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.fallbackMode
}

// SetFallbackMode updates signaling fallback mode.
func (n *Node) SetFallbackMode(fb bool) {
	n.mu.Lock()
	n.fallbackMode = fb
	n.mu.Unlock()
}

// SendMessage encrypts, signs, and broadcasts a chat message in the primary room.
func (n *Node) SendMessage(text string) (*Envelope, error) {
	return n.SendChannelMessage(n.RoomID, text)
}

// SendChannelMessage encrypts, signs, and broadcasts a chat message in channelID.
func (n *Node) SendChannelMessage(channelID, text string) (*Envelope, error) {
	n.mu.RLock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		n.mu.RUnlock()
		return nil, fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	if ch.evictedPeers[n.Address()] > 0 {
		n.mu.RUnlock()
		return nil, errors.New("cotilla: evicted peer cannot send messages")
	}
	key, epoch := ch.activeKeyAndEpoch()
	roomID := ch.RoomID
	n.mu.RUnlock()

	plain, err := json.Marshal(ChatPayload{Type: "chat", Text: text})
	if err != nil {
		return nil, err
	}
	env, err := NewEnvelopeWithEpoch(n.ID, roomID, key, epoch, plain)
	if err != nil {
		return nil, err
	}

	n.mu.Lock()
	if cur := n.channelLocked(roomID); cur != nil {
		cur.RingBuffer.Push(env)
		recordSeenEnvelopeLocked(cur, env.ID())
	}
	n.mu.Unlock()

	_ = n.sendGroupPacket(ch, BroadcastAddr, PortChat, env)
	return env, nil
}

func (n *Node) handleEnvelope(from string, env *Envelope) {
	n.processEnvelope(env, n.Cfg.ReplayWindow, false)
}

func (n *Node) processEnvelope(env *Envelope, maxSkew time.Duration, isCatchUp bool) bool {
	if env == nil {
		return false
	}
	n.mu.RLock()
	ch := n.channelLocked(env.RoomID)
	n.mu.RUnlock()
	if ch == nil {
		return false
	}
	if err := env.Verify(ch.RoomID, maxSkew); err != nil {
		return false
	}
	plain, ok := n.decryptAndStoreEnvelope(ch, env, isCatchUp)
	if !ok {
		return false
	}
	if n.Hooks.OnMessage != nil {
		n.Hooks.OnMessage(env, plain)
	}
	return true
}

func (n *Node) decryptAndStoreEnvelope(ch *ChannelState, env *Envelope, isCatchUp bool) ([]byte, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ch.IsAppDist {
		return nil, false
	}

	if ch.evictedPeers[env.AuthorPubKey] > 0 && env.EpochID >= ch.evictedPeers[env.AuthorPubKey] {
		return nil, false
	}
	if _, seen := ch.seenEnvelopes[env.ID()]; seen {
		return nil, false
	}
	key, ok := ch.epochKeys[env.EpochID]
	if !ok {
		key = ch.RoomKey
	}
	plain, err := env.Decrypt(key)
	if err != nil {
		if ch.BootstrapKey != key {
			plain, err = env.Decrypt(ch.BootstrapKey)
		}
		if err != nil {
			return nil, false
		}
	}
	ch.RingBuffer.Push(env)
	recordSeenEnvelopeLocked(ch, env.ID())
	return plain, true
}

// Leave broadcasts a signed voluntary departure packet and stops background loops.
func (n *Node) Leave() error {
	lv := n.newLeaveFrame()
	pkt, err := NewPlainPacket(n.ID, BroadcastAddr, PortLeave, 1, lv)
	if err != nil {
		return err
	}
	n.broadcastPacketWithFanout(pkt, n.Cfg.MaxPeers)
	n.StopMeshSupervisor()
	return nil
}

// StartMeshSupervisor runs the background HyParView + group quota maintenance loop.
func (n *Node) StartMeshSupervisor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-n.supervisorStop:
				return
			case <-ticker.C:
				n.superviseMesh()
			}
		}
	}()
}

// StopMeshSupervisor stops all background mesh maintenance and expanding broadcasts.
func (n *Node) StopMeshSupervisor() {
	n.broadcaster.Stop()
	n.supervisorStopOnce.Do(func() {
		close(n.supervisorStop)
	})
}

func (n *Node) superviseMesh() {
	if n.Transport == nil || n.isEvictedEverywhere(n.Address()) {
		return
	}
	n.checkAnchorDeficit()
	if len(n.overlay.ActivePeers()) < n.Cfg.MinActivePeers {
		n.repairMeshFromPassive()
		n.DiscoverPeers()
	}
	n.maintainGroupQuotas()
	if time.Since(n.lastShuffleAt) >= n.Cfg.ShuffleInterval {
		n.lastShuffleAt = time.Now()
		n.stepHyParViewShuffle()
		n.rotateExcessPeer()
	}
}

func (n *Node) checkAnchorDeficit() {
	n.mu.RLock()
	fallback := n.fallbackMode
	anchors := 0
	live := make(map[string]bool)
	for _, p := range n.overlay.ActivePeers() {
		live[p] = true
	}
	for a := range n.anchorPeers {
		if live[a] {
			anchors++
		}
	}
	n.mu.RUnlock()
	if n.Hooks.OnAnchorDeficit != nil && (len(live) == 0 || (!fallback && anchors < n.Cfg.MinAnchorConnections)) {
		n.Hooks.OnAnchorDeficit(anchors, len(live))
	}
}

func (n *Node) maintainGroupQuotas() {
	n.mu.RLock()
	var need []*ChannelState
	for _, ch := range n.channels {
		if n.overlay.ChannelPeerCount(ch.ChannelHash) < n.Cfg.GroupTargetPeers(ch.Kind) {
			need = append(need, ch)
		}
	}
	n.mu.RUnlock()
	for _, ch := range need {
		n.startGroupDiscovery(ch)
	}
}

func (n *Node) repairMeshFromPassive() {
	needed := make(map[uint32]bool)
	n.mu.RLock()
	for _, ch := range n.channels {
		if n.overlay.ChannelPeerCount(ch.ChannelHash) < n.Cfg.GroupTargetPeers(ch.Kind) {
			needed[ch.ChannelHash] = true
		}
	}
	n.mu.RUnlock()
	deficit := n.Cfg.MaxPeers - len(n.overlay.ActivePeers())
	if deficit <= 0 {
		return
	}
	if deficit > 4 {
		deficit = 4
	}
	cands := n.overlay.PickRepairCandidates(needed, deficit)
	n.dialCandidates(cands)
}

func (n *Node) rotateExcessPeer() {
	if len(n.overlay.ActivePeers()) <= n.Cfg.MaxPeers {
		return
	}
	mins := make(map[uint32]int)
	n.mu.RLock()
	for _, ch := range n.channels {
		mins[ch.ChannelHash] = n.Cfg.GroupTargetPeers(ch.Kind)
	}
	n.mu.RUnlock()
	if victim := n.overlay.PickRotationVictim(mins, 3*time.Second); victim != "" {
		n.overlay.RemoveActive(victim, true)
		n.Transport.ClosePeer(victim)
	}
}
