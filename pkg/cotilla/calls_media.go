package cotilla

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CallOptions configures which media capabilities a participant enables when joining a call.
type CallOptions struct {
	ListenOnly bool `json:"listen_only"`
	Audio      bool `json:"audio"`
	Video      bool `json:"video"`
	Screen     bool `json:"screen"`
}

// CallPeerState tracks the active call presence of an authorized remote participant in a scope.
type CallPeerState struct {
	Address      string    `json:"address"`
	CallID       string    `json:"call_id"`
	LeafIndex    int       `json:"leaf_index"`
	Epoch        int64     `json:"epoch"`
	SenderEncPub string    `json:"sender_enc_pub,omitempty"`
	Audio        bool      `json:"audio"`
	Video        bool      `json:"video"`
	Screen       bool      `json:"screen"`
	LastSeen     time.Time `json:"last_seen"`
}

type dmScope struct {
	RoomID   string
	PeerAddr string
	RoomKey  RoomKey
}

type callSession struct {
	ScopeID  string
	IsDM     bool
	CallID   string
	Joined   bool
	SelfOpts CallOptions
	Epoch    int64
	MyLeaf   int
	Peers    map[string]*CallPeerState
}

// RegisterDMScope registers a 2-peer DM cryptographic scope for scoped A/V calls and SFrame keys.
func (n *Node) RegisterDMScope(roomID, peerAddr string, key RoomKey) error {
	if roomID == "" || peerAddr == "" || peerAddr == n.Address() {
		return errors.New("cotilla: invalid DM scope parameters")
	}
	n.mu.Lock()
	if n.dmScopes == nil {
		n.dmScopes = make(map[string]*dmScope)
	}
	n.dmScopes[roomID] = &dmScope{RoomID: roomID, PeerAddr: peerAddr, RoomKey: key}
	n.mu.Unlock()
	return nil
}

// UnregisterDMScope closes any active call in roomID and deletes DM call key state.
func (n *Node) UnregisterDMScope(roomID string) {
	_ = n.LeaveCall(roomID)
	n.mu.Lock()
	if d, ok := n.dmScopes[roomID]; ok {
		zeroizeBytes(d.RoomKey[:])
		delete(n.dmScopes, roomID)
	}
	delete(n.callRoster, roomID)
	n.mu.Unlock()
}

// ActiveCallPeers returns a copy of currently known active call participants in scopeID.
func (n *Node) ActiveCallPeers(scopeID string) []CallPeerState {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var peersMap map[string]*CallPeerState
	if sess := n.activeCalls[scopeID]; sess != nil && sess.Joined {
		peersMap = sess.Peers
	} else {
		peersMap = n.callRoster[scopeID]
	}
	out := make([]CallPeerState, 0, len(peersMap))
	for _, p := range peersMap {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}

// IsInCall reports whether the local node is currently joined to a call in scopeID.
func (n *Node) IsInCall(scopeID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sess := n.activeCalls[scopeID]
	return sess != nil && sess.Joined
}

// ExportSFrameKeys computes and returns the current SFrameKeyBundle for scopeID.
func (n *Node) ExportSFrameKeys(scopeID string) (*SFrameKeyBundle, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	bundle, _, err := n.buildScopeSFrameBundleLocked(scopeID, false)
	return bundle, err
}

func (n *Node) collectOpenRoomPeersLocked(scopeID string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if p == "" || p == n.Address() || n.IsGatewayPeer(p) {
			return
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	for p := range n.channelPeers[scopeID] {
		add(p)
	}
	for p := range n.callRoster[scopeID] {
		add(p)
	}
	if len(out) == 0 {
		for _, p := range n.overlay.ActivePeers() {
			add(p)
		}
	}
	return out
}

func (n *Node) buildScopeSFrameBundleLocked(scopeID string, forceDM bool) (*SFrameKeyBundle, bool, error) {
	if dm := n.dmScopes[scopeID]; dm != nil {
		bundle, err := BuildDMSFrameBundle(dm.RoomID, dm.RoomKey, n.Address(), dm.PeerAddr)
		return bundle, true, err
	}
	if forceDM {
		return nil, true, fmt.Errorf("cotilla: DM scope %s not registered", scopeID)
	}
	ch := n.channelLocked(scopeID)
	if ch == nil {
		return nil, false, fmt.Errorf("cotilla: scope %s is not joined", scopeID)
	}
	var openPeers []string
	if ch.mlsGroup == nil || ch.currentEpoch == 0 {
		openPeers = n.collectOpenRoomPeersLocked(scopeID)
	}
	bundle, err := buildChannelSFrameBundle(ch, n.Address(), openPeers)
	return bundle, false, err
}

// JoinCall activates a call session scoped to an admitted MLS channel or 1:1 DM.
func (n *Node) JoinCall(scopeID string, isDM bool, opts CallOptions) (*SFrameKeyBundle, error) {
	if scopeID == "" {
		scopeID = n.RoomID
	}
	var callNonce [16]byte
	if _, err := rand.Read(callNonce[:]); err != nil {
		return nil, err
	}
	callID := hex.EncodeToString(callNonce[:])

	n.mu.Lock()
	bundle, resolvedDM, err := n.buildScopeSFrameBundleLocked(scopeID, isDM)
	if err != nil {
		n.mu.Unlock()
		return nil, err
	}
	isDM = resolvedDM
	if existing := n.activeCalls[scopeID]; existing != nil && existing.CallID != "" {
		callID = existing.CallID
	}
	sess := &callSession{
		ScopeID:  scopeID,
		IsDM:     isDM,
		CallID:   callID,
		Joined:   true,
		SelfOpts: opts,
		Epoch:    int64(bundle.Epoch),
		MyLeaf:   bundle.LeafIndex,
		Peers:    n.prepopulateCallPeersLocked(scopeID, isDM),
	}
	n.activeCalls[scopeID] = sess
	payload := n.buildCallPresencePayload("join", sess)
	cf, ch, targets, err := n.sealCallControlLocked(scopeID, isDM, &payload)
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}

	if n.Hooks.OnSFrameKeysUpdated != nil {
		n.Hooks.OnSFrameKeysUpdated(scopeID, isDM, bundle)
	}
	n.dispatchCallControl(cf, ch, isDM, targets)
	return bundle, nil
}

func (n *Node) prepopulateCallPeersLocked(scopeID string, isDM bool) map[string]*CallPeerState {
	peers := make(map[string]*CallPeerState)
	for addr, st := range n.callRoster[scopeID] {
		if addr == n.Address() || st == nil {
			continue
		}
		if !isDM {
			ch := n.channelLocked(scopeID)
			if ch == nil || ch.evictedPeers[addr] > 0 || (ch.mlsGroup != nil && ch.mlsGroup.FindLeafByAddress(addr) < 0) {
				continue
			}
		} else if dm := n.dmScopes[scopeID]; dm == nil || dm.PeerAddr != addr {
			continue
		}
		cp := *st
		peers[addr] = &cp
	}
	return peers
}

func (n *Node) buildCallPresencePayload(action string, sess *callSession) CallPresencePayload {
	return CallPresencePayload{
		Action:       action,
		ScopeID:      sess.ScopeID,
		IsDM:         sess.IsDM,
		CallID:       sess.CallID,
		Epoch:        sess.Epoch,
		LeafIndex:    sess.MyLeaf,
		SenderEncPub: n.ID.EncAddress(),
		Audio:        sess.SelfOpts.Audio,
		Video:        sess.SelfOpts.Video,
		Screen:       sess.SelfOpts.Screen,
	}
}

// UpdateCallOptions broadcasts updated mic/cam/screen status within an active joined call.
func (n *Node) UpdateCallOptions(scopeID string, opts CallOptions) error {
	if scopeID == "" {
		scopeID = n.RoomID
	}
	n.mu.Lock()
	sess := n.activeCalls[scopeID]
	if sess == nil || !sess.Joined {
		n.mu.Unlock()
		return fmt.Errorf("cotilla: not joined to call in %s", scopeID)
	}
	sess.SelfOpts = opts
	payload := n.buildCallPresencePayload("update", sess)
	cf, ch, targets, err := n.sealCallControlLocked(scopeID, sess.IsDM, &payload)
	n.mu.Unlock()
	if err != nil {
		return err
	}
	n.dispatchCallControl(cf, ch, sess.IsDM, targets)
	return nil
}

// LeaveCall ends local participation in scopeID's call and notifies active peers.
func (n *Node) LeaveCall(scopeID string) error {
	if scopeID == "" {
		scopeID = n.RoomID
	}
	n.mu.Lock()
	sess := n.activeCalls[scopeID]
	if sess == nil || !sess.Joined {
		n.mu.Unlock()
		return nil
	}
	delete(n.activeCalls, scopeID)
	peerAddrs := make([]string, 0, len(sess.Peers))
	for p := range sess.Peers {
		peerAddrs = append(peerAddrs, p)
	}
	payload := n.buildCallPresencePayload("leave", sess)
	cf, ch, targets, err := n.sealCallControlLocked(scopeID, sess.IsDM, &payload)
	n.mu.Unlock()

	if err == nil {
		n.dispatchCallControl(cf, ch, sess.IsDM, targets)
	}
	if n.Hooks.OnCallPeerClosed != nil {
		for _, p := range peerAddrs {
			n.Hooks.OnCallPeerClosed(scopeID, p)
		}
		n.Hooks.OnCallPeerClosed(scopeID, "")
	}
	return nil
}

func (n *Node) sealCallControlLocked(scopeID string, isDM bool, payload *CallPresencePayload) (*CallControlFrame, *ChannelState, []string, error) {
	encKey, epochID, ch, targets, err := n.resolveCallControlScopeLocked(scopeID, isDM)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, nil, err
	}
	now := time.Now().UnixMilli()
	aad := CanonicalCallControlAAD(scopeID, n.Address(), epochID, now, isDM)
	nonce, ct, err := EncryptRoomPayload(encKey, raw, aad)
	if err != nil {
		return nil, nil, nil, err
	}
	nonceHex := hex.EncodeToString(nonce)
	ctHex := hex.EncodeToString(ct)
	sig := hex.EncodeToString(n.ID.Sign(CanonicalCallControl(scopeID, n.Address(), nonceHex, ctHex, epochID, now, isDM)))

	cf := &CallControlFrame{
		ScopeID:    scopeID,
		AuthorPub:  n.Address(),
		EpochID:    epochID,
		IsDM:       isDM,
		Timestamp:  now,
		Nonce:      nonceHex,
		Ciphertext: ctHex,
		Signature:  sig,
	}
	return cf, ch, targets, nil
}

func (n *Node) resolveCallControlScopeLocked(scopeID string, isDM bool) (RoomKey, int64, *ChannelState, []string, error) {
	if isDM {
		dm := n.dmScopes[scopeID]
		if dm == nil {
			return RoomKey{}, 0, nil, nil, fmt.Errorf("cotilla: DM scope %s not found", scopeID)
		}
		return dm.RoomKey, 0, nil, []string{dm.PeerAddr}, nil
	}
	ch := n.channelLocked(scopeID)
	if ch == nil {
		return RoomKey{}, 0, nil, nil, fmt.Errorf("cotilla: channel %s not found", scopeID)
	}
	key, epoch := ch.activeKeyAndEpoch()
	return key, epoch, ch, n.collectCallTargetsLocked(ch, scopeID), nil
}

func (n *Node) collectCallTargetsLocked(ch *ChannelState, scopeID string) []string {
	targetSet := make(map[string]struct{})
	if ch.mlsGroup != nil && ch.mlsGroup.Tree != nil {
		for i := 0; i < ch.mlsGroup.Tree.NumLeaves; i++ {
			lf := ch.mlsGroup.Tree.Nodes[2*i]
			if lf != nil && !lf.Blank && lf.SignPubHex != "" && lf.SignPubHex != n.Address() && ch.evictedPeers[lf.SignPubHex] == 0 {
				targetSet[lf.SignPubHex] = struct{}{}
			}
		}
	} else {
		for p := range n.channelPeers[scopeID] {
			if p != "" && p != n.Address() && ch.evictedPeers[p] == 0 {
				targetSet[p] = struct{}{}
			}
		}
		if len(targetSet) == 0 && ch.creatorPub == "" && ch.channelInvite == nil {
			for _, p := range n.overlay.ActivePeers() {
				if ch.evictedPeers[p] == 0 {
					targetSet[p] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(targetSet))
	for p := range targetSet {
		out = append(out, p)
	}
	return out
}

func (n *Node) dispatchCallControl(cf *CallControlFrame, ch *ChannelState, isDM bool, targets []string) {
	if cf == nil || n.Transport == nil {
		return
	}
	if isDM {
		for _, target := range targets {
			_ = n.sendUnicastPacket(target, n.overlay.EncKey(target), PortCallCtrl, cf)
		}
		return
	}
	if ch != nil {
		for _, target := range targets {
			_ = n.sendGroupPacket(ch, target, PortCallCtrl, cf)
		}
	}
}
