package cotilla

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SendCallSignal encrypts a pairwise secondary WebRTC signal using Noise_IK and routes it via Packet.
func (n *Node) SendCallSignal(scopeID, target, kind, payload string) error {
	if scopeID == "" {
		scopeID = n.RoomID
	}
	if target == "" || target == n.Address() {
		return errors.New("cotilla: invalid call signal target")
	}
	isDM, epoch, callID, encPubHex, err := n.validateOutboundCallSignal(scopeID, target, kind)
	if err != nil {
		return err
	}
	frame, err := n.buildCallSignalFrame(scopeID, target, kind, payload, callID, encPubHex, epoch, isDM)
	if err != nil {
		return err
	}
	return n.sendUnicastPacket(target, encPubHex, PortCallSig, frame)
}

func (n *Node) validateOutboundCallSignal(scopeID, target, kind string) (bool, int64, string, string, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	sess := n.activeCalls[scopeID]
	if (sess == nil || !sess.Joined) && kind != "bye" {
		return false, 0, "", "", fmt.Errorf("cotilla: local node not joined to call in %s", scopeID)
	}
	var isDM bool
	var epoch int64
	var callID string
	if sess != nil {
		isDM, epoch, callID = sess.IsDM, sess.Epoch, sess.CallID
	} else if n.dmScopes[scopeID] != nil {
		isDM = true
	}

	encPub := n.overlay.EncKey(target)
	if encPub == "" && sess != nil && sess.Peers[target] != nil {
		encPub = sess.Peers[target].SenderEncPub
	}
	if isDM {
		if dm := n.dmScopes[scopeID]; dm == nil || dm.PeerAddr != target {
			return false, 0, "", "", errors.New("cotilla: call signal target is not the DM partner")
		}
		return true, epoch, callID, encPub, nil
	}
	ch := n.channelLocked(scopeID)
	if ch == nil || ch.evictedPeers[n.Address()] > 0 || ch.evictedPeers[target] > 0 {
		return false, 0, "", "", errors.New("cotilla: unauthorized or evicted call signal participant")
	}
	if ch.mlsGroup != nil && ch.mlsGroup.FindLeafByAddress(target) < 0 {
		return false, 0, "", "", fmt.Errorf("cotilla: target %s not in MLS group %s", target, scopeID)
	}
	return false, ch.currentEpoch, callID, encPub, nil
}

func (n *Node) buildCallSignalFrame(scopeID, target, kind, payload, callID, encPubHex string, epoch int64, isDM bool) (*CallSignalFrame, error) {
	targetEnc, err := ParseEncPub(encPubHex)
	if err != nil {
		return nil, fmt.Errorf("cotilla: missing or invalid X25519 key for %s: %w", target, err)
	}
	innerBytes, err := json.Marshal(CallSignalPayload{
		ScopeID: scopeID, IsDM: isDM, CallID: callID, Epoch: epoch, Kind: kind, Payload: payload, From: n.Address(),
	})
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	ePub, nonce, ct, err := EncryptDirectInvite(n.ID, targetEnc, innerBytes, CanonicalCallSignalAAD(n.Address(), target, now))
	if err != nil {
		return nil, err
	}
	ePubHex := hex.EncodeToString(ePub[:])
	nonceHex := hex.EncodeToString(nonce)
	ctHex := hex.EncodeToString(ct)
	sig := hex.EncodeToString(n.ID.Sign(CanonicalCallSignal(n.Address(), n.ID.EncAddress(), target, ePubHex, nonceHex, ctHex, now)))
	return &CallSignalFrame{
		From: n.Address(), FromEncPub: n.ID.EncAddress(), Target: target,
		EphemeralPub: ePubHex, Nonce: nonceHex, Ciphertext: ctHex, Timestamp: now, Signature: sig,
	}, nil
}

func (n *Node) handleCallControl(from string, cf *CallControlFrame) {
	if cf == nil || cf.AuthorPub == "" || cf.ScopeID == "" || !withinWindow(cf.Timestamp, n.Cfg.ReplayWindow) {
		return
	}
	if !Verify(cf.AuthorPub, CanonicalCallControl(cf.ScopeID, cf.AuthorPub, cf.Nonce, cf.Ciphertext, cf.EpochID, cf.Timestamp, cf.IsDM), cf.Signature) {
		return
	}
	if n.packetCache.MarkSeen(fmt.Sprintf("cctrl:%s:%s:%d:%s", cf.ScopeID, cf.AuthorPub, cf.Timestamp, cf.Nonce)) {
		return
	}
	decKey, leafIdx, ok := n.resolveCallControlDecryptKey(cf)
	if !ok {
		return
	}
	payload, err := decryptCallControlFrame(cf, decKey)
	if err != nil {
		return
	}
	n.applyCallPresence(from, cf, payload, leafIdx)
}

func (n *Node) resolveCallControlDecryptKey(cf *CallControlFrame) (RoomKey, int, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if cf.IsDM {
		dm := n.dmScopes[cf.ScopeID]
		if dm == nil || dm.PeerAddr != cf.AuthorPub {
			return RoomKey{}, -1, false
		}
		return dm.RoomKey, -1, true
	}
	ch := n.channelLocked(cf.ScopeID)
	if ch == nil || ch.evictedPeers[cf.AuthorPub] > 0 || !n.isAdmittedMemberLocked(ch, cf.AuthorPub) {
		return RoomKey{}, -1, false
	}
	leafIdx := -1
	if ch.mlsGroup != nil {
		leafIdx = ch.mlsGroup.FindLeafByAddress(cf.AuthorPub)
		if leafIdx < 0 {
			return RoomKey{}, -1, false
		}
	}
	key, ok := ch.epochKeys[cf.EpochID]
	if !ok {
		key = ch.RoomKey
	}
	return key, leafIdx, true
}

func decryptCallControlFrame(cf *CallControlFrame, decKey RoomKey) (*CallPresencePayload, error) {
	nonce, err := hex.DecodeString(cf.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(cf.Ciphertext)
	if err != nil {
		return nil, err
	}
	pt, err := DecryptRoomPayload(decKey, nonce, ct, CanonicalCallControlAAD(cf.ScopeID, cf.AuthorPub, cf.EpochID, cf.Timestamp, cf.IsDM))
	if err != nil {
		return nil, err
	}
	var payload CallPresencePayload
	if err := json.Unmarshal(pt, &payload); err != nil || payload.ScopeID != cf.ScopeID || payload.IsDM != cf.IsDM {
		return nil, errors.New("cotilla: invalid call presence payload")
	}
	return &payload, nil
}

func (n *Node) applyCallPresence(from string, cf *CallControlFrame, payload *CallPresencePayload, leafIdx int) {
	if payload.SenderEncPub != "" {
		n.overlay.SetEncKey(cf.AuthorPub, payload.SenderEncPub)
	}
	n.mu.Lock()
	if n.callRoster[cf.ScopeID] == nil {
		n.callRoster[cf.ScopeID] = make(map[string]*CallPeerState)
	}
	sess := n.activeCalls[cf.ScopeID]
	var needPeerClose bool
	var replyCF *CallControlFrame
	var replyCh *ChannelState
	var refreshedBundle *SFrameKeyBundle

	if payload.Action == "leave" {
		delete(n.callRoster[cf.ScopeID], cf.AuthorPub)
		if sess != nil && sess.Peers[cf.AuthorPub] != nil {
			delete(sess.Peers, cf.AuthorPub)
			needPeerClose = true
		}
	} else {
		replyCF, replyCh, refreshedBundle = n.upsertCallPeerLocked(from, cf, payload, sess, leafIdx)
	}
	sessJoined := sess != nil && sess.Joined
	n.mu.Unlock()

	if refreshedBundle != nil && n.Hooks.OnSFrameKeysUpdated != nil {
		n.Hooks.OnSFrameKeysUpdated(cf.ScopeID, cf.IsDM, refreshedBundle)
	}
	if needPeerClose && n.Hooks.OnCallPeerClosed != nil {
		n.Hooks.OnCallPeerClosed(cf.ScopeID, cf.AuthorPub)
	}
	if replyCF != nil {
		n.dispatchCallControl(replyCF, replyCh, cf.IsDM, []string{cf.AuthorPub})
	}
	if sessJoined && n.Hooks.OnCallPresence != nil {
		n.Hooks.OnCallPresence(cf.ScopeID, cf.IsDM, cf.AuthorPub, payload)
	}
}

func (n *Node) upsertCallPeerLocked(from string, cf *CallControlFrame, payload *CallPresencePayload, sess *callSession, leafIdx int) (*CallControlFrame, *ChannelState, *SFrameKeyBundle) {
	alreadyIn := sess != nil && sess.Peers[cf.AuthorPub] != nil
	resolvedLeaf := payload.LeafIndex
	if leafIdx >= 0 {
		resolvedLeaf = leafIdx
	}
	st := &CallPeerState{
		Address: cf.AuthorPub, CallID: payload.CallID, LeafIndex: resolvedLeaf, Epoch: cf.EpochID,
		SenderEncPub: payload.SenderEncPub, Audio: payload.Audio, Video: payload.Video, Screen: payload.Screen, LastSeen: time.Now(),
	}
	n.callRoster[cf.ScopeID][cf.AuthorPub] = st
	if sess == nil || !sess.Joined {
		return nil, nil, nil
	}
	cp := *st
	sess.Peers[cf.AuthorPub] = &cp

	var refreshed *SFrameKeyBundle
	if !cf.IsDM && sess.Epoch == 0 && !alreadyIn {
		if b, _, err := n.buildScopeSFrameBundleLocked(cf.ScopeID, false); err == nil {
			refreshed = b
		}
	}
	if payload.Action == "join" && (!alreadyIn || from != "") {
		selfPayload := n.buildCallPresencePayload("update", sess)
		cfReply, chReply, _, _ := n.sealCallControlLocked(cf.ScopeID, sess.IsDM, &selfPayload)
		return cfReply, chReply, refreshed
	}
	return nil, nil, refreshed
}

func (n *Node) handleCallSignal(from string, frame *CallSignalFrame) {
	if frame == nil || frame.Target != n.Address() || frame.From == "" || !withinWindow(frame.Timestamp, n.Cfg.ReplayWindow) {
		return
	}
	if !Verify(frame.From, CanonicalCallSignal(frame.From, frame.FromEncPub, frame.Target, frame.EphemeralPub, frame.Nonce, frame.Ciphertext, frame.Timestamp), frame.Signature) {
		return
	}
	if n.packetCache.MarkSeen(fmt.Sprintf("csig:%s:%s:%d:%s", frame.From, frame.Target, frame.Timestamp, frame.Nonce)) {
		return
	}
	sig, err := n.decryptCallSignal(frame)
	if err != nil || !n.isAuthorizedCallSignal(frame.From, sig) {
		return
	}
	if frame.FromEncPub != "" {
		n.overlay.SetEncKey(frame.From, frame.FromEncPub)
	}
	if n.Hooks.OnCallSignal != nil {
		n.Hooks.OnCallSignal(sig)
	}
}

func (n *Node) decryptCallSignal(frame *CallSignalFrame) (*CallSignalPayload, error) {
	ePub, err := ParseEncPub(frame.EphemeralPub)
	if err != nil {
		return nil, err
	}
	senderEnc, err := ParseEncPub(frame.FromEncPub)
	if err != nil {
		return nil, err
	}
	nonce, err := hex.DecodeString(frame.Nonce)
	if err != nil {
		return nil, err
	}
	ct, err := hex.DecodeString(frame.Ciphertext)
	if err != nil {
		return nil, err
	}
	pt, err := DecryptDirectInvite(n.ID, senderEnc, ePub, nonce, ct, CanonicalCallSignalAAD(frame.From, frame.Target, frame.Timestamp))
	if err != nil {
		return nil, err
	}
	var sig CallSignalPayload
	if err := json.Unmarshal(pt, &sig); err != nil || sig.ScopeID == "" || (sig.From != "" && sig.From != frame.From) {
		return nil, errors.New("cotilla: invalid call signal payload")
	}
	sig.From = frame.From
	return &sig, nil
}

func (n *Node) isAuthorizedCallSignal(sender string, sig *CallSignalPayload) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	sess := n.activeCalls[sig.ScopeID]
	if sess == nil || !sess.Joined || sig.IsDM != sess.IsDM {
		return false
	}
	if sig.IsDM {
		dm := n.dmScopes[sig.ScopeID]
		return dm != nil && dm.PeerAddr == sender
	}
	ch := n.channelLocked(sig.ScopeID)
	if ch == nil || ch.evictedPeers[n.Address()] > 0 || ch.evictedPeers[sender] > 0 {
		return false
	}
	if !n.isAdmittedMemberLocked(ch, sender) || sig.Epoch != ch.currentEpoch {
		return false
	}
	return ch.mlsGroup == nil || ch.mlsGroup.FindLeafByAddress(sender) >= 0
}

func (n *Node) syncCallPresenceToPeer(target string) {
	if target == "" || n.IsGatewayPeer(target) {
		return
	}
	n.mu.RLock()
	type item struct {
		cf *CallControlFrame
		ch *ChannelState
		dm bool
	}
	var list []item
	for scopeID, sess := range n.activeCalls {
		if sess == nil || !sess.Joined {
			continue
		}
		payload := n.buildCallPresencePayload("update", sess)
		if cf, ch, _, err := n.sealCallControlLocked(scopeID, sess.IsDM, &payload); err == nil {
			list = append(list, item{cf: cf, ch: ch, dm: sess.IsDM})
		}
	}
	n.mu.RUnlock()
	for _, it := range list {
		if it.dm {
			_ = n.sendUnicastPacket(target, "", PortCallCtrl, it.cf)
		} else if it.ch != nil {
			_ = n.sendGroupPacket(it.ch, target, PortCallCtrl, it.cf)
		}
	}
}

func (n *Node) notifyCallEpochTransition(scopeID, evictedPeer string) {
	if scopeID == "" {
		return
	}
	if evictedPeer == n.Address() {
		_ = n.LeaveCall(scopeID)
		n.mu.Lock()
		delete(n.callRoster, scopeID)
		n.mu.Unlock()
		if n.Hooks.OnCallPeerClosed != nil {
			n.Hooks.OnCallPeerClosed(scopeID, "")
		}
		return
	}
	var bundle *SFrameKeyBundle
	var isDM bool
	var closePeers []string

	n.mu.Lock()
	if evictedPeer != "" {
		delete(n.callRoster[scopeID], evictedPeer)
		if sess := n.activeCalls[scopeID]; sess != nil && sess.Peers[evictedPeer] != nil {
			delete(sess.Peers, evictedPeer)
			closePeers = append(closePeers, evictedPeer)
		}
	}
	if sess := n.activeCalls[scopeID]; sess != nil && sess.Joined {
		if b, resolvedDM, err := n.buildScopeSFrameBundleLocked(scopeID, sess.IsDM); err == nil {
			bundle, isDM = b, resolvedDM
			sess.Epoch, sess.MyLeaf = int64(b.Epoch), b.LeafIndex
		}
	}
	n.mu.Unlock()

	if n.Hooks.OnCallPeerClosed != nil {
		for _, p := range closePeers {
			n.Hooks.OnCallPeerClosed(scopeID, p)
		}
	}
	if bundle != nil && n.Hooks.OnSFrameKeysUpdated != nil {
		n.Hooks.OnSFrameKeysUpdated(scopeID, isDM, bundle)
	}
}
