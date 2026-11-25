package cotilla

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// RotateEpochKey ratchets the primary room to a new MLS epoch.
func (n *Node) RotateEpochKey() (*EpochCommit, error) {
	return n.RotateEpochKeyInChannel(n.RoomID)
}

// RotateEpochKeyInChannel ratchets channelID via an MLS Update commit.
func (n *Node) RotateEpochKeyInChannel(channelID string) (*EpochCommit, error) {
	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if err := n.checkCanCommitLocked(ch, channelID); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	mlsCommit, err := ch.mlsGroup.CreateUpdateCommit()
	if err != nil {
		n.mu.Unlock()
		return nil, fmt.Errorf("cotilla: treekem update commit: %w", err)
	}
	commit := n.finalizeLocalCommitLocked(ch, mlsCommit, nil, "", "", "epoch ratchet")
	n.mu.Unlock()

	n.publishCommit(ch, commit, "")
	return commit, nil
}

// EvictPeer locks targetAddr out of the primary room via an MLS Remove commit.
func (n *Node) EvictPeer(targetAddr, reason string) (*EpochCommit, error) {
	return n.EvictPeerInChannel(n.RoomID, targetAddr, reason)
}

// EvictPeerInChannel locks targetAddr out of channelID while isolating other channels and DMs.
func (n *Node) EvictPeerInChannel(channelID, targetAddr, reason string) (*EpochCommit, error) {
	if targetAddr == "" || targetAddr == n.Address() {
		return nil, errors.New("cotilla: cannot evict self or empty peer")
	}
	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if err := n.checkCanCommitLocked(ch, channelID); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	if ch.evictedPeers[targetAddr] > 0 {
		n.mu.Unlock()
		return nil, errors.New("cotilla: peer already evicted")
	}
	leaf := ch.mlsGroup.FindLeafByAddress(targetAddr)
	if leaf == -1 {
		n.mu.Unlock()
		return nil, fmt.Errorf("cotilla: peer %s not in MLS ratchet tree", targetAddr)
	}
	mlsCommit, err := ch.mlsGroup.CreateRemoveCommit(leaf)
	if err != nil {
		n.mu.Unlock()
		return nil, err
	}
	commit := n.finalizeLocalCommitLocked(ch, mlsCommit, nil, targetAddr, "", reason)
	ch.evictedPeers[targetAddr] = commit.EpochID
	delete(ch.peerKeyPackages, targetAddr)
	evictedAll := n.isEvictedEverywhereLocked(targetAddr)
	n.mu.Unlock()

	n.publishCommit(ch, commit, targetAddr)
	if evictedAll {
		n.overlay.RemovePassive(targetAddr)
		if n.Transport != nil {
			time.AfterFunc(150*time.Millisecond, func() { n.Transport.ClosePeer(targetAddr) })
		}
	}
	if n.Hooks.OnMemberEvicted != nil {
		n.Hooks.OnMemberEvicted(targetAddr, n.Address(), reason, commit.EpochID)
	}
	return commit, nil
}

func (n *Node) checkCanCommitLocked(ch *ChannelState, channelID string) error {
	if ch == nil {
		return fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	if ch.Kind == ChannelPublic || ch.IsAppDist {
		return errors.New("cotilla: cannot issue MLS commit on public/app-dist channel")
	}
	isGenesis := ch.creatorPub == "" && len(ch.peerInviters) == 0 && ch.channelInvite == nil && ch.currentEpoch == 0
	if ch.evictedPeers[n.Address()] > 0 || (!isGenesis && !n.isAdmittedMemberLocked(ch, n.Address())) {
		return errors.New("cotilla: evicted or unadmitted peer cannot issue commit")
	}
	return n.ensureMLSGroupLocked(ch)
}

func (n *Node) finalizeLocalCommitLocked(ch *ChannelState, mlsCommit *MLSCommit, mlsWelcome *MLSWelcome, evictedPeer, addedPeer, reason string) *EpochCommit {
	newEpoch := int64(mlsCommit.Epoch)
	var newKey RoomKey
	appKey := ch.mlsGroup.ApplicationSecretBytes()
	copy(newKey[:], appKey[:])
	zeroizeBytes(appKey[:])

	commit := &EpochCommit{
		EpochID:         newEpoch,
		RoomID:          ch.RoomID,
		Evictor:         n.Address(),
		EvictorEncPub:   n.ID.EncAddress(),
		EvictedPeer:     evictedPeer,
		AddedPeer:       addedPeer,
		Reason:          reason,
		MLSCommit:       mlsCommit,
		MLSWelcome:      mlsWelcome,
		CommitterInvite: ch.channelInvite.Redacted(),
		Timestamp:       time.Now().UnixMilli(),
	}
	commit.Signature = hex.EncodeToString(n.ID.Sign(CanonicalEpochCommitFromCommit(commit)))

	ch.currentEpoch = newEpoch
	if ch.joinedEpoch == 0 {
		ch.joinedEpoch = 1
	}
	if ch.memberJoinEpoch[n.Address()] == 0 {
		ch.memberJoinEpoch[n.Address()] = 1
	}
	if addedPeer != "" {
		ch.memberJoinEpoch[addedPeer] = newEpoch
	}
	n.recordEpochKeyLocked(ch, newEpoch, newKey)
	ch.RoomKey = newKey
	if ch.peerInviters[n.Address()] == "" {
		ch.peerInviters[n.Address()] = n.Address()
	}
	n.syncMemberJoinEpochsFromTreeLocked(ch)
	appendCommitHistoryLocked(ch, commit)
	return commit
}

func appendCommitHistoryLocked(ch *ChannelState, commit *EpochCommit) {
	ch.commitHistory = append(ch.commitHistory, commit)
	if len(ch.commitHistory) > maxRetainedEpochs {
		excess := len(ch.commitHistory) - maxRetainedEpochs
		copy(ch.commitHistory, ch.commitHistory[excess:])
		clear(ch.commitHistory[len(ch.commitHistory)-excess:])
		ch.commitHistory = ch.commitHistory[:maxRetainedEpochs]
	}
}

func (n *Node) publishCommit(ch *ChannelState, commit *EpochCommit, evictedPeer string) {
	n.notifyCallEpochTransition(ch.RoomID, evictedPeer)
	_ = n.sendBootstrapGroupPacket(ch, BroadcastAddr, PortEpochCommit, commit)
	if n.Hooks.OnEpochCommit != nil {
		n.Hooks.OnEpochCommit(commit)
	}
}

func (n *Node) isAdmissionCoordinatorInChannel(channelID string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	if ch == nil || ch.evictedPeers[n.Address()] > 0 || ch.currentEpoch == 0 {
		return false
	}
	if ch.mlsGroup != nil && ch.mlsGroup.Tree != nil {
		connected := make(map[string]bool)
		connected[n.Address()] = true
		if n.Transport != nil {
			for _, p := range n.Transport.Peers() {
				connected[p] = true
			}
		}
		// Find the primary (lowest-index non-evicted) leaf in the MLS tree.
		// If a higher-index leaf is not directly connected to the primary leaf yet
		// (e.g., it received the Welcome via a 2-hop relay), wait a short grace window
		// since the last epoch transition before failing over so we never split-brain.
		primaryAddr := ""
		for i := 0; i < ch.mlsGroup.Tree.NumLeaves; i++ {
			idx := 2 * i
			if idx >= len(ch.mlsGroup.Tree.Nodes) {
				break
			}
			node := ch.mlsGroup.Tree.Nodes[idx]
			if node == nil || node.Blank || node.SignPubHex == "" || ch.evictedPeers[node.SignPubHex] > 0 {
				continue
			}
			if primaryAddr == "" {
				primaryAddr = node.SignPubHex
				if primaryAddr == n.Address() {
					return true
				}
				if connected[primaryAddr] {
					return false
				}
				lastTS := ch.epochTimestamps[ch.currentEpoch]
				if lastTS > 0 && time.Now().UnixMilli()-lastTS < 4000 {
					return false
				}
			}
			if connected[node.SignPubHex] {
				return node.SignPubHex == n.Address()
			}
		}
	}
	if ch.creatorPub == n.Address() {
		return true
	}
	lowest := n.Address()
	if n.Transport != nil {
		for _, p := range n.Transport.Peers() {
			if ch.creatorPub != "" && p == ch.creatorPub {
				return false
			}
			if n.isAdmittedMemberLocked(ch, p) && ch.evictedPeers[p] == 0 && p < lowest {
				lowest = p
			}
		}
	}
	return lowest == n.Address()
}

func (n *Node) maybeAdmitMemberInChannel(channelID, targetAddr string, kp *KeyPackage, inviter string) {
	if targetAddr == "" || targetAddr == n.Address() || !n.isAdmissionCoordinatorInChannel(channelID) {
		return
	}
	go n.checkPendingAdmissionsInChannel(channelID)
}

func (n *Node) checkPendingAdmissionsInChannel(channelID string) {
	if !n.isAdmissionCoordinatorInChannel(channelID) {
		return
	}
	n.admissionMu.Lock()
	defer n.admissionMu.Unlock()

	failed := make(map[string]bool)
	for n.isAdmissionCoordinatorInChannel(channelID) {
		targetAddr, targetKP := n.nextPendingAdmission(channelID, failed)
		if targetAddr == "" {
			return
		}
		if _, err := n.admitMemberToTreeKEMInChannel(channelID, targetAddr, targetKP); err != nil {
			failed[targetAddr] = true
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (n *Node) nextPendingAdmission(channelID string, failed map[string]bool) (string, *KeyPackage) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		return "", nil
	}
	addrs := make([]string, 0, len(ch.peerKeyPackages))
	for p := range ch.peerKeyPackages {
		addrs = append(addrs, p)
	}
	sort.Strings(addrs)
	for _, p := range addrs {
		if p == n.Address() || ch.evictedPeers[p] > 0 || failed[p] || !n.isAdmittedMemberLocked(ch, p) {
			continue
		}
		kp := ch.peerKeyPackages[p]
		if kp == nil || !kp.Verify() || kp.SignPub != p {
			continue
		}
		needs := ch.memberJoinEpoch[p] == 0 || ch.mlsGroup == nil || ch.mlsGroup.FindLeafByAddress(p) == -1 ||
			(ch.admittedInitKeys[p] != ([32]byte{}) && ch.admittedInitKeys[p] != kp.InitKey)
		if needs {
			return p, kp
		}
	}
	return "", nil
}

func (n *Node) admitMemberToTreeKEMInChannel(channelID, targetAddr string, kp *KeyPackage) (*EpochCommit, error) {
	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if err := n.checkCanCommitLocked(ch, channelID); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	if kp == nil || !kp.Verify() || kp.SignPub != targetAddr || ch.evictedPeers[targetAddr] > 0 {
		n.mu.Unlock()
		return nil, errors.New("cotilla: invalid key package or evicted target")
	}
	mlsCommit, mlsWelcome, err := ch.mlsGroup.CreateAddCommit(kp)
	if err != nil {
		n.mu.Unlock()
		return nil, err
	}
	ch.admittedInitKeys[targetAddr] = kp.InitKey
	commit := n.finalizeLocalCommitLocked(ch, mlsCommit, mlsWelcome, "", targetAddr, "member admission")
	n.mu.Unlock()

	n.publishCommit(ch, commit, "")
	return commit, nil
}

func (n *Node) handleEpochCommit(from string, commit *EpochCommit) {
	n.handleEpochCommitInternal(from, commit, n.Cfg.ReplayWindow)
}

func (n *Node) handleEpochCommitInternal(from string, commit *EpochCommit, maxSkew time.Duration) {
	if commit == nil || commit.Evictor == "" || commit.Signature == "" || !withinWindow(commit.Timestamp, maxSkew) {
		return
	}
	if !Verify(commit.Evictor, CanonicalEpochCommitFromCommit(commit), commit.Signature) {
		return
	}
	n.mu.RLock()
	ch := n.channelLocked(commit.RoomID)
	if ch == nil || ch.IsAppDist || ch.Kind == ChannelPublic || commit.RoomID != ch.RoomID {
		n.mu.RUnlock()
		return
	}
	evicted := ch.evictedPeers[commit.Evictor] > 0
	admitted := n.isAdmittedMemberLocked(ch, commit.Evictor)
	joinedEpoch := ch.joinedEpoch
	n.mu.RUnlock()

	if evicted || (joinedEpoch > 0 && !admitted) {
		return
	}
	if commit.EvictedPeer == n.Address() {
		n.handleSelfEvictionCommit(ch, commit)
		return
	}
	if commit.MLSWelcome != nil && joinedEpoch == 0 && (commit.AddedPeer == "" || commit.AddedPeer == n.Address()) {
		n.handleWelcomeCommit(ch, commit)
		return
	}
	n.handleMemberCommit(ch, commit)
}

func (n *Node) handleSelfEvictionCommit(ch *ChannelState, commit *EpochCommit) {
	n.mu.Lock()
	err := n.applyMLSCommitLocked(ch, commit)
	if !errors.Is(err, ErrTreeKEMEvictedMember) {
		n.mu.Unlock()
		return
	}
	ch.evictedPeers[n.Address()] = commit.EpochID
	closeAll := n.isEvictedEverywhereLocked(n.Address())
	n.mu.Unlock()

	n.notifyCallEpochTransition(ch.RoomID, n.Address())
	if closeAll && n.Transport != nil {
		time.AfterFunc(100*time.Millisecond, func() {
			for _, p := range n.Transport.Peers() {
				n.Transport.ClosePeer(p)
			}
		})
	}
	if n.Hooks.OnMemberEvicted != nil {
		n.Hooks.OnMemberEvicted(n.Address(), commit.Evictor, commit.Reason, commit.EpochID)
	}
}

func (n *Node) handleWelcomeCommit(ch *ChannelState, commit *EpochCommit) {
	n.mu.RLock()
	authorized := n.isAuthorizedCommitterLocked(ch, commit)
	var initPriv *[32]byte
	if ch.myKeyPackage != nil {
		initPriv = ch.myKeyPackage.InitPriv
	}
	n.mu.RUnlock()
	if !authorized || commit.MLSWelcome.GroupID != ch.RoomID {
		return
	}
	grp, err := NewMLSGroupFromWelcome(n.ID, commit.MLSWelcome, initPriv)
	if err != nil || grp.GroupID != ch.RoomID {
		return
	}
	n.installWelcomeGroup(ch, grp, commit)
	n.notifyCallEpochTransition(ch.RoomID, "")
	if n.Hooks.OnEpochCommit != nil {
		n.Hooks.OnEpochCommit(commit)
	}
	go n.RequestCatchUpForChannel(ch.RoomID)
	go n.checkPendingAdmissionsInChannel(ch.RoomID)
}

func (n *Node) installWelcomeGroup(ch *ChannelState, grp *MLSGroup, commit *EpochCommit) {
	var newKey RoomKey
	appKey := grp.ApplicationSecretBytes()
	copy(newKey[:], appKey[:])
	zeroizeBytes(appKey[:])

	n.mu.Lock()
	defer n.mu.Unlock()
	ch.mlsGroup = grp
	ch.joinedEpoch = commit.EpochID
	ch.currentEpoch = commit.EpochID
	n.recordEpochKeyLocked(ch, commit.EpochID, newKey)
	ch.RoomKey = newKey
	ch.memberJoinEpoch[n.Address()] = commit.EpochID
	if ch.myKeyPackage != nil {
		ch.admittedInitKeys[n.Address()] = ch.myKeyPackage.InitKey
	}
	n.syncMemberJoinEpochsFromTreeLocked(ch)
	appendCommitHistoryLocked(ch, commit)
	n.drainPendingCommitsLocked(ch)
}

func (n *Node) handleMemberCommit(ch *ChannelState, commit *EpochCommit) {
	if commit.MLSCommit == nil {
		return
	}
	n.mu.Lock()
	if ch.joinedEpoch == 0 && commit.EpochID > 1 {
		if len(ch.pendingCommits) < maxPendingCommitsPerCh {
			ch.pendingCommits[commit.EpochID] = commit
		}
		n.mu.Unlock()
		return
	}
	if commit.EpochID <= ch.currentEpoch && ch.currentEpoch > 0 {
		n.mu.Unlock()
		return
	}
	if commit.EpochID > ch.currentEpoch+1 {
		if len(ch.pendingCommits) < maxPendingCommitsPerCh {
			ch.pendingCommits[commit.EpochID] = commit
		}
		n.mu.Unlock()
		go n.RequestCatchUpForChannel(ch.RoomID)
		return
	}
	if err := n.applyMLSCommitLocked(ch, commit); err != nil {
		n.mu.Unlock()
		return
	}
	n.drainPendingCommitsLocked(ch)
	newEpoch := ch.currentEpoch
	evictedAll := commit.EvictedPeer != "" && n.isEvictedEverywhereLocked(commit.EvictedPeer)
	n.mu.Unlock()

	n.notifyCallEpochTransition(ch.RoomID, commit.EvictedPeer)
	if commit.EvictedPeer != "" && n.Hooks.OnMemberEvicted != nil {
		n.Hooks.OnMemberEvicted(commit.EvictedPeer, commit.Evictor, commit.Reason, newEpoch)
	}
	if n.Hooks.OnEpochCommit != nil {
		n.Hooks.OnEpochCommit(commit)
	}
	if evictedAll && commit.EvictedPeer != n.Address() {
		n.overlay.RemovePassive(commit.EvictedPeer)
		if n.Transport != nil {
			time.AfterFunc(150*time.Millisecond, func() { n.Transport.ClosePeer(commit.EvictedPeer) })
		}
	}
	go n.checkPendingAdmissionsInChannel(ch.RoomID)
}

func (n *Node) drainPendingCommitsLocked(ch *ChannelState) {
	for {
		next := ch.pendingCommits[ch.currentEpoch+1]
		if next == nil {
			return
		}
		delete(ch.pendingCommits, ch.currentEpoch+1)
		if ch.evictedPeers[next.Evictor] > 0 || !n.isAdmittedMemberLocked(ch, next.Evictor) {
			return
		}
		if n.applyMLSCommitLocked(ch, next) != nil {
			return
		}
	}
}

func (n *Node) applyMLSCommitLocked(ch *ChannelState, commit *EpochCommit) error {
	if commit == nil || commit.MLSCommit == nil {
		return errors.New("cotilla: nil MLSCommit")
	}
	if ch.mlsGroup == nil {
		if err := n.ensureMLSGroupLocked(ch); err != nil {
			return err
		}
		if commit.EpochID == ch.currentEpoch+1 {
			ch.mlsGroup.Epoch = uint64(ch.currentEpoch)
		}
	}
	if err := ch.mlsGroup.ProcessCommit(commit.MLSCommit); err != nil {
		return err
	}
	var newKey RoomKey
	appKey := ch.mlsGroup.ApplicationSecretBytes()
	copy(newKey[:], appKey[:])
	zeroizeBytes(appKey[:])

	newEpoch := int64(commit.MLSCommit.Epoch)
	ch.currentEpoch = newEpoch
	if ch.joinedEpoch == 0 {
		ch.joinedEpoch = newEpoch
	}
	n.recordEpochKeyLocked(ch, newEpoch, newKey)
	ch.RoomKey = newKey
	if commit.AddedPeer != "" {
		ch.memberJoinEpoch[commit.AddedPeer] = newEpoch
	}
	if commit.MLSCommit.AddedPackage != nil {
		ch.admittedInitKeys[commit.MLSCommit.AddedPackage.SignPub] = commit.MLSCommit.AddedPackage.InitKey
	}
	if commit.EvictedPeer != "" {
		ch.evictedPeers[commit.EvictedPeer] = newEpoch
		delete(ch.peerKeyPackages, commit.EvictedPeer)
		delete(ch.admittedInitKeys, commit.EvictedPeer)
	}
	n.syncMemberJoinEpochsFromTreeLocked(ch)
	appendCommitHistoryLocked(ch, commit)
	return nil
}

func (n *Node) isAuthorizedCommitterLocked(ch *ChannelState, commit *EpochCommit) bool {
	if ch == nil || commit == nil {
		return false
	}
	if ch.creatorPub == "" && ch.channelInvite == nil && len(ch.peerInviters) == 0 {
		return true
	}
	if n.isAdmittedMemberLocked(ch, commit.Evictor) && ch.evictedPeers[commit.Evictor] == 0 {
		return true
	}
	return commit.CommitterInvite != nil &&
		commit.CommitterInvite.InviterPub == commit.Evictor &&
		commit.CommitterInvite.ParentInvite != nil &&
		n.verifyChannelInviteLocked(ch, commit.CommitterInvite, "") == nil
}
