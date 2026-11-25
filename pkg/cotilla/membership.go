package cotilla

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/hkdf"
)

func (n *Node) recordEpochKeyLocked(ch *ChannelState, epoch int64, key RoomKey) {
	ch.epochKeys[epoch] = key
	ch.epochTimestamps[epoch] = time.Now().UnixMilli()
	n.pruneExpiredEpochsLocked(ch)
}

const maxRetainedEpochs = 256

func (n *Node) pruneExpiredEpochsLocked(ch *ChannelState) {
	cutoff := time.Now().Add(-n.Cfg.MessageTTL).UnixMilli()
	for ep, ts := range ch.epochTimestamps {
		if ep == 0 || ep == ch.currentEpoch || ep == ch.joinedEpoch {
			continue
		}
		if ts < cutoff {
			if rk, ok := ch.epochKeys[ep]; ok {
				zeroizeBytes(rk[:])
			}
			delete(ch.epochKeys, ep)
			delete(ch.epochTimestamps, ep)
		}
	}
	if len(ch.epochKeys) > maxRetainedEpochs {
		epochs := make([]int64, 0, len(ch.epochKeys))
		for ep := range ch.epochKeys {
			if ep != 0 && ep != ch.currentEpoch && ep != ch.joinedEpoch {
				epochs = append(epochs, ep)
			}
		}
		sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
		excess := len(ch.epochKeys) - maxRetainedEpochs
		for i := 0; i < excess && i < len(epochs); i++ {
			ep := epochs[i]
			if rk, ok := ch.epochKeys[ep]; ok {
				zeroizeBytes(rk[:])
			}
			delete(ch.epochKeys, ep)
			delete(ch.epochTimestamps, ep)
		}
	}
}

func (n *Node) syncMemberJoinEpochsFromTreeLocked(ch *ChannelState) {
	if ch == nil || ch.mlsGroup == nil || ch.mlsGroup.Tree == nil {
		return
	}
	for i := 0; i < ch.mlsGroup.Tree.NumLeaves; i++ {
		leaf := ch.mlsGroup.Tree.Nodes[2*i]
		if leaf == nil || leaf.Blank || leaf.SignPubHex == "" {
			continue
		}
		if leaf.JoinedEpoch > 0 {
			ch.memberJoinEpoch[leaf.SignPubHex] = int64(leaf.JoinedEpoch)
		} else if ch.memberJoinEpoch[leaf.SignPubHex] == 0 {
			ch.memberJoinEpoch[leaf.SignPubHex] = 1
		}
	}
}

// InitGenesisEpoch establishes MLS Epoch 1 in the primary room.
func (n *Node) InitGenesisEpoch() error { return n.InitChannelMLS(n.RoomID) }

// InitChannelMLS establishes MLS Epoch 1 in channelID for the room creator.
func (n *Node) InitChannelMLS(channelID string) error {
	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		n.mu.Unlock()
		return fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	if ch.Kind == ChannelPublic || ch.IsAppDist {
		n.mu.Unlock()
		return errors.New("cotilla: MLS is only used on private channels")
	}
	if ch.currentEpoch > 0 {
		n.mu.Unlock()
		return nil
	}
	if ch.creatorPub == "" {
		ch.creatorPub = n.Address()
		ch.peerInviters[n.Address()] = n.Address()
	}
	if ch.mlsGroup == nil {
		grp, err := NewMLSGroup(ch.RoomID, n.ID)
		if err != nil {
			n.mu.Unlock()
			return err
		}
		ch.mlsGroup = grp
		ch.currentEpoch = 1
		ch.joinedEpoch = 1
		ch.memberJoinEpoch[n.Address()] = 1
		var key RoomKey
		appKey := grp.ApplicationSecretBytes()
		copy(key[:], appKey[:])
		zeroizeBytes(appKey[:])
		n.recordEpochKeyLocked(ch, 1, key)
		ch.RoomKey = key
	}
	n.mu.Unlock()

	n.notifyCallEpochTransition(channelID, "")
	go n.checkPendingAdmissionsInChannel(channelID)
	return nil
}

// BroadcastPeerInfo announces this node's credentials, KeyPackage, and redacted invite on joined private channels.
func (n *Node) BroadcastPeerInfo() {
	if n.Transport == nil {
		return
	}
	now := time.Now().UnixMilli()
	sig := hex.EncodeToString(n.ID.Sign(CanonicalPeerInfo(n.Address(), n.ID.EncAddress(), now)))

	n.mu.RLock()
	channels := make([]*ChannelState, 0, len(n.channels))
	for _, ch := range n.channels {
		if ch.Kind == ChannelPrivate && !ch.IsAppDist {
			channels = append(channels, ch)
		}
	}
	n.mu.RUnlock()

	for _, ch := range channels {
		n.mu.RLock()
		pi := PeerInfoFrame{
			RoomID:     ch.RoomID,
			SignPub:    n.Address(),
			EncPub:     n.ID.EncAddress(),
			Timestamp:  now,
			Signature:  sig,
			Invite:     ch.channelInvite.Redacted(),
			KeyPackage: ch.myKeyPackage,
		}
		n.mu.RUnlock()
		_ = n.sendBootstrapGroupPacket(ch, BroadcastAddr, PortGroupPeerInfo, &pi)
	}
}

func (n *Node) sendBootstrapGroupPacket(ch *ChannelState, to string, port Port, body any) error {
	ttl := n.Cfg.GroupTTL(ch.Kind)
	pkt, err := NewGroupPacket(n.ID, to, ch.ChannelHash, 0, ch.BootstrapKey, port, ttl, body)
	if err != nil {
		return err
	}
	if to != "" && to != BroadcastAddr {
		return n.sendPacket(to, pkt)
	}
	n.broadcastPacketToChannel(ch, pkt)
	return nil
}

func (n *Node) handlePeerInfo(from string, pi *PeerInfoFrame) {
	if !n.validatePeerInfo(pi) {
		return
	}
	n.overlay.SetEncKey(pi.SignPub, pi.EncPub)

	targetRoom := pi.RoomID
	if targetRoom == "" && pi.Invite != nil {
		targetRoom = pi.Invite.RoomID
	}
	n.mu.RLock()
	ch := n.channelLocked(targetRoom)
	evicted := ch != nil && ch.evictedPeers[pi.SignPub] > 0
	n.mu.RUnlock()

	if ch == nil || evicted {
		return
	}
	if !n.verifyPeerInfoInvite(ch, pi) {
		return
	}
	n.addChannelPeer(ch.RoomID, pi.SignPub)
	n.overlay.MarkChannelPeer(pi.SignPub, ch.ChannelHash)
	if n.Hooks.OnChannelDiscovered != nil {
		n.Hooks.OnChannelDiscovered(ch.RoomID, pi.SignPub)
	}
	n.recordPeerKeyPackage(ch, pi)
	if pi.SignPub != n.Address() && !n.shouldSkipDial(pi.SignPub) {
		desc := PeerDescriptor{SignPub: pi.SignPub, EncPub: pi.EncPub, ChannelHashes: []uint32{ch.ChannelHash}}
		n.overlay.AddPassive(desc)
		n.dialCandidates([]PeerDescriptor{desc})
	}

	inviter := ""
	if pi.Invite != nil {
		inviter = pi.Invite.InviterPub
	}
	go n.maybeAdmitMemberInChannel(ch.RoomID, pi.SignPub, pi.KeyPackage, inviter)
}

func (n *Node) validatePeerInfo(pi *PeerInfoFrame) bool {
	if pi == nil || pi.SignPub == "" || pi.EncPub == "" || !withinWindow(pi.Timestamp, n.Cfg.ReplayWindow) {
		return false
	}
	if !Verify(pi.SignPub, CanonicalPeerInfo(pi.SignPub, pi.EncPub, pi.Timestamp), pi.Signature) {
		return false
	}
	if pi.KeyPackage != nil && (!pi.KeyPackage.Verify() || pi.KeyPackage.SignPub != pi.SignPub) {
		return false
	}
	return true
}

func (n *Node) verifyPeerInfoInvite(ch *ChannelState, pi *PeerInfoFrame) bool {
	if pi.Invite == nil {
		return true
	}
	n.mu.RLock()
	already := ch.memberJoinEpoch[pi.SignPub] > 0 || (ch.mlsGroup != nil && ch.mlsGroup.FindLeafByAddress(pi.SignPub) != -1)
	n.mu.RUnlock()
	if already {
		return true
	}
	if err := n.verifyChannelInviteForChannelAndPeer(ch.RoomID, pi.Invite, pi.SignPub); err != nil {
		n.log("rejecting peer %s with invalid invite: %v", pi.SignPub, err)
		return false
	}
	n.mu.Lock()
	recordInviteProvenanceLocked(ch, pi.Invite, pi.SignPub)
	n.mu.Unlock()
	return true
}

func recordInviteProvenanceLocked(ch *ChannelState, inv *ChannelInvite, joiner string) {
	for curr := inv; curr != nil; curr = curr.ParentInvite {
		if ch.peerInviters[curr.InviterPub] == "" {
			if curr.ParentInvite != nil {
				ch.peerInviters[curr.InviterPub] = curr.ParentInvite.InviterPub
			} else {
				ch.peerInviters[curr.InviterPub] = curr.InviterPub
			}
		}
		if curr.ParentInvite == nil && ch.creatorPub == "" {
			ch.creatorPub = curr.InviterPub
		}
	}
	if joiner != "" && inv != nil {
		ch.peerInviters[joiner] = inv.InviterPub
	}
}

func (n *Node) recordPeerKeyPackage(ch *ChannelState, pi *PeerInfoFrame) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if pi.KeyPackage == nil {
		return
	}
	if ch.mlsGroup != nil && ch.mlsGroup.FindLeafByAddress(pi.SignPub) != -1 && ch.admittedInitKeys[pi.SignPub] == ([32]byte{}) {
		if ch.peerKeyPackages[pi.SignPub] == nil {
			ch.admittedInitKeys[pi.SignPub] = pi.KeyPackage.InitKey
		}
	}
	ch.peerKeyPackages[pi.SignPub] = pi.KeyPackage
}

// CreateChannelInvite generates a signed invitation for the primary room.
func (n *Node) CreateChannelInvite(ttl time.Duration) (*ChannelInvite, error) {
	return n.CreateChannelInviteForChannel(n.RoomID, ttl)
}

// CreateChannelInviteForChannel generates a signed invitation with provenance for channelID.
func (n *Node) CreateChannelInviteForChannel(channelID string, ttl time.Duration, inviteePub ...string) (*ChannelInvite, error) {
	if ttl <= 0 {
		ttl = n.Cfg.InviteTTL
	}
	targetInvitee := ""
	if len(inviteePub) > 0 {
		targetInvitee = inviteePub[0]
	}
	expiresAt := time.Now().UnixMilli() + ttl.Milliseconds()

	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		n.mu.Unlock()
		return nil, fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	if ch.evictedPeers[n.Address()] > 0 {
		n.mu.Unlock()
		return nil, errors.New("cotilla: evicted peer cannot create channel invites")
	}
	isGenesis := ch.creatorPub == "" && len(ch.peerInviters) == 0 && ch.channelInvite == nil
	if !isGenesis && !n.isAdmittedMemberLocked(ch, n.Address()) {
		n.mu.Unlock()
		return nil, errors.New("cotilla: unadmitted peer cannot create channel invites")
	}
	inv := n.signInviteLocked(ch, targetInvitee, expiresAt)
	if ch.creatorPub == "" && ch.channelInvite == nil {
		ch.creatorPub = n.Address()
		ch.peerInviters[n.Address()] = n.Address()
	}
	n.mu.Unlock()
	return inv, nil
}

func (n *Node) signInviteLocked(ch *ChannelState, targetInvitee string, expiresAt int64) *ChannelInvite {
	keyHash := InviteKeyCommitment(ch.BootstrapKey.String())
	canonical := CanonicalChannelInviteWithInvitee(ch.RoomID, n.Address(), targetInvitee, keyHash, ch.currentEpoch, expiresAt)
	return &ChannelInvite{
		RoomID:       ch.RoomID,
		InviterPub:   n.Address(),
		InviteePub:   targetInvitee,
		RoomKey:      ch.BootstrapKey.String(),
		RoomKeyHash:  keyHash,
		EpochID:      ch.currentEpoch,
		ExpiresAt:    expiresAt,
		Signature:    hex.EncodeToString(n.ID.Sign(canonical)),
		ParentInvite: ch.channelInvite,
	}
}

// VerifyChannelInvite validates a channel invitation's signature, expiry, and delegation chain.
func (n *Node) VerifyChannelInvite(inv *ChannelInvite) error {
	if inv == nil {
		return errors.New("cotilla: nil channel invite")
	}
	roomID := inv.RoomID
	if roomID == "" {
		roomID = n.RoomID
	}
	return n.verifyChannelInviteForChannelAndPeer(roomID, inv, "")
}

func (n *Node) verifyChannelInviteForChannelAndPeer(channelID string, inv *ChannelInvite, peerAddr string) error {
	if inv == nil {
		return errors.New("cotilla: nil channel invite")
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		return fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	return n.verifyChannelInviteLocked(ch, inv, peerAddr)
}

func (n *Node) verifyChannelInviteLocked(ch *ChannelState, inv *ChannelInvite, peerAddr string) error {
	if inv.RoomID != ch.RoomID {
		return fmt.Errorf("cotilla: channel invite room mismatch (%s vs %s)", inv.RoomID, ch.RoomID)
	}
	if peerAddr != "" && inv.InviteePub != "" && inv.InviteePub != peerAddr {
		return fmt.Errorf("cotilla: channel invite targeted at %s, not %s", inv.InviteePub, peerAddr)
	}
	rootCommit := inv.KeyCommitment()
	if rootCommit == "" {
		return errors.New("cotilla: channel invite missing key commitment")
	}
	now := time.Now().UnixMilli()
	foundAdmitted := false
	for curr, depth := inv, 0; curr != nil; curr, depth = curr.ParentInvite, depth+1 {
		if err := n.verifyInviteLinkLocked(ch, curr, rootCommit, now, depth); err != nil {
			return err
		}
		if n.isAdmittedMemberLocked(ch, curr.InviterPub) {
			foundAdmitted = true
		}
	}
	if !foundAdmitted {
		return errors.New("cotilla: inviter does not trace to an admitted member")
	}
	return nil
}

func (n *Node) verifyInviteLinkLocked(ch *ChannelState, curr *ChannelInvite, rootCommit string, now int64, depth int) error {
	if depth >= 32 {
		return errors.New("cotilla: invite delegation chain exceeds max depth")
	}
	if curr.RoomID != ch.RoomID || now > curr.ExpiresAt || curr.KeyCommitment() != rootCommit {
		return errors.New("cotilla: invite expired or room/key mismatch")
	}
	if ch.evictedPeers[curr.InviterPub] > 0 {
		return fmt.Errorf("cotilla: inviter %s has been evicted", curr.InviterPub)
	}
	if curr.ParentInvite != nil && curr.ParentInvite.InviteePub != "" && curr.ParentInvite.InviteePub != curr.InviterPub {
		return errors.New("cotilla: parent invite invitee mismatch")
	}
	canonical := CanonicalChannelInviteWithInvitee(curr.RoomID, curr.InviterPub, curr.InviteePub, curr.KeyCommitment(), curr.EpochID, curr.ExpiresAt)
	if !Verify(curr.InviterPub, canonical, curr.Signature) {
		return fmt.Errorf("cotilla: invalid invite signature from %s", curr.InviterPub)
	}
	return nil
}

// SetChannelInvite sets this node's invite for the primary channel.
func (n *Node) SetChannelInvite(inv *ChannelInvite) {
	roomID := n.RoomID
	if inv != nil && inv.RoomID != "" {
		roomID = inv.RoomID
	}
	n.SetChannelInviteForChannel(roomID, inv)
}

// SetChannelInviteForChannel associates an invite with channelID and announces PeerInfo.
func (n *Node) SetChannelInviteForChannel(channelID string, inv *ChannelInvite) {
	n.mu.Lock()
	ch := n.channelLocked(channelID)
	if ch != nil {
		ch.channelInvite = inv
		recordInviteProvenanceLocked(ch, inv, "")
	}
	hasTransport := n.Transport != nil
	n.mu.Unlock()
	if inv != nil && hasTransport {
		go n.BroadcastPeerInfo()
	}
}

// ChannelInvite returns the primary channel's active invite.
func (n *Node) ChannelInvite() *ChannelInvite {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.channelInvite
}

// InvitedBy returns the inviter of peerAddr in the primary channel.
func (n *Node) InvitedBy(peerAddr string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.peerInviters[peerAddr]
}

// IsAdmittedMember reports whether addr is admitted in the primary channel.
func (n *Node) IsAdmittedMember(addr string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.isAdmittedMemberLocked(n.ChannelState, addr)
}

func (n *Node) isAdmittedMemberLocked(ch *ChannelState, addr string) bool {
	if ch == nil || addr == "" || ch.evictedPeers[addr] > 0 {
		return false
	}
	if ch.Kind == ChannelPublic || ch.IsAppDist {
		return true
	}
	if ch.mlsGroup != nil && ch.mlsGroup.FindLeafByAddress(addr) != -1 {
		return true
	}
	if ch.creatorPub != "" || len(ch.peerInviters) > 0 || ch.channelInvite != nil || ch.currentEpoch > 0 {
		return addr == ch.creatorPub || ch.peerInviters[addr] != "" ||
			(ch.channelInvite != nil && ch.channelInvite.InviterPub == addr) ||
			(addr == n.Address() && ch.channelInvite != nil)
	}
	return true
}

// IsPeerEvicted reports whether addr has been evicted from the primary channel.
func (n *Node) IsPeerEvicted(addr string) bool { return n.IsPeerEvictedInChannel(n.RoomID, addr) }

// IsPeerEvictedInChannel reports whether addr has been evicted from channelID.
func (n *Node) IsPeerEvictedInChannel(channelID, addr string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	return ch != nil && ch.evictedPeers[addr] > 0
}

// CurrentEpoch returns the primary room's current epoch counter.
func (n *Node) CurrentEpoch() int64 { return n.ChannelCurrentEpoch(n.RoomID) }

// ChannelCurrentEpoch returns channelID's current epoch counter.
func (n *Node) ChannelCurrentEpoch(channelID string) int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		return 0
	}
	return ch.currentEpoch
}

// ChannelRingBuffer returns the RingBuffer for channelID.
func (n *Node) ChannelRingBuffer(channelID string) *RingBuffer {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		return nil
	}
	return ch.RingBuffer
}

// JoinedEpoch returns the epoch when this node joined the primary channel.
func (n *Node) JoinedEpoch() int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.joinedEpoch
}

// MemberJoinEpoch returns the epoch at which addr joined the primary channel.
func (n *Node) MemberJoinEpoch(addr string) int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.memberJoinEpoch[addr]
}

func (n *Node) ensureMLSGroupLocked(ch *ChannelState) error {
	if ch.mlsGroup != nil {
		return nil
	}
	isGenesis := ch.creatorPub == "" && len(ch.peerInviters) == 0 && ch.channelInvite == nil && ch.currentEpoch == 0
	if ch.evictedPeers[n.Address()] > 0 || (!isGenesis && !n.isAdmittedMemberLocked(ch, n.Address())) {
		return errors.New("cotilla: unadmitted or evicted peer cannot initialize MLS group")
	}
	allAddrs, peerKeys := n.collectGenesisLeavesLocked(ch)
	tree, myLeafIdx := n.buildGenesisTreeLocked(ch, allAddrs, peerKeys)
	var initSecret [32]byte
	if ch.currentEpoch == 0 {
		copy(initSecret[:], hkdf.Extract(sha256.New, ch.RoomKey[:], []byte("cotilla-genesis-init-secret")))
	}
	ch.mlsGroup = &MLSGroup{
		GroupID:       ch.RoomID,
		Epoch:         uint64(ch.currentEpoch),
		MyLeafIndex:   myLeafIdx,
		LocalIdentity: n.ID,
		Tree:          tree,
		InitSecret:    initSecret,
	}
	return nil
}

func (n *Node) collectGenesisLeavesLocked(ch *ChannelState) ([]string, map[string][32]byte) {
	encKeys := n.overlay.EncKeysSnapshot()
	peerKeys := make(map[string][32]byte, 1+len(encKeys))
	if ch.myKeyPackage != nil && ch.myKeyPackage.InitPriv != nil {
		peerKeys[n.Address()] = ch.myKeyPackage.InitKey
	} else {
		peerKeys[n.Address()] = n.ID.EncPub
	}
	allAddrs := []string{n.Address()}
	for peerAddr, encHex := range encKeys {
		if peerAddr == n.Address() || ch.evictedPeers[peerAddr] > 0 || !n.isAdmittedMemberLocked(ch, peerAddr) {
			continue
		}
		if kp := ch.peerKeyPackages[peerAddr]; kp != nil && kp.Verify() && kp.SignPub == peerAddr {
			peerKeys[peerAddr] = kp.InitKey
			allAddrs = append(allAddrs, peerAddr)
		} else if parsed, err := ParseEncPub(encHex); err == nil {
			peerKeys[peerAddr] = parsed
			allAddrs = append(allAddrs, peerAddr)
		}
	}
	sort.Strings(allAddrs)
	return allAddrs, peerKeys
}

func (n *Node) buildGenesisTreeLocked(ch *ChannelState, allAddrs []string, peerKeys map[string][32]byte) (*RatchetTree, int) {
	tree := NewRatchetTree(len(allAddrs))
	myLeafIdx := -1
	for idx, addr := range allAddrs {
		leaf := tree.Nodes[2*idx]
		leaf.Blank = false
		leaf.PublicKey = peerKeys[addr]
		leaf.SignPubHex = addr
		ch.admittedInitKeys[addr] = peerKeys[addr]
		if addr == n.Address() {
			myLeafIdx = idx
			leaf.Identity = n.ID
			priv := n.ID.EncPriv
			if ch.myKeyPackage != nil && ch.myKeyPackage.InitPriv != nil {
				priv = *ch.myKeyPackage.InitPriv
			}
			leaf.PrivateKey = &priv
		} else if ch.memberJoinEpoch[addr] == 0 {
			ch.memberJoinEpoch[addr] = 1
		}
	}
	return tree, myLeafIdx
}
