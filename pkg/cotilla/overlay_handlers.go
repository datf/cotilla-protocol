package cotilla

import (
	"encoding/hex"
	"fmt"
	"time"
)

// DiscoverPeers initiates an expanding-ring peer_request broadcast to BroadcastAddr.
// Starts with InitialBroadcastTTL to InitialBroadcastFanout peers, doubling both every 2*TTL if unanswered.
func (n *Node) DiscoverPeers() {
	if n.Transport == nil {
		return
	}
	n.broadcaster.Start("peer_request", n.Cfg.MaxBroadcastTTL, func(ttl, fanout int) {
		req := PeerRequestPayload{
			WantCount:     n.Cfg.MinActivePeers,
			KnownPeers:    n.liveNonGatewayPeers(),
			ChannelHashes: n.activeChannelHashes(),
		}
		pkt, err := NewPlainPacket(n.ID, BroadcastAddr, PortPeerRequest, ttl, req)
		if err != nil {
			return
		}
		n.broadcastPacketWithFanout(pkt, fanout)
	})
}

// QueryPeers is an alias for DiscoverPeers for convenient caller ergonomics.
func (n *Node) QueryPeers() {
	n.DiscoverPeers()
}

func (n *Node) handlePeerRequest(from string, pkt *Packet, req *PeerRequestPayload) {
	if pkt.From == n.Address() {
		return
	}
	want := req.WantCount
	if want <= 0 || want > n.Cfg.MaxPeers {
		want = n.Cfg.MinActivePeers
	}
	known := make(map[string]bool, len(req.KnownPeers))
	for _, k := range req.KnownPeers {
		known[k] = true
	}

	candidates := n.overlay.SampleDescriptors(want*2, pkt.From)
	filtered := make([]PeerDescriptor, 0, want)
	for _, d := range candidates {
		if !known[d.SignPub] && d.SignPub != n.Address() {
			filtered = append(filtered, d)
			if len(filtered) >= want {
				break
			}
		}
	}
	// Always include self if not already directly connected to the requester
	if from != pkt.From {
		filtered = append(filtered, n.selfDescriptor())
	}

	res := PeerResponsePayload{
		RequestID: pkt.ID,
		Peers:     filtered,
	}
	_ = n.sendUnicastPacket(pkt.From, pkt.FromEnc, PortPeerResponse, res)
}

func (n *Node) handlePeerResponse(from string, pkt *Packet, res *PeerResponsePayload) {
	if len(res.Peers) == 0 {
		return
	}
	var newAddrs []string
	for _, desc := range res.Peers {
		if desc.SignPub == "" || desc.SignPub == n.Address() || n.IsGatewayPeer(desc.SignPub) {
			continue
		}
		if n.isEvictedEverywhere(desc.SignPub) {
			continue
		}
		n.overlay.AddPassive(desc)
		newAddrs = append(newAddrs, desc.SignPub)
	}
	if len(newAddrs) > 0 {
		n.broadcaster.MarkSatisfied("peer_request")
		if n.Hooks.OnPeerCandidate != nil {
			n.Hooks.OnPeerCandidate(newAddrs)
		}
		n.dialCandidates(res.Peers)
	}
}

func (n *Node) dialCandidates(candidates []PeerDescriptor) {
	rtc, ok := n.Transport.(WebRTCTransport)
	if !ok || len(candidates) == 0 {
		return
	}
	activeCount := len(n.overlay.ActivePeers())
	for _, cand := range candidates {
		if activeCount >= n.Cfg.MaxPeers {
			return
		}
		if n.shouldSkipDial(cand.SignPub) {
			continue
		}
		activeCount++
		go n.initiateWebRTCOffer(rtc, cand.SignPub, cand.EncPub)
	}
}

func (n *Node) shouldSkipDial(addr string) bool {
	if addr == "" || addr == n.Address() || n.IsGatewayPeer(addr) || n.isEvictedEverywhere(addr) {
		return true
	}
	if checker, ok := n.Transport.(interface{ HasActiveOrPending(string) bool }); ok && checker.HasActiveOrPending(addr) {
		return true
	}
	for _, p := range n.Transport.Peers() {
		if p == addr {
			return true
		}
	}
	return false
}

func (n *Node) initiateWebRTCOffer(rtc WebRTCTransport, targetSign, targetEnc string) {
	sdp, err := rtc.CreateOffer(targetSign)
	if err != nil {
		return
	}
	sig := WebRTCSignalPayload{Kind: "offer", SDP: sdp}
	_ = n.sendUnicastPacket(targetSign, targetEnc, PortWebRTCSignal, sig)
}

func (n *Node) handleWebRTCSignal(from string, pkt *Packet, sig *WebRTCSignalPayload) {
	if pkt.From == n.Address() || n.isEvictedEverywhere(pkt.From) {
		return
	}
	rtc, ok := n.Transport.(WebRTCTransport)
	if !ok {
		return
	}
	switch sig.Kind {
	case "offer":
		// Polite/impolite glare resolution: if we already have an outbound pending offer
		// to pkt.From and are not yet connected, the lexicographically larger address wins.
		if !n.hasConnectedPeer(pkt.From) {
			if checker, ok := n.Transport.(interface{ HasActiveOrPending(string) bool }); ok && checker.HasActiveOrPending(pkt.From) {
				if n.Address() > pkt.From {
					return
				}
			}
		}
		go func() {
			ansSDP, err := rtc.AcceptOffer(pkt.From, sig.SDP)
			if err != nil {
				return
			}
			reply := WebRTCSignalPayload{Kind: "answer", SDP: ansSDP}
			_ = n.sendUnicastPacket(pkt.From, pkt.FromEnc, PortWebRTCSignal, reply)
		}()
	case "answer":
		_ = rtc.AcceptAnswer(pkt.From, sig.SDP)
	}
}

func (n *Node) hasConnectedPeer(addr string) bool {
	if n.Transport == nil {
		return false
	}
	for _, p := range n.Transport.Peers() {
		if p == addr {
			return true
		}
	}
	return false
}

func (n *Node) handleRootIntro(from string, ri *RootIntroFrame) {
	n.mu.Lock()
	if ri.IsAnchor {
		n.anchorPeers[n.Address()] = true
	}
	n.fallbackMode = ri.Fallback
	for _, a := range ri.AnchorPeers {
		if a != n.Address() && !n.IsGatewayPeer(a) {
			n.anchorPeers[a] = true
			n.overlay.MarkAnchor(a, true)
		}
	}
	n.mu.Unlock()

	if n.Hooks.OnAnchorIntro != nil {
		n.Hooks.OnAnchorIntro(ri.AnchorPeers, ri.Fallback)
	}
	descs := ri.Anchors
	if len(descs) == 0 {
		for _, a := range ri.AnchorPeers {
			descs = append(descs, PeerDescriptor{SignPub: a})
		}
	}
	for _, d := range descs {
		n.overlay.AddPassive(d)
	}
	n.dialCandidates(descs)
}

// SolicitAnchors asks healthy non-anchor peers to register with their signaling server.
func (n *Node) SolicitAnchors(needed int, excludeAnchors []string) {
	if n.Transport == nil {
		return
	}
	if needed <= 0 {
		needed = 1
	}
	excl := append([]string{n.Address()}, excludeAnchors...)
	solicit := AnchorSolicitFrame{
		QueryID: RandomID(),
		Sender:  n.Address(),
		Needed:  needed,
		Exclude: excl,
	}
	pkt, err := NewPlainPacket(n.ID, BroadcastAddr, PortAnchorSolicit, n.Cfg.GossipTTL, solicit)
	if err != nil {
		return
	}
	n.broadcastPacketWithFanout(pkt, n.Cfg.GossipFanout)
}

func (n *Node) handleAnchorSolicit(from string, as *AnchorSolicitFrame) {
	if n.isEvictedEverywhere(n.Address()) || n.isEvictedEverywhere(as.Sender) {
		return
	}
	for _, e := range as.Exclude {
		if e == n.Address() {
			return
		}
	}
	needed := as.Needed
	if needed <= 0 {
		needed = 1
	}
	if n.Hooks.OnAnchorSolicit != nil {
		go n.Hooks.OnAnchorSolicit(needed)
	}
}

func (n *Node) stepHyParViewShuffle() {
	active := n.overlay.ActivePeers()
	if len(active) == 0 {
		return
	}
	target := active[time.Now().UnixNano()%int64(len(active))]
	sample := n.overlay.SampleDescriptors(n.Cfg.ShuffleFanout, target)
	hops := n.Cfg.ShuffleTTL - 1
	if hops < 0 {
		hops = 0
	}
	payload := ShufflePayload{
		Origin:        n.selfDescriptor(),
		Peers:         sample,
		RemainingHops: hops,
		RequestID:     RandomID(),
	}
	_ = n.sendUnicastPacket(target, n.overlay.EncKey(target), PortHyParViewShuffle, payload)
}

func (n *Node) handleShuffle(from string, pkt *Packet, sh *ShufflePayload) {
	if !sh.IsReply && sh.RemainingHops > 0 {
		if next := n.pickShuffleForwardTarget(from, sh.Origin.SignPub); next != "" {
			fwd := *sh
			fwd.RemainingHops--
			_ = n.sendUnicastPacket(next, n.overlay.EncKey(next), PortHyParViewShuffle, fwd)
			return
		}
	}
	for _, d := range sh.Peers {
		if d.SignPub != n.Address() && !n.isEvictedEverywhere(d.SignPub) {
			n.overlay.AddPassive(d)
		}
	}
	if sh.Origin.SignPub != "" && sh.Origin.SignPub != n.Address() {
		n.overlay.AddPassive(sh.Origin)
	}
	if sh.IsReply {
		return
	}
	replyTo := pkt.From
	replyEnc := pkt.FromEnc
	if sh.Origin.SignPub != "" {
		replyTo = sh.Origin.SignPub
		replyEnc = sh.Origin.EncPub
	}
	reply := ShufflePayload{
		Origin:    n.selfDescriptor(),
		Peers:     n.overlay.SampleDescriptors(n.Cfg.ShuffleFanout, replyTo),
		IsReply:   true,
		RequestID: sh.RequestID,
	}
	_ = n.sendUnicastPacket(replyTo, replyEnc, PortHyParViewShuffle, reply)
}

func (n *Node) pickShuffleForwardTarget(excludeFrom, origin string) string {
	active := n.overlay.ActivePeers()
	var cands []string
	for _, p := range active {
		if p != excludeFrom && p != origin {
			cands = append(cands, p)
		}
	}
	if len(cands) == 0 {
		return ""
	}
	return cands[time.Now().UnixNano()%int64(len(cands))]
}

func (n *Node) handleGroupDiscover(from string, pkt *Packet, ch *ChannelState, gd *GroupDiscoverPayload) {
	if pkt.From == n.Address() {
		return
	}
	n.mu.RLock()
	evicted := ch.evictedPeers[pkt.From] > 0
	n.mu.RUnlock()
	if evicted {
		return
	}
	n.addChannelPeer(ch.RoomID, pkt.From)
	n.overlay.MarkChannelPeer(pkt.From, ch.ChannelHash)
	if n.overlay.ChannelPeerCount(ch.ChannelHash) >= n.Cfg.GroupTargetPeers(ch.Kind) {
		n.broadcaster.MarkSatisfied(fmt.Sprintf("group:%d", ch.ChannelHash))
	}

	if n.Hooks.OnChannelDiscovered != nil {
		n.Hooks.OnChannelDiscovered(ch.RoomID, pkt.From)
	}
	if !gd.IsReply {
		_ = n.sendBootstrapGroupPacket(ch, pkt.From, PortGroupDiscover, &GroupDiscoverPayload{
			RoomID:  ch.RoomID,
			IsReply: true,
		})
	}
	// If not yet directly connected, record in passive view and dial the discovered group member directly.
	if !n.shouldSkipDial(pkt.From) {
		desc := PeerDescriptor{SignPub: pkt.From, EncPub: pkt.FromEnc, ChannelHashes: []uint32{ch.ChannelHash}}
		n.overlay.AddPassive(desc)
		n.dialCandidates([]PeerDescriptor{desc})
	} else {
		go n.BroadcastPeerInfo()
	}
}

func (n *Node) handleLeave(from string, lv *LeaveFrame) {
	if lv.Peer == "" || lv.Peer == n.Address() {
		return
	}
	if !Verify(lv.Peer, CanonicalLeave(lv.Peer, lv.Timestamp), lv.Signature) {
		return
	}
	n.RemovePeer(lv.Peer)
	if n.Transport != nil {
		n.Transport.ClosePeer(lv.Peer)
	}
}

func (n *Node) selfDescriptor() PeerDescriptor {
	return PeerDescriptor{
		SignPub:       n.Address(),
		EncPub:        n.ID.EncAddress(),
		ChannelHashes: n.activeChannelHashes(),
	}
}

func (n *Node) activeChannelHashes() []uint32 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]uint32, 0, len(n.channels))
	for _, ch := range n.channels {
		if ch.ChannelHash != 0 {
			out = append(out, ch.ChannelHash)
		}
	}
	return out
}

// SignLeave builds a signed LeaveFrame.
func (n *Node) newLeaveFrame() LeaveFrame {
	now := time.Now().UnixMilli()
	return LeaveFrame{
		Peer:      n.Address(),
		Timestamp: now,
		Signature: hex.EncodeToString(n.ID.Sign(CanonicalLeave(n.Address(), now))),
	}
}
