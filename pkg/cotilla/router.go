package cotilla

import (
	"encoding/json"
	mrand "math/rand/v2"
)

// HandleWire processes an incoming serialized Packet received over a WebRTC DataChannel.
func (n *Node) HandleWire(from string, data []byte) {
	pkt, err := UnmarshalPacket(data)
	if err != nil || pkt == nil {
		n.log("unmarshal packet failed from %s: %v", from, err)
		return
	}
	if err := VerifyPacket(pkt, maxGossipTTL, n.Cfg.ReplayWindow); err != nil {
		n.log("dropping invalid packet from %s: %v", from, err)
		return
	}
	if n.isBlockedPeer(from, pkt) {
		return
	}
	if n.packetCache.MarkSeen(pkt.ID) {
		return
	}
	n.recordPacketSender(from, pkt)
	n.routePacket(from, pkt)
}

func (n *Node) isBlockedPeer(from string, pkt *Packet) bool {
	n.mu.RLock()
	evictedFrom := n.isEvictedEverywhereLocked(from)
	evictedOrigin := n.isEvictedEverywhereLocked(pkt.From)
	n.mu.RUnlock()

	if !evictedFrom && !evictedOrigin {
		return false
	}
	// Allow 1:1 unicast DMs/invites/call signals even if evicted from a group channel.
	if pkt.ChannelHash == 0 && pkt.To == n.Address() && pkt.Encrypted {
		return false
	}
	if evictedFrom && n.Transport != nil {
		n.Transport.ClosePeer(from)
	}
	return true
}

func (n *Node) recordPacketSender(from string, pkt *Packet) {
	if from != "" && from != n.Address() && (n.Transport == nil || n.hasConnectedPeer(from)) {
		n.AddPeer(from)
	}
	if pkt.FromEnc != "" {
		n.overlay.SetEncKey(pkt.From, pkt.FromEnc)
	}
	if pkt.ChannelHash != 0 {
		n.overlay.MarkChannelPeer(pkt.From, pkt.ChannelHash)
		if from != "" && from != pkt.From {
			n.overlay.MarkChannelPeer(from, pkt.ChannelHash)
		}
	}
}

func (n *Node) routePacket(from string, pkt *Packet) {
	isForMe := pkt.To == n.Address()
	isBroadcast := pkt.To == BroadcastAddr

	if isForMe || isBroadcast {
		n.deliverLocal(from, pkt)
	}
	if isForMe {
		return
	}
	if pkt.HopLimit > 1 {
		n.forwardPacket(from, pkt)
	}
}

func (n *Node) deliverLocal(from string, pkt *Packet) {
	if !pkt.Encrypted {
		n.dispatchPort(from, pkt, nil, pkt.Port, pkt.Payload)
		return
	}
	if pkt.ChannelHash == 0 {
		if pkt.To != n.Address() {
			return
		}
		sd, err := OpenUnicastPacket(n.ID, pkt)
		if err != nil {
			n.log("unicast decrypt failed from %s: %v", pkt.From, err)
			return
		}
		n.dispatchPort(from, pkt, nil, sd.Port, sd.Body)
		return
	}
	n.mu.RLock()
	ch := n.channelsByHash[pkt.ChannelHash]
	if ch == nil {
		n.mu.RUnlock()
		return
	}
	sd, err := ch.decryptGroupPacket(pkt)
	shouldCatchUp := err != nil && ch.joinedEpoch > 0 && pkt.EpochID > ch.currentEpoch
	roomID := ch.RoomID
	n.mu.RUnlock()
	if err != nil {
		if shouldCatchUp {
			n.triggerCatchUpForChannel(roomID)
		}
		return
	}
	n.dispatchPort(from, pkt, ch, sd.Port, sd.Body)
}

func (n *Node) dispatchPort(from string, pkt *Packet, ch *ChannelState, port Port, body []byte) {
	switch port {
	case PortPeerRequest, PortPeerResponse, PortWebRTCSignal, PortRootIntro,
		PortAnchorSolicit, PortHyParViewShuffle, PortGroupDiscover, PortLeave:
		n.dispatchOverlayPort(from, pkt, ch, port, body)
	case PortChat, PortGroupPeerInfo, PortEpochCommit, PortSyncReq, PortSyncRes:
		n.dispatchChannelPort(from, pkt, ch, port, body)
	case PortAttachMeta, PortChunkReq, PortChunkRes, PortAppInviteReq, PortAppManifestReq, PortAppManifestRes:
		n.dispatchTransferPort(from, pkt, ch, port, body)
	case PortDirectInvite, PortDirectInviteRes, PortDM, PortCallCtrl, PortCallSig:
		n.dispatchDirectAndCallPort(from, pkt, ch, port, body)
	}
}

func (n *Node) dispatchOverlayPort(from string, pkt *Packet, ch *ChannelState, port Port, body []byte) {
	switch port {
	case PortPeerRequest:
		var req PeerRequestPayload
		if json.Unmarshal(body, &req) == nil {
			n.handlePeerRequest(from, pkt, &req)
		}
	case PortPeerResponse:
		var res PeerResponsePayload
		if json.Unmarshal(body, &res) == nil {
			n.handlePeerResponse(from, pkt, &res)
		}
	case PortWebRTCSignal:
		var sig WebRTCSignalPayload
		if json.Unmarshal(body, &sig) == nil {
			n.handleWebRTCSignal(from, pkt, &sig)
		}
	case PortRootIntro:
		var ri RootIntroFrame
		if json.Unmarshal(body, &ri) == nil {
			n.handleRootIntro(from, &ri)
		}
	case PortAnchorSolicit:
		var as AnchorSolicitFrame
		if json.Unmarshal(body, &as) == nil {
			n.handleAnchorSolicit(from, &as)
		}
	case PortHyParViewShuffle:
		var sh ShufflePayload
		if json.Unmarshal(body, &sh) == nil {
			n.handleShuffle(from, pkt, &sh)
		}
	case PortGroupDiscover:
		var gd GroupDiscoverPayload
		if ch != nil && json.Unmarshal(body, &gd) == nil {
			n.handleGroupDiscover(from, pkt, ch, &gd)
		}
	case PortLeave:
		var lv LeaveFrame
		if json.Unmarshal(body, &lv) == nil {
			n.handleLeave(from, &lv)
		}
	}
}

func (n *Node) dispatchChannelPort(from string, pkt *Packet, ch *ChannelState, port Port, body []byte) {
	switch port {
	case PortChat:
		var env Envelope
		if json.Unmarshal(body, &env) == nil {
			n.handleEnvelope(from, &env)
		}
	case PortGroupPeerInfo:
		var pi PeerInfoFrame
		if json.Unmarshal(body, &pi) == nil {
			n.handlePeerInfo(from, &pi)
		}
	case PortEpochCommit:
		var ec EpochCommit
		if json.Unmarshal(body, &ec) == nil {
			n.handleEpochCommit(from, &ec)
		}
	case PortSyncReq:
		var req SyncRequest
		if json.Unmarshal(body, &req) == nil {
			n.handleSyncReq(pkt.From, &req)
		}
	case PortSyncRes:
		var res SyncResponse
		if json.Unmarshal(body, &res) == nil {
			n.handleSyncRes(pkt.From, &res)
		}
	}
}

func (n *Node) dispatchTransferPort(from string, pkt *Packet, ch *ChannelState, port Port, body []byte) {
	switch port {
	case PortAttachMeta:
		var meta AttachmentMeta
		if json.Unmarshal(body, &meta) == nil {
			n.handleAttachMeta(pkt.From, &meta)
		}
	case PortChunkReq:
		var req ChunkRequest
		if json.Unmarshal(body, &req) == nil {
			n.handleChunkReq(pkt.From, &req)
		}
	case PortChunkRes:
		var res ChunkResponse
		if json.Unmarshal(body, &res) == nil {
			n.handleChunkRes(pkt.From, &res)
		}
	case PortAppInviteReq:
		var req AppManifestRequest
		if json.Unmarshal(body, &req) == nil {
			n.handleAppInviteReq(from, pkt, &req)
		}
	case PortAppManifestReq:
		var req AppManifestRequest
		if json.Unmarshal(body, &req) == nil {
			n.handleAppManifestReq(from, pkt, &req)
		}
	case PortAppManifestRes:
		var res AppManifestResponse
		if json.Unmarshal(body, &res) == nil {
			n.handleAppManifestRes(pkt.From, &res)
		}
	}
}

func (n *Node) dispatchDirectAndCallPort(from string, pkt *Packet, ch *ChannelState, port Port, body []byte) {
	switch port {
	case PortDirectInvite:
		var inv DirectInvite
		if json.Unmarshal(body, &inv) == nil {
			n.handleDirectInvite(from, &inv)
		}
	case PortDirectInviteRes:
		var res InviteResponse
		if json.Unmarshal(body, &res) == nil {
			n.handleInviteResponse(from, &res)
		}
	case PortDM:
		var dm DMFrame
		if json.Unmarshal(body, &dm) == nil {
			n.handleDM(pkt.From, &dm)
		}
	case PortCallCtrl:
		var cc CallControlFrame
		if json.Unmarshal(body, &cc) == nil {
			n.handleCallControl(from, &cc)
		}
	case PortCallSig:
		var cs CallSignalFrame
		if json.Unmarshal(body, &cs) == nil {
			n.handleCallSignal(from, &cs)
		}
	}
}

func (n *Node) forwardPacket(from string, pkt *Packet) {
	if n.Transport == nil {
		return
	}
	fwd := *pkt
	fwd.HopLimit--
	data, err := MarshalPacket(&fwd)
	if err != nil {
		return
	}
	if fwd.To != BroadcastAddr {
		if n.Transport.Send(fwd.To, data) == nil {
			return
		}
	}
	targets := n.selectForwardTargets(from, &fwd, n.Cfg.GossipFanout)
	for _, t := range targets {
		_ = n.Transport.Send(t, data)
	}
}

func (n *Node) isGatewayOrSignaling(peer string) bool {
	if n.IsGatewayPeer(peer) {
		return true
	}
	return len(peer) >= 9 && peer[:9] == "signaling"
}

func (n *Node) selectForwardTargets(excludeFrom string, pkt *Packet, fanout int) []string {
	if n.Transport == nil {
		return nil
	}
	live := n.Transport.Peers()
	var nonGW, gw []string
	for _, p := range live {
		if p == "" || p == n.Address() || p == excludeFrom || p == pkt.From {
			continue
		}
		if n.isGatewayOrSignaling(p) {
			gw = append(gw, p)
		} else {
			nonGW = append(nonGW, p)
		}
	}
	candidates := nonGW
	if pkt.ChannelHash == 0 {
		candidates = append(candidates, gw...)
	}
	mrand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	if fanout > 0 && len(candidates) > fanout {
		candidates = candidates[:fanout]
	}
	return candidates
}

// sendPacket marshals and sends p directly to target, falling back to gossip relay if disconnected.
func (n *Node) sendPacket(target string, p *Packet) error {
	if n.Transport == nil || p == nil {
		return nil
	}
	n.packetCache.MarkSeen(p.ID)
	data, err := MarshalPacket(p)
	if err != nil {
		return err
	}
	if target != "" && target != BroadcastAddr {
		if n.Transport.Send(target, data) == nil {
			return nil
		}
	}
	return n.fanoutRaw(data, p, n.Cfg.GossipFanout)
}

func (n *Node) broadcastPacketWithFanout(p *Packet, fanout int) {
	if n.Transport == nil || p == nil {
		return
	}
	n.packetCache.MarkSeen(p.ID)
	data, err := MarshalPacket(p)
	if err != nil {
		return
	}
	_ = n.fanoutRaw(data, p, fanout)
}

func (n *Node) fanoutRaw(data []byte, p *Packet, fanout int) error {
	targets := n.selectForwardTargets("", p, fanout)
	if len(targets) == 0 && p.ChannelHash == 0 {
		for _, peer := range n.Transport.Peers() {
			if peer != n.Address() {
				_ = n.Transport.Send(peer, data)
			}
		}
		return nil
	}
	for _, t := range targets {
		_ = n.Transport.Send(t, data)
	}
	return nil
}

func (n *Node) sendGroupPacket(ch *ChannelState, to string, port Port, body any) error {
	if ch == nil {
		return nil
	}
	key, epoch := ch.activeKeyAndEpoch()
	ttl := n.Cfg.GroupTTL(ch.Kind)
	p, err := NewGroupPacket(n.ID, to, ch.ChannelHash, epoch, key, port, ttl, body)
	if err != nil {
		return err
	}
	if to != "" && to != BroadcastAddr {
		return n.sendPacket(to, p)
	}
	n.broadcastPacketToChannel(ch, p)
	return nil
}

func (n *Node) broadcastPacketToChannel(ch *ChannelState, p *Packet) {
	if n.Transport == nil || p == nil {
		return
	}
	n.packetCache.MarkSeen(p.ID)
	data, err := MarshalPacket(p)
	if err != nil {
		return
	}
	for _, peer := range n.Transport.Peers() {
		if peer == n.Address() || n.isGatewayOrSignaling(peer) {
			continue
		}
		_ = n.Transport.Send(peer, data)
	}
}

func (n *Node) sendUnicastPacket(toSign, toEnc string, port Port, body any) error {
	if toEnc == "" {
		toEnc = n.overlay.EncKey(toSign)
	}
	if toEnc == "" {
		p, err := NewPlainPacket(n.ID, toSign, port, n.Cfg.GossipTTL, body)
		if err != nil {
			return err
		}
		return n.sendPacket(toSign, p)
	}
	p, err := NewUnicastPacket(n.ID, toSign, toEnc, port, n.Cfg.GossipTTL, body)
	if err != nil {
		return err
	}
	return n.sendPacket(toSign, p)
}
