package cotilla

import (
	"fmt"
	mrand "math/rand/v2"
	"time"
)

func recordSeenEnvelopeLocked(ch *ChannelState, id string) {
	if _, exists := ch.seenEnvelopes[id]; exists {
		return
	}
	if len(ch.seenOrder) >= maxSeenEnvelopesTracked {
		oldest := ch.seenOrder[0]
		copy(ch.seenOrder, ch.seenOrder[1:])
		ch.seenOrder[len(ch.seenOrder)-1] = id
		delete(ch.seenEnvelopes, oldest)
		ch.seenEnvelopes[id] = struct{}{}
		ch.lastSeenMsgID = id
		return
	}
	ch.seenEnvelopes[id] = struct{}{}
	ch.seenOrder = append(ch.seenOrder, id)
	ch.lastSeenMsgID = id
}

// RequestCatchUp initiates expanding-ring targeted catch-up sync for the primary channel.
func (n *Node) RequestCatchUp() error {
	return n.RequestCatchUpForChannel(n.RoomID)
}

// RequestCatchUpForChannel starts expanding-ring targeted sync (1 -> 2 -> 4 -> 8...) for channelID.
func (n *Node) RequestCatchUpForChannel(channelID string) error {
	n.mu.RLock()
	ch := n.channelLocked(channelID)
	n.mu.RUnlock()
	if ch == nil {
		return fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	ch.syncMutex.Lock()
	ch.syncBatchSize = 1
	ch.queriedSyncPeers = make(map[string]bool)
	ch.syncLastRespAt = time.Time{}
	alreadyActive := ch.syncActive
	ch.syncActive = true
	ch.syncMutex.Unlock()

	if alreadyActive {
		go func() { _, _ = n.RequestCatchUpNextBatchForChannel(ch.RoomID) }()
		return nil
	}
	go n.runExpandingSyncLoop(ch)
	return nil
}

func (n *Node) runExpandingSyncLoop(ch *ChannelState) {
	defer func() {
		ch.syncMutex.Lock()
		ch.syncActive = false
		ch.syncMutex.Unlock()
	}()
	for attempt := 0; attempt < 5; attempt++ {
		queried, err := n.RequestCatchUpNextBatchForChannel(ch.RoomID)
		if err != nil || len(queried) == 0 {
			return
		}
		start := time.Now()
		wait := n.Cfg.SyncTimeout
		if wait <= 0 {
			wait = 1500 * time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-n.supervisorStop:
			timer.Stop()
			return
		case <-timer.C:
		}
		ch.syncMutex.Lock()
		gotResp := !ch.syncLastRespAt.IsZero() && ch.syncLastRespAt.After(start)
		ch.syncMutex.Unlock()
		if gotResp {
			return
		}
	}
}

// RequestCatchUpNextBatch sends the next doubling batch of SyncRequest packets for the primary channel.
func (n *Node) RequestCatchUpNextBatch() ([]string, error) {
	return n.RequestCatchUpNextBatchForChannel(n.RoomID)
}

// RequestCatchUpNextBatchForChannel targets live unqueried peers in doubling batches (1 -> 2 -> 4 -> 8).
func (n *Node) RequestCatchUpNextBatchForChannel(channelID string) ([]string, error) {
	if n.Transport == nil {
		return nil, nil
	}
	n.mu.RLock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		n.mu.RUnlock()
		return nil, fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	req := n.buildSyncRequestLocked(ch)
	n.mu.RUnlock()

	targets := n.pickSyncTargets(ch)
	for _, peer := range targets {
		_ = n.sendBootstrapGroupPacket(ch, peer, PortSyncReq, req)
	}
	return targets, nil
}

func (n *Node) buildSyncRequestLocked(ch *ChannelState) SyncRequest {
	maxKnown := max(n.Cfg.RingBufferCapacity*2, 400)
	start := 0
	if len(ch.seenOrder) > maxKnown {
		start = len(ch.seenOrder) - maxKnown
	}
	known := make([]string, len(ch.seenOrder)-start)
	copy(known, ch.seenOrder[start:])
	return SyncRequest{
		RoomID:        ch.RoomID,
		LastSeenMsgID: ch.lastSeenMsgID,
		KnownIDs:      known,
		CurrentEpoch:  ch.currentEpoch,
	}
}

func (n *Node) pickSyncTargets(ch *ChannelState) []string {
	live := n.liveNonGatewayPeers()
	if len(live) == 0 {
		return nil
	}
	ch.syncMutex.Lock()
	defer ch.syncMutex.Unlock()

	var unqueried []string
	for _, p := range live {
		if !ch.queriedSyncPeers[p] {
			unqueried = append(unqueried, p)
		}
	}
	if len(unqueried) == 0 {
		ch.queriedSyncPeers = make(map[string]bool)
		ch.syncBatchSize = 1
		unqueried = append(unqueried, live...)
	}
	mrand.Shuffle(len(unqueried), func(i, j int) { unqueried[i], unqueried[j] = unqueried[j], unqueried[i] })
	batch := ch.syncBatchSize
	if batch <= 0 {
		batch = 1
	}
	if batch > len(unqueried) {
		batch = len(unqueried)
	}
	chosen := unqueried[:batch]
	for _, p := range chosen {
		ch.queriedSyncPeers[p] = true
	}
	ch.syncBatchSize = batch * 2
	return chosen
}

func (n *Node) handleSyncReq(from string, req *SyncRequest) {
	if req == nil || n.Transport == nil {
		return
	}
	n.mu.RLock()
	ch := n.channelLocked(req.RoomID)
	if ch == nil || ch.evictedPeers[from] > 0 || !n.isAdmittedMemberLocked(ch, from) {
		n.mu.RUnlock()
		return
	}
	res := n.buildSyncResponseLocked(ch, from, req)
	n.mu.RUnlock()

	if len(res.Envelopes) > 0 || len(res.Offers) > 0 || len(res.Commits) > 0 {
		_ = n.sendBootstrapGroupPacket(ch, from, PortSyncRes, res)
	}
}

func (n *Node) buildSyncResponseLocked(ch *ChannelState, peer string, req *SyncRequest) SyncResponse {
	minEpoch := ch.memberJoinEpoch[peer]
	var maxEpoch int64
	if evEp := ch.evictedPeers[peer]; evEp > 0 {
		maxEpoch = evEp - 1
	}
	var missing []*Envelope
	var offers []*AttachmentMeta
	// Only return encrypted messages/offers to admitted MLS members with a known join epoch
	// (or on public/non-MLS channels where minEpoch == 0 and currentEpoch == 0).
	if ch.Kind != ChannelPrivate || ch.currentEpoch == 0 || minEpoch > 0 {
		missing = ch.RingBuffer.GetMissingForEpochRange("", req.KnownIDs, minEpoch, maxEpoch)
		for _, meta := range ch.knownOffers {
			if minEpoch > 0 && meta.EpochID > 0 && meta.EpochID < minEpoch {
				continue
			}
			if maxEpoch > 0 && meta.EpochID > maxEpoch {
				continue
			}
			offers = append(offers, meta)
		}
	}
	var commits []*EpochCommit
	for _, c := range ch.commitHistory {
		if c.EpochID > req.CurrentEpoch {
			commits = append(commits, c)
		}
	}
	return SyncResponse{
		RoomID:    ch.RoomID,
		Envelopes: missing,
		Offers:    offers,
		Commits:   commits,
	}
}

func (n *Node) handleSyncRes(from string, res *SyncResponse) {
	if res == nil {
		return
	}
	n.mu.RLock()
	ch := n.channelLocked(res.RoomID)
	n.mu.RUnlock()
	if ch == nil {
		return
	}
	ch.syncMutex.Lock()
	ch.syncLastRespAt = time.Now()
	ch.syncMutex.Unlock()

	for _, c := range res.Commits {
		n.handleEpochCommitInternal(from, c, n.Cfg.MessageTTL)
	}
	for _, env := range res.Envelopes {
		n.processEnvelope(env, n.Cfg.MessageTTL, true)
	}
	for _, meta := range res.Offers {
		n.handleAttachMeta(from, meta)
	}
	if len(res.Commits) > 0 {
		go func() { _, _ = n.RequestCatchUpNextBatchForChannel(ch.RoomID) }()
	}
}
