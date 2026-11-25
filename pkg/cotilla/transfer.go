package cotilla

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const chunkPipelineWindow = 16

// ShareAttachment chunks, encrypts, and announces a file attachment in the primary room.
func (n *Node) ShareAttachment(name, mime string, data []byte) (*AttachmentMeta, error) {
	return n.ShareAttachmentInChannel(n.RoomID, name, mime, data)
}

// ShareAttachmentInChannel broadcasts only AttachmentMeta (on-demand; chunks are never pushed).
func (n *Node) ShareAttachmentInChannel(channelID, name, mime string, data []byte) (*AttachmentMeta, error) {
	n.mu.RLock()
	ch := n.channelLocked(channelID)
	if ch == nil {
		n.mu.RUnlock()
		return nil, fmt.Errorf("cotilla: not joined to channel %s", channelID)
	}
	if ch.evictedPeers[n.Address()] > 0 {
		n.mu.RUnlock()
		return nil, errors.New("cotilla: evicted peer cannot share attachments")
	}
	key, epoch := ch.activeKeyAndEpoch()
	roomID := ch.RoomID
	n.mu.RUnlock()

	meta, chunks, err := PrepareAttachmentWithEpoch(key, epoch, n.Address(), name, mime, data)
	if err != nil {
		return nil, err
	}
	meta.RoomID = roomID
	meta.Timestamp = time.Now().UnixMilli()
	canonical := CanonicalAttachMeta(meta.RoomID, meta.FileID, meta.Hash, meta.Name, meta.MIME, meta.AuthorPubKey, meta.Size, meta.TotalChunks, meta.EpochID, meta.Timestamp)
	meta.Signature = hex.EncodeToString(n.ID.Sign(canonical))

	n.mu.Lock()
	ch = n.channelLocked(roomID)
	if ch != nil {
		ch.localAttachments[meta.FileID] = chunks
		ch.knownOffers[meta.FileID] = meta
		ch.assembledAttachments[meta.FileID] = data
	}
	n.mu.Unlock()

	_ = n.sendGroupPacket(ch, BroadcastAddr, PortAttachMeta, meta)
	return meta, nil
}

func (n *Node) findChannelByFileLocked(fileID string) *ChannelState {
	for _, ch := range n.channels {
		if ch.knownOffers[fileID] != nil || ch.localAttachments[fileID] != nil || ch.assembledAttachments[fileID] != nil {
			return ch
		}
	}
	return nil
}

// DownloadAttachment initiates an on-demand pipelined download for fileID.
func (n *Node) DownloadAttachment(fileID string) error {
	n.mu.Lock()
	ch := n.findChannelByFileLocked(fileID)
	if ch == nil {
		n.mu.Unlock()
		return fmt.Errorf("cotilla: unknown attachment offer %s", fileID)
	}
	if assembled := ch.assembledAttachments[fileID]; assembled != nil {
		meta := ch.knownOffers[fileID]
		isAppDist := ch.IsAppDist
		n.mu.Unlock()
		if !isAppDist && n.Hooks.OnAttachment != nil && meta != nil {
			n.Hooks.OnAttachment(meta, assembled)
		}
		return nil
	}
	meta := ch.knownOffers[fileID]
	if !ch.IsAppDist && ch.joinedEpoch > 0 && meta.EpochID > 0 && meta.EpochID < ch.joinedEpoch {
		n.mu.Unlock()
		return fmt.Errorf("cotilla: attachment %s belongs to pre-join epoch %d (joined at %d)", fileID, meta.EpochID, ch.joinedEpoch)
	}
	if ch.assemblers[fileID] == nil {
		key := ch.epochKeys[meta.EpochID]
		if key == (RoomKey{}) {
			key = ch.RoomKey
		}
		ch.assemblers[fileID] = NewAttachmentAssembler(*meta, key)
	}
	alreadyDownloading := ch.downloading[fileID]
	ch.downloading[fileID] = true
	n.mu.Unlock()

	n.fetchNextChunks(fileID)
	if !alreadyDownloading {
		go n.monitorDownloadRetries(fileID)
	}
	return nil
}

func (n *Node) monitorDownloadRetries(fileID string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for i := 0; i < 60; i++ {
		select {
		case <-n.supervisorStop:
			return
		case <-ticker.C:
		}
		n.mu.RLock()
		ch := n.findChannelByFileLocked(fileID)
		done := ch == nil || ch.assembledAttachments[fileID] != nil || ch.assemblers[fileID] == nil
		n.mu.RUnlock()
		if done {
			return
		}
		n.RetryMissingChunks(fileID)
	}
}

// GetAttachmentData returns the assembled plaintext bytes for fileID if available.
func (n *Node) GetAttachmentData(fileID string) ([]byte, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	ch := n.findChannelByFileLocked(fileID)
	if ch == nil || ch.assembledAttachments[fileID] == nil {
		return nil, fmt.Errorf("cotilla: attachment %s not downloaded", fileID)
	}
	return ch.assembledAttachments[fileID], nil
}

// AttachmentOffers returns all known non-app-dist attachment metadata offers.
func (n *Node) AttachmentOffers() []*AttachmentMeta {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var out []*AttachmentMeta
	for _, ch := range n.channels {
		if ch.IsAppDist {
			continue
		}
		for _, meta := range ch.knownOffers {
			out = append(out, meta)
		}
	}
	return out
}

// RequestAttachment stores meta and triggers DownloadAttachment.
func (n *Node) RequestAttachment(meta AttachmentMeta) {
	n.mu.Lock()
	ch := n.channelLocked(meta.RoomID)
	if ch != nil {
		ch.knownOffers[meta.FileID] = &meta
	}
	n.mu.Unlock()
	_ = n.DownloadAttachment(meta.FileID)
}

func (n *Node) fetchNextChunks(fileID string) {
	n.mu.RLock()
	ch := n.findChannelByFileLocked(fileID)
	if ch == nil || ch.assemblers[fileID] == nil {
		n.mu.RUnlock()
		return
	}
	assembler := ch.assemblers[fileID]
	source := ch.offerSources[fileID]
	roomID := ch.RoomID
	n.mu.RUnlock()

	missing := assembler.NextMissingChunks(chunkPipelineWindow)
	if len(missing) == 0 {
		return
	}
	target := n.resolveChunkTarget(source)
	for _, idx := range missing {
		req := ChunkRequest{RoomID: roomID, FileID: fileID, ChunkIndex: idx}
		_ = n.sendGroupPacket(ch, target, PortChunkReq, req)
	}
}

// RetryMissingChunks broadcasts requests for any stale/missing chunks across the group mesh (swarm failover).
func (n *Node) RetryMissingChunks(fileID string) {
	n.mu.RLock()
	ch := n.findChannelByFileLocked(fileID)
	if ch == nil || ch.assemblers[fileID] == nil {
		n.mu.RUnlock()
		return
	}
	asm := ch.assemblers[fileID]
	asm.RetryStaleRequests(3 * time.Second)
	missing := asm.NextMissingChunks(chunkPipelineWindow)
	roomID := ch.RoomID
	n.mu.RUnlock()

	for _, idx := range missing {
		req := ChunkRequest{RoomID: roomID, FileID: fileID, ChunkIndex: idx}
		_ = n.sendGroupPacket(ch, BroadcastAddr, PortChunkReq, req)
	}
}

func (n *Node) resolveChunkTarget(source string) string {
	if source != "" && n.Transport != nil {
		for _, p := range n.Transport.Peers() {
			if p == source {
				return source
			}
		}
	}
	return BroadcastAddr
}

func (n *Node) syncOffersToPeer(target string) {
	if target == "" || n.IsGatewayPeer(target) {
		return
	}
	n.mu.RLock()
	type offerEntry struct {
		ch   *ChannelState
		meta *AttachmentMeta
	}
	var list []offerEntry
	for _, ch := range n.channels {
		if ch.IsAppDist || ch.evictedPeers[target] > 0 {
			continue
		}
		targetJoin := ch.memberJoinEpoch[target]
		for _, meta := range ch.knownOffers {
			if targetJoin > 0 && meta.EpochID > 0 && meta.EpochID < targetJoin {
				continue
			}
			list = append(list, offerEntry{ch: ch, meta: meta})
		}
	}
	n.mu.RUnlock()
	for _, item := range list {
		_ = n.sendGroupPacket(item.ch, target, PortAttachMeta, item.meta)
	}
}

func (n *Node) handleAttachMeta(from string, meta *AttachmentMeta) {
	if !n.validateAttachMeta(meta) {
		return
	}
	n.mu.Lock()
	ch := n.channelLocked(meta.RoomID)
	if ch == nil || ch.evictedPeers[from] > 0 || ch.evictedPeers[meta.AuthorPubKey] > 0 {
		n.mu.Unlock()
		return
	}
	if !n.isAdmittedMemberLocked(ch, from) || !n.isAdmittedMemberLocked(ch, meta.AuthorPubKey) {
		n.mu.Unlock()
		return
	}
	if ch.joinedEpoch > 0 && (meta.EpochID < ch.joinedEpoch || meta.EpochID == 0) {
		n.mu.Unlock()
		return
	}
	if ch.currentEpoch > 0 && meta.EpochID == 0 && !ch.IsAppDist {
		n.mu.Unlock()
		return
	}
	if !ch.IsAppDist && ch.joinedEpoch > 0 && meta.EpochID > 0 && meta.EpochID < ch.joinedEpoch {
		n.mu.Unlock()
		return
	}
	_, existed := ch.knownOffers[meta.FileID]
	ch.knownOffers[meta.FileID] = meta
	ch.offerSources[meta.FileID] = from
	isAppDist := ch.IsAppDist
	n.mu.Unlock()

	if !existed && !isAppDist && n.Hooks.OnAttachmentOffer != nil {
		n.Hooks.OnAttachmentOffer(meta)
	}
}

func (n *Node) validateAttachMeta(meta *AttachmentMeta) bool {
	if meta == nil || meta.FileID == "" || meta.AuthorPubKey == "" || meta.Signature == "" {
		return false
	}
	if meta.TotalChunks < 0 || meta.TotalChunks > MaxAttachmentChunks || meta.Size < 0 || meta.Size > MaxAttachmentSize {
		return false
	}
	if !withinWindow(meta.Timestamp, n.Cfg.ReplayWindow) {
		return false
	}
	canonical := CanonicalAttachMeta(meta.RoomID, meta.FileID, meta.Hash, meta.Name, meta.MIME, meta.AuthorPubKey, meta.Size, meta.TotalChunks, meta.EpochID, meta.Timestamp)
	return Verify(meta.AuthorPubKey, canonical, meta.Signature)
}

func (n *Node) handleChunkReq(from string, req *ChunkRequest) {
	if req == nil || req.FileID == "" || req.ChunkIndex < 0 {
		return
	}
	n.mu.RLock()
	ch := n.findChannelByFileLocked(req.FileID)
	if ch == nil || ch.evictedPeers[from] > 0 {
		n.mu.RUnlock()
		return
	}
	chunks := ch.localAttachments[req.FileID]
	var data []byte
	if req.ChunkIndex < len(chunks) {
		data = chunks[req.ChunkIndex]
	} else if asm := ch.assemblers[req.FileID]; asm != nil {
		data = asm.RawChunk(req.ChunkIndex)
	}
	roomID := ch.RoomID
	n.mu.RUnlock()

	if len(data) == 0 {
		return
	}
	res := ChunkResponse{RoomID: roomID, FileID: req.FileID, ChunkIndex: req.ChunkIndex, Data: data}
	_ = n.sendGroupPacket(ch, from, PortChunkRes, res)
}

func (n *Node) handleChunkRes(from string, res *ChunkResponse) {
	if res == nil || res.FileID == "" || len(res.Data) == 0 {
		return
	}
	n.mu.Lock()
	ch := n.findChannelByFileLocked(res.FileID)
	if ch == nil || ch.assemblers[res.FileID] == nil || ch.assembledAttachments[res.FileID] != nil {
		n.mu.Unlock()
		return
	}
	asm := ch.assemblers[res.FileID]
	if _, err := asm.AddChunk(res.ChunkIndex, res.Data); err != nil {
		n.mu.Unlock()
		return
	}
	received, total := asm.Progress()
	complete := asm.IsComplete()
	n.mu.Unlock()

	if n.Hooks.OnAttachmentProgress != nil {
		n.Hooks.OnAttachmentProgress(res.FileID, received, total)
	}
	if complete {
		n.finalizeAttachment(res.FileID)
	} else {
		n.fetchNextChunks(res.FileID)
	}
}

func (n *Node) finalizeAttachment(fileID string) {
	n.mu.Lock()
	ch := n.findChannelByFileLocked(fileID)
	if ch == nil || ch.assemblers[fileID] == nil {
		n.mu.Unlock()
		return
	}
	asm := ch.assemblers[fileID]
	data, err := asm.Assemble()
	if err != nil {
		n.mu.Unlock()
		n.log("attachment assembly failed for %s: %v", fileID, err)
		return
	}
	meta := ch.knownOffers[fileID]
	ch.assembledAttachments[fileID] = data
	ch.localAttachments[fileID] = asm.ExportRawChunks() // Immediately act as swarm seeder!
	delete(ch.downloading, fileID)
	manifest := ch.appManifests[fileID]
	isAppDist := ch.IsAppDist
	validSigs := ch.appDistValidSigs
	appName := ch.appDistAppName
	appVer := ch.appDistVersion
	minSeq := ch.appDistMinSeq
	n.mu.Unlock()

	if isAppDist && manifest != nil {
		if err := VerifyAppBundleWithKeys(manifest, data, validSigs, appName, appVer, "", minSeq, time.Now().UnixMilli()); err != nil {
			n.log("app bundle verification failed: %v", err)
			return
		}
		n.mu.Lock()
		n.seededApps[manifest.AppID] = &seededAppBundle{
			Manifest:    manifest,
			BundleBytes: data,
			ValidSigs:   validSigs,
			RoomID:      ch.RoomID,
			RoomKey:     ch.BootstrapKey,
		}
		n.mu.Unlock()
		if n.Hooks.OnAppBundleReady != nil {
			n.Hooks.OnAppBundleReady(manifest, data)
		}
		return
	}
	if !isAppDist && n.Hooks.OnAttachment != nil && meta != nil {
		n.Hooks.OnAttachment(meta, data)
	}
}
