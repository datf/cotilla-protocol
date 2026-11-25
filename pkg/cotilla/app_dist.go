package cotilla

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type seededAppBundle struct {
	Manifest    *AppManifest
	BundleBytes []byte
	ValidSigs   []string
	RoomID      string
	RoomKey     RoomKey
}

// BootstrapApp configures and joins the public app seeder group (ChannelPublic) using cfg,
// then starts an expanding-ring broadcast requesting the app manifest and chunks.
func (n *Node) BootstrapApp(cfg AppBootstrapConfig) (RoomKey, error) {
	groupName := cfg.SeederGroup.Name
	if groupName == "" {
		groupName = DefaultAppDistRoomID
	}
	key := AppDistRoomKeyFor(groupName)
	if cfg.SeederGroup.PSK != "" {
		if parsed, err := ParseRoomKey(cfg.SeederGroup.PSK); err == nil {
			key = parsed
		}
	}
	if err := n.joinAppDistLocked(groupName, key, cfg); err != nil {
		return RoomKey{}, err
	}
	n.RequestAppManifest(groupName, cfg.AppName, cfg.SeederGroup.Channel, cfg.MinSeq)
	return key, nil
}

// JoinAppDistChannel joins a public app distribution group with a single pinned publisher key.
func (n *Node) JoinAppDistChannel(roomID string, key RoomKey, pinnedPubHex string, minSeq uint64) error {
	var sigs []string
	if pinnedPubHex != "" {
		sigs = []string{pinnedPubHex}
	}
	cfg := AppBootstrapConfig{
		MinSeq:          minSeq,
		ValidSignatures: sigs,
		SeederGroup:     SeederGroupConfig{Name: roomID},
	}
	if key == (RoomKey{}) {
		key = AppDistRoomKeyFor(roomID)
	}
	if err := n.joinAppDistLocked(roomID, key, cfg); err != nil {
		return err
	}
	n.RequestAppManifest(roomID, "", "", minSeq)
	return nil
}

func (n *Node) joinAppDistLocked(roomID string, key RoomKey, cfg AppBootstrapConfig) error {
	if roomID == "" {
		roomID = DefaultAppDistRoomID
	}
	n.mu.Lock()
	ch := n.channels[roomID]
	if ch == nil {
		myKp := n.myKeyPackage
		if myKp == nil {
			myKp, _ = NewKeyPackage(n.ID)
		}
		ch = newChannelState(roomID, key, ChannelPublic, myKp, n.Cfg)
		n.channels[roomID] = ch
		n.channelsByHash[ch.ChannelHash] = ch
	}
	ch.Kind = ChannelPublic
	ch.IsAppDist = true
	ch.appDistValidSigs = cfg.ValidSignatures
	ch.appDistAppName = cfg.AppName
	ch.appDistVersion = cfg.Version
	ch.appDistMinSeq = cfg.MinSeq
	n.mu.Unlock()

	n.startGroupDiscovery(ch)
	return nil
}

// RegisterAppBundle verifies, chunks, and registers an application bundle for seeding in the public group.
func (n *Node) RegisterAppBundle(roomID string, key RoomKey, manifest *AppManifest, bundleBytes []byte, pinnedPubHex string) error {
	if manifest == nil || len(bundleBytes) == 0 {
		return errors.New("cotilla: manifest and bundle bytes are required")
	}
	if roomID == "" {
		roomID = DefaultAppDistRoomID
	}
	if key == (RoomKey{}) {
		key = AppDistRoomKeyFor(roomID)
	}
	if err := VerifyAppBundle(manifest, bundleBytes, pinnedPubHex, manifest.AppID, manifest.Channel, manifest.Seq, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("cotilla: cannot register invalid app bundle: %w", err)
	}
	_, chunks, err := PrepareAttachmentWithEpoch(key, 0, n.Address(), manifest.AppID+".html", manifest.EntryMIME, bundleBytes)
	if err != nil {
		return fmt.Errorf("cotilla: prepare attachment chunks: %w", err)
	}

	n.mu.Lock()
	ch := n.channels[roomID]
	if ch == nil {
		myKp := n.myKeyPackage
		if myKp == nil {
			myKp, _ = NewKeyPackage(n.ID)
		}
		ch = newChannelState(roomID, key, ChannelPublic, myKp, n.Cfg)
		n.channels[roomID] = ch
		n.channelsByHash[ch.ChannelHash] = ch
	}
	ch.Kind = ChannelPublic
	ch.IsAppDist = true
	ch.localAttachments[manifest.FileID] = chunks
	ch.assembledAttachments[manifest.FileID] = bundleBytes
	ch.appManifests[manifest.FileID] = manifest
	n.seededApps[manifest.AppID] = &seededAppBundle{
		Manifest:    manifest,
		BundleBytes: bundleBytes,
		ValidSigs:   []string{pinnedPubHex},
		RoomID:      roomID,
		RoomKey:     key,
	}
	n.mu.Unlock()

	n.startGroupDiscovery(ch)
	return nil
}

// RequestAppManifest broadcasts an encrypted expanding-ring AppManifestRequest to the public seeder group.
func (n *Node) RequestAppManifest(roomID, appID, channel string, minSeq uint64) {
	if roomID == "" {
		roomID = DefaultAppDistRoomID
	}
	n.mu.RLock()
	ch := n.channels[roomID]
	version := ""
	if ch != nil {
		version = ch.appDistVersion
	}
	n.mu.RUnlock()
	if ch == nil {
		return
	}

	tag := "app_manifest:" + appID
	n.broadcaster.Start(tag, n.Cfg.PublicGroupTTL, func(ttl, fanout int) {
		req := AppManifestRequest{
			RoomID:    roomID,
			AppID:     appID,
			Version:   version,
			Channel:   channel,
			MinSeq:    minSeq,
			RequestID: RandomID(),
		}
		pkt, err := NewGroupPacket(n.ID, BroadcastAddr, ch.ChannelHash, 0, ch.BootstrapKey, PortAppManifestReq, ttl, req)
		if err != nil {
			return
		}
		n.broadcastPacketWithFanout(pkt, fanout)
	})
}

func (n *Node) handleAppInviteReq(from string, pkt *Packet, req *AppManifestRequest) {
	n.handleAppManifestReq(from, pkt, req)
}

func (n *Node) handleAppManifestReq(from string, pkt *Packet, req *AppManifestRequest) {
	if req == nil {
		return
	}
	n.mu.RLock()
	var app *seededAppBundle
	if req.AppID != "" {
		app = n.seededApps[req.AppID]
	} else {
		for _, cand := range n.seededApps {
			if req.RoomID == "" || cand.RoomID == req.RoomID {
				app = cand
				break
			}
		}
	}
	ch := n.channels[req.RoomID]
	if ch == nil && app != nil {
		ch = n.channels[app.RoomID]
	}
	n.mu.RUnlock()

	if app == nil || app.Manifest == nil || ch == nil {
		return
	}
	if !matchesAppRequest(app.Manifest, req) {
		return
	}

	offer := n.signSeederAttachmentMeta(app)
	res := AppManifestResponse{
		RoomID:    app.RoomID,
		RequestID: req.RequestID,
		Manifest:  app.Manifest,
		Offer:     offer,
	}
	_ = n.sendGroupPacket(ch, pkt.From, PortAppManifestRes, res)
}

func matchesAppRequest(m *AppManifest, req *AppManifestRequest) bool {
	if req.Channel != "" && m.Channel != req.Channel {
		return false
	}
	if req.Version != "" && m.Version != req.Version {
		return false
	}
	if req.MinSeq > 0 && m.Seq < req.MinSeq {
		return false
	}
	if req.FileHash != "" && m.SHA256 != req.FileHash && m.FileID != req.FileHash {
		return false
	}
	return true
}

func (n *Node) signSeederAttachmentMeta(app *seededAppBundle) *AttachmentMeta {
	now := time.Now().UnixMilli()
	meta := &AttachmentMeta{
		RoomID:       app.RoomID,
		FileID:       app.Manifest.FileID,
		Hash:         app.Manifest.SHA256,
		Name:         app.Manifest.AppID + ".html",
		Size:         app.Manifest.Size,
		MIME:         app.Manifest.EntryMIME,
		TotalChunks:  app.Manifest.TotalChunks,
		EpochID:      0,
		AuthorPubKey: n.Address(),
		Timestamp:    now,
	}
	canonical := CanonicalAttachMeta(meta.RoomID, meta.FileID, meta.Hash, meta.Name, meta.MIME, meta.AuthorPubKey, meta.Size, meta.TotalChunks, meta.EpochID, meta.Timestamp)
	meta.Signature = hex.EncodeToString(n.ID.Sign(canonical))
	return meta
}

func (n *Node) handleAppManifestRes(from string, res *AppManifestResponse) {
	if res == nil || res.Manifest == nil || res.Offer == nil {
		return
	}
	roomID := res.RoomID
	if roomID == "" {
		roomID = DefaultAppDistRoomID
	}
	n.mu.RLock()
	ch := n.channels[roomID]
	if ch == nil {
		n.mu.RUnlock()
		return
	}
	validSigs := ch.appDistValidSigs
	appName := ch.appDistAppName
	appVer := ch.appDistVersion
	minSeq := ch.appDistMinSeq
	n.mu.RUnlock()

	now := time.Now().UnixMilli()
	if err := VerifyAppManifestWithKeys(res.Manifest, validSigs, appName, appVer, "", minSeq, now); err != nil {
		n.log("dropping app manifest: %v", err)
		return
	}
	if !n.verifyManifestOfferMatch(res.Manifest, res.Offer) {
		return
	}

	n.broadcaster.MarkSatisfied("app_manifest:" + res.Manifest.AppID)
	n.broadcaster.MarkSatisfied("app_manifest:")
	if !n.registerIncomingAppOffer(ch, from, res) {
		return
	}
	if n.Hooks.OnAppManifest != nil {
		n.Hooks.OnAppManifest(res.Manifest, from)
	}
	if n.Hooks.OnAppBundleReady != nil {
		_ = n.DownloadAttachment(res.Manifest.FileID)
	}
}

func (n *Node) verifyManifestOfferMatch(m *AppManifest, offer *AttachmentMeta) bool {
	if offer.FileID != m.FileID || offer.Hash != m.SHA256 || offer.Size != m.Size || offer.TotalChunks != m.TotalChunks || offer.EpochID != 0 {
		return false
	}
	return n.validateAttachMeta(offer)
}

func (n *Node) registerIncomingAppOffer(ch *ChannelState, from string, res *AppManifestResponse) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if ch.assembledAttachments[res.Manifest.FileID] != nil {
		return false
	}
	if existing := n.seededApps[res.Manifest.AppID]; existing != nil && existing.Manifest != nil && existing.Manifest.Seq >= res.Manifest.Seq {
		return false
	}
	ch.knownOffers[res.Manifest.FileID] = res.Offer
	ch.offerSources[res.Manifest.FileID] = from
	ch.appManifests[res.Manifest.FileID] = res.Manifest
	if ch.assemblers[res.Manifest.FileID] == nil {
		ch.assemblers[res.Manifest.FileID] = NewAttachmentAssembler(*res.Offer, ch.BootstrapKey)
	}
	return true
}
