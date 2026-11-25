package cotilla

import (
	mrand "math/rand/v2"
	"sync"
	"time"
)

// ActivePeer tracks an open WebRTC overlay neighbor in the HyParView Active View.
type ActivePeer struct {
	SignPub       string
	EncPub        string
	JoinedAt      time.Time
	LastSeen      time.Time
	IsAnchor      bool
	IsGateway     bool
	ChannelHashes map[uint32]bool
}

// OverlayView implements HyParView Active/Passive peer views with group-aware quotas.
type OverlayView struct {
	mu      sync.RWMutex
	self    string
	cfg     Config
	active  map[string]*ActivePeer
	passive map[string]PeerDescriptor
	encKeys map[string]string
}

// NewOverlayView creates a HyParView membership manager for local node self.
func NewOverlayView(self string, cfg Config) *OverlayView {
	return &OverlayView{
		self:    self,
		cfg:     cfg,
		active:  make(map[string]*ActivePeer),
		passive: make(map[string]PeerDescriptor),
		encKeys: make(map[string]string),
	}
}

// AddActive registers or refreshes an active peer connection.
func (v *OverlayView) AddActive(signPub string, isGateway bool) bool {
	if signPub == "" || signPub == v.self {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	if existing, ok := v.active[signPub]; ok {
		existing.LastSeen = now
		if isGateway {
			existing.IsGateway = true
		}
		return false
	}
	enc := v.encKeys[signPub]
	if desc, ok := v.passive[signPub]; ok {
		if enc == "" {
			enc = desc.EncPub
		}
		delete(v.passive, signPub)
	}
	v.active[signPub] = &ActivePeer{
		SignPub:       signPub,
		EncPub:        enc,
		JoinedAt:      now,
		LastSeen:      now,
		IsGateway:     isGateway,
		ChannelHashes: make(map[uint32]bool),
	}
	return true
}

// RemoveActive removes a disconnected peer from the active view.
func (v *OverlayView) RemoveActive(signPub string, keepInPassive bool) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	ap, ok := v.active[signPub]
	if !ok {
		return false
	}
	delete(v.active, signPub)
	if keepInPassive && !ap.IsGateway {
		v.addPassiveLocked(v.descriptorFromActiveLocked(ap))
	}
	return true
}

// SetEncKey records a peer's X25519 public encryption key.
func (v *OverlayView) SetEncKey(signPub, encPub string) {
	if signPub == "" || encPub == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.encKeys[signPub] = encPub
	if ap, ok := v.active[signPub]; ok {
		ap.EncPub = encPub
	}
	if desc, ok := v.passive[signPub]; ok {
		desc.EncPub = encPub
		v.passive[signPub] = desc
	}
}

// EncKey returns the known X25519 encryption key for signPub, if any.
func (v *OverlayView) EncKey(signPub string) string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.encKeys[signPub]
}

// EncKeysSnapshot returns a copy of all known SignPub -> EncPub mappings.
func (v *OverlayView) EncKeysSnapshot() map[string]string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make(map[string]string, len(v.encKeys))
	for k, val := range v.encKeys {
		out[k] = val
	}
	return out
}

// MarkChannelPeer associates an active peer with a channel hash.
func (v *OverlayView) MarkChannelPeer(signPub string, chHash uint32) {
	if signPub == "" || chHash == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if ap, ok := v.active[signPub]; ok {
		ap.ChannelHashes[chHash] = true
	}
}

// MarkAnchor sets anchor status on an active peer.
func (v *OverlayView) MarkAnchor(signPub string, isAnchor bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ap, ok := v.active[signPub]; ok {
		ap.IsAnchor = isAnchor
	}
}

// AddPassive inserts a peer descriptor into the bounded passive view.
func (v *OverlayView) AddPassive(desc PeerDescriptor) {
	if desc.SignPub == "" || desc.SignPub == v.self {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.addPassiveLocked(desc)
}

func (v *OverlayView) addPassiveLocked(desc PeerDescriptor) {
	if desc.EncPub != "" {
		v.encKeys[desc.SignPub] = desc.EncPub
	}
	if _, isAct := v.active[desc.SignPub]; isAct {
		return
	}
	if _, exists := v.passive[desc.SignPub]; !exists && len(v.passive) >= v.cfg.PassiveViewSize {
		v.evictRandomPassiveLocked()
	}
	v.passive[desc.SignPub] = desc
}

func (v *OverlayView) evictRandomPassiveLocked() {
	for k := range v.passive {
		delete(v.passive, k)
		if _, isAct := v.active[k]; !isAct {
			delete(v.encKeys, k)
		}
		return
	}
}

// RemovePassive deletes signPub from the passive view (e.g. on eviction).
func (v *OverlayView) RemovePassive(signPub string) {
	v.mu.Lock()
	delete(v.passive, signPub)
	if _, isAct := v.active[signPub]; !isAct {
		delete(v.encKeys, signPub)
	}
	v.mu.Unlock()
}

// ActivePeers returns all active non-gateway peer addresses.
func (v *OverlayView) ActivePeers() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.active))
	for addr, ap := range v.active {
		if !ap.IsGateway {
			out = append(out, addr)
		}
	}
	return out
}

// PassivePeers returns a snapshot of all passive descriptors.
func (v *OverlayView) PassivePeers() []PeerDescriptor {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]PeerDescriptor, 0, len(v.passive))
	for _, desc := range v.passive {
		out = append(out, desc)
	}
	return out
}

// ChannelPeerCount returns the number of active peers participating in chHash.
func (v *OverlayView) ChannelPeerCount(chHash uint32) int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	count := 0
	for _, ap := range v.active {
		if !ap.IsGateway && ap.ChannelHashes[chHash] {
			count++
		}
	}
	return count
}

// SampleDescriptors returns up to limit random peer descriptors from active and passive views.
func (v *OverlayView) SampleDescriptors(limit int, exclude string) []PeerDescriptor {
	v.mu.RLock()
	defer v.mu.RUnlock()

	pool := make([]PeerDescriptor, 0, len(v.active)+len(v.passive))
	for addr, ap := range v.active {
		if addr != exclude && !ap.IsGateway {
			pool = append(pool, v.descriptorFromActiveLocked(ap))
		}
	}
	for addr, desc := range v.passive {
		if addr != exclude {
			pool = append(pool, desc)
		}
	}
	mrand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if limit > 0 && len(pool) > limit {
		pool = pool[:limit]
	}
	return pool
}

// PickRepairCandidates selects up to limit disconnected peers from the passive view,
// prioritizing descriptors that advertise any channel hash in neededChannels.
func (v *OverlayView) PickRepairCandidates(neededChannels map[uint32]bool, limit int) []PeerDescriptor {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var preferred, general []PeerDescriptor
	for _, desc := range v.passive {
		if hasMatchingChannel(desc.ChannelHashes, neededChannels) {
			preferred = append(preferred, desc)
		} else {
			general = append(general, desc)
		}
	}
	mrand.Shuffle(len(preferred), func(i, j int) { preferred[i], preferred[j] = preferred[j], preferred[i] })
	mrand.Shuffle(len(general), func(i, j int) { general[i], general[j] = general[j], general[i] })
	combined := append(preferred, general...)
	if limit > 0 && len(combined) > limit {
		combined = combined[:limit]
	}
	return combined
}

// PickRotationVictim returns a non-anchor, non-gateway active peer safe to rotate out
// without dropping any channel below its required minimum peer count.
func (v *OverlayView) PickRotationVictim(minByChannel map[uint32]int, grace time.Duration) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := time.Now()
	counts := v.channelCountsLocked()
	var candidates []string
	for addr, ap := range v.active {
		if ap.IsGateway || ap.IsAnchor || now.Sub(ap.JoinedAt) < grace {
			continue
		}
		if v.safeToDropLocked(ap, counts, minByChannel) {
			candidates = append(candidates, addr)
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	return candidates[mrand.IntN(len(candidates))]
}

func (v *OverlayView) channelCountsLocked() map[uint32]int {
	counts := make(map[uint32]int)
	for _, ap := range v.active {
		if ap.IsGateway {
			continue
		}
		for ch := range ap.ChannelHashes {
			counts[ch]++
		}
	}
	return counts
}

func (v *OverlayView) safeToDropLocked(ap *ActivePeer, counts, mins map[uint32]int) bool {
	for ch := range ap.ChannelHashes {
		if minNeed := mins[ch]; minNeed > 0 && counts[ch] <= minNeed {
			return false
		}
	}
	return true
}

func (v *OverlayView) descriptorFromActiveLocked(ap *ActivePeer) PeerDescriptor {
	hashes := make([]uint32, 0, len(ap.ChannelHashes))
	for ch := range ap.ChannelHashes {
		hashes = append(hashes, ch)
	}
	return PeerDescriptor{SignPub: ap.SignPub, EncPub: ap.EncPub, ChannelHashes: hashes}
}

func hasMatchingChannel(hashes []uint32, needed map[uint32]bool) bool {
	for _, h := range hashes {
		if needed[h] {
			return true
		}
	}
	return false
}
