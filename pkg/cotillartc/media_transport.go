//go:build !js && !wasip1

package cotillartc

import (
	"sync"
	"sync/atomic"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/pion/webrtc/v4"
)

const (
	MediaKindAudio = "audio"
	MediaKindVideo = "video"
)

// CallMediaStats tracks encrypted/decrypted frame counts on a CallMediaTransport.
type CallMediaStats struct {
	EncryptedAudio uint64 `json:"encrypted_audio"`
	EncryptedVideo uint64 `json:"encrypted_video"`
	DecryptedAudio uint64 `json:"decrypted_audio"`
	DecryptedVideo uint64 `json:"decrypted_video"`
	Rejected       uint64 `json:"rejected"`
}

type callPeerKey struct {
	ScopeID  string
	PeerAddr string
}

// CallMediaTransport manages dedicated secondary WebRTC PeerConnections strictly scoped
// to active MLS channel or 1:1 DM calls with RFC 9605 SFrame encryption.
type CallMediaTransport struct {
	self   string
	config webrtc.Configuration

	mu            sync.Mutex
	signalSender  func(scopeID, target, kind, payload string) error
	onMediaFrame  func(scopeID, fromPeer, mediaKind string, kid uint64, plaintext []byte)
	onPeerState   func(scopeID, peerAddr string, state webrtc.PeerConnectionState)
	onError       func(scopeID, peerAddr, op string, err error)
	pendingOffers map[callPeerKey]bool

	encAudio atomic.Uint64
	encVideo atomic.Uint64
	decAudio atomic.Uint64
	decVideo atomic.Uint64
	rejected atomic.Uint64

	callMediaPlatform
}

// NewCallMediaTransport constructs a scoped secondary WebRTC transport for SFrame A/V calls.
func NewCallMediaTransport(self string, stunURLs []string, signalSender func(scopeID, target, kind, payload string) error) *CallMediaTransport {
	cfg := webrtc.Configuration{
		BundlePolicy: webrtc.BundlePolicyMaxBundle,
	}
	if len(stunURLs) > 0 {
		cfg.ICEServers = []webrtc.ICEServer{{URLs: stunURLs}}
	}
	t := &CallMediaTransport{
		self:          self,
		config:        cfg,
		signalSender:  signalSender,
		pendingOffers: make(map[callPeerKey]bool),
	}
	t.initCallPlatform()
	return t
}

// OnMediaFrame registers the handler invoked after an inbound RTP media frame passes SFrame AEAD decryption.
func (t *CallMediaTransport) OnMediaFrame(cb func(scopeID, fromPeer, mediaKind string, kid uint64, plaintext []byte)) {
	t.mu.Lock()
	t.onMediaFrame = cb
	t.mu.Unlock()
}

// OnPeerState registers a callback when a secondary call PeerConnection changes state.
func (t *CallMediaTransport) OnPeerState(cb func(scopeID, peerAddr string, state webrtc.PeerConnectionState)) {
	t.mu.Lock()
	t.onPeerState = cb
	t.mu.Unlock()
}

// OnError registers a callback invoked when asynchronous secondary call signaling/ICE fails.
func (t *CallMediaTransport) OnError(cb func(scopeID, peerAddr, op string, err error)) {
	t.mu.Lock()
	t.onError = cb
	t.mu.Unlock()
}

func (t *CallMediaTransport) reportError(scopeID, peerAddr, op string, err error) {
	if err == nil {
		return
	}
	t.mu.Lock()
	cb := t.onError
	t.mu.Unlock()
	if cb != nil {
		cb(scopeID, peerAddr, op, err)
	}
}

// Stats returns a snapshot of encrypted, decrypted, and rejected SFrame frame counters.
func (t *CallMediaTransport) Stats() CallMediaStats {
	return CallMediaStats{
		EncryptedAudio: t.encAudio.Load(),
		EncryptedVideo: t.encVideo.Load(),
		DecryptedAudio: t.decAudio.Load(),
		DecryptedVideo: t.decVideo.Load(),
		Rejected:       t.rejected.Load(),
	}
}

// AttachNode wires a cotilla.Node's Hooks onto t while preserving any existing hook handlers in base.
func (t *CallMediaTransport) AttachNode(n *cot.Node, base cot.Hooks) cot.Hooks {
	grace := cot.DefaultConfig().CallEpochGrace
	if n != nil {
		grace = n.Cfg.CallEpochGrace
	}
	if base.OnSFrameKeysUpdated != nil {
		prevKeys := base.OnSFrameKeysUpdated
		base.OnSFrameKeysUpdated = func(scopeID string, isDM bool, bundle *cot.SFrameKeyBundle) {
			_ = t.UpdateSFrameBundle(bundle, grace)
			prevKeys(scopeID, isDM, bundle)
		}
	} else {
		base.OnSFrameKeysUpdated = func(scopeID string, isDM bool, bundle *cot.SFrameKeyBundle) {
			_ = t.UpdateSFrameBundle(bundle, grace)
		}
	}

	if base.OnCallPresence != nil {
		prevPresence := base.OnCallPresence
		base.OnCallPresence = func(scopeID string, isDM bool, from string, payload *cot.CallPresencePayload) {
			t.HandlePresence(scopeID, from, payload)
			prevPresence(scopeID, isDM, from, payload)
		}
	} else {
		base.OnCallPresence = func(scopeID string, isDM bool, from string, payload *cot.CallPresencePayload) {
			t.HandlePresence(scopeID, from, payload)
		}
	}

	if base.OnCallSignal != nil {
		prevSig := base.OnCallSignal
		base.OnCallSignal = func(sig *cot.CallSignalPayload) {
			t.HandleSignal(sig)
			prevSig(sig)
		}
	} else {
		base.OnCallSignal = func(sig *cot.CallSignalPayload) {
			t.HandleSignal(sig)
		}
	}

	if base.OnCallPeerClosed != nil {
		prevClose := base.OnCallPeerClosed
		base.OnCallPeerClosed = func(scopeID, peerAddr string) {
			if peerAddr == "" {
				t.CloseScope(scopeID)
			} else {
				t.RevokeAndClosePeer(scopeID, peerAddr)
			}
			prevClose(scopeID, peerAddr)
		}
	} else {
		base.OnCallPeerClosed = func(scopeID, peerAddr string) {
			if peerAddr == "" {
				t.CloseScope(scopeID)
			} else {
				t.RevokeAndClosePeer(scopeID, peerAddr)
			}
		}
	}

	return base
}

func (t *CallMediaTransport) clearPendingOffer(key callPeerKey) {
	t.mu.Lock()
	delete(t.pendingOffers, key)
	t.mu.Unlock()
}

// HandlePresence handles a peer call join/update/leave, initiating the secondary WebRTC offer
// from the deterministic lower address to avoid SDP glare.
func (t *CallMediaTransport) HandlePresence(scopeID, from string, payload *cot.CallPresencePayload) {
	if from == "" || from == t.self || payload == nil {
		return
	}
	if payload.Action == "leave" {
		t.ClosePeer(scopeID, from)
		return
	}
	if t.self >= from {
		return
	}
	key := callPeerKey{ScopeID: scopeID, PeerAddr: from}
	t.mu.Lock()
	if t.pendingOffers == nil {
		t.pendingOffers = make(map[callPeerKey]bool)
	}
	if t.pendingOffers[key] {
		t.mu.Unlock()
		return
	}
	t.pendingOffers[key] = true
	t.mu.Unlock()

	if t.HasPeer(scopeID, from) {
		t.clearPendingOffer(key)
		return
	}

	go func() {
		defer t.clearPendingOffer(key)
		offerSDP, err := t.CreateOffer(scopeID, from)
		if err != nil {
			t.reportError(scopeID, from, "create_offer", err)
			return
		}
		t.mu.Lock()
		sendFn := t.signalSender
		t.mu.Unlock()
		if sendFn != nil {
			if err := sendFn(scopeID, from, "offer", offerSDP); err != nil {
				t.reportError(scopeID, from, "send_offer", err)
			}
		}
	}()
}

// InitiateCallPeers initiates secondary WebRTC offers toward already-active call peers
// for which the local node holds the deterministic lower address.
func (t *CallMediaTransport) InitiateCallPeers(scopeID string, peers []cot.CallPeerState) {
	for _, p := range peers {
		if p.Address == "" || p.Address == t.self {
			continue
		}
		t.HandlePresence(scopeID, p.Address, &cot.CallPresencePayload{
			Action:       "join",
			ScopeID:      scopeID,
			CallID:       p.CallID,
			Epoch:        p.Epoch,
			LeafIndex:    p.LeafIndex,
			SenderEncPub: p.SenderEncPub,
			Audio:        p.Audio,
			Video:        p.Video,
			Screen:       p.Screen,
		})
	}
}

// HandleSignal processes an authenticated & decrypted secondary WebRTC signal for scopeID.
func (t *CallMediaTransport) HandleSignal(sig *cot.CallSignalPayload) {
	if sig == nil || sig.ScopeID == "" || sig.From == "" || sig.From == t.self {
		return
	}
	switch sig.Kind {
	case "offer":
		go func() {
			answerSDP, err := t.AcceptOffer(sig.ScopeID, sig.From, sig.Payload)
			if err != nil {
				t.reportError(sig.ScopeID, sig.From, "accept_offer", err)
				return
			}
			t.mu.Lock()
			sendFn := t.signalSender
			t.mu.Unlock()
			if sendFn != nil {
				if err := sendFn(sig.ScopeID, sig.From, "answer", answerSDP); err != nil {
					t.reportError(sig.ScopeID, sig.From, "send_answer", err)
				}
			}
		}()
	case "answer":
		if err := t.AcceptAnswer(sig.ScopeID, sig.From, sig.Payload); err != nil {
			t.reportError(sig.ScopeID, sig.From, "accept_answer", err)
		}
	case "candidate":
		if err := t.AddCandidate(sig.ScopeID, sig.From, sig.Payload); err != nil {
			t.reportError(sig.ScopeID, sig.From, "add_candidate", err)
		}
	case "bye":
		t.ClosePeer(sig.ScopeID, sig.From)
	}
}
