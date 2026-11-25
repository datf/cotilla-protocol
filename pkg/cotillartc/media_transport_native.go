//go:build !js && !wasip1

package cotillartc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
)

type callScopeState struct {
	keyring    *cot.SFrameKeyring
	audioTrack *webrtc.TrackLocalStaticSample
	videoTrack *webrtc.TrackLocalStaticSample
}

const defaultCallPendingOfferTTL = 10 * time.Second

type callPeerConn struct {
	pc           *webrtc.PeerConnection
	state        webrtc.PeerConnectionState
	createdAt    time.Time
	closed       bool
	stopOnce     sync.Once
	stopCh       chan struct{}
	audioSender  *webrtc.RTPSender
	videoSender  *webrtc.RTPSender
	pendingCands []webrtc.ICECandidateInit
}

type callMediaPlatform struct {
	api     *webrtc.API
	scopes  map[string]*callScopeState
	peers   map[callPeerKey]*callPeerConn
	peerOps map[callPeerKey]*sync.Mutex
}

func (t *CallMediaTransport) initCallPlatform() {
	m := &webrtc.MediaEngine{}
	_ = m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeOpus,
			ClockRate:   48000,
			Channels:    2,
			SDPFmtpLine: "minptime=10;useinbandfec=1",
		},
		PayloadType: 111,
	}, webrtc.RTPCodecTypeAudio)
	_ = m.RegisterCodec(webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
			RTCPFeedback: []webrtc.RTCPFeedback{
				{Type: "nack"},
				{Type: "nack", Parameter: "pli"},
			},
		},
		PayloadType: 96,
	}, webrtc.RTPCodecTypeVideo)

	se := newIsolatedSettingEngine()
	t.api = webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithSettingEngine(se))
	t.scopes = make(map[string]*callScopeState)
	t.peers = make(map[callPeerKey]*callPeerConn)
	t.peerOps = make(map[callPeerKey]*sync.Mutex)
}

func (t *CallMediaTransport) getOrCreateScopeLocked(scopeID string) (*callScopeState, error) {
	if s, ok := t.scopes[scopeID]; ok {
		return s, nil
	}
	audioTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2},
		"audio-"+shortScope(scopeID),
		"cotilla-call-"+shortScope(scopeID),
	)
	if err != nil {
		return nil, err
	}
	videoTrack, err := webrtc.NewTrackLocalStaticSample(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000},
		"video-"+shortScope(scopeID),
		"cotilla-call-"+shortScope(scopeID),
	)
	if err != nil {
		return nil, err
	}
	s := &callScopeState{
		keyring:    cot.NewSFrameKeyring(),
		audioTrack: audioTrack,
		videoTrack: videoTrack,
	}
	t.scopes[scopeID] = s
	return s, nil
}

func shortScope(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// UpdateSFrameBundle installs rotated SFrame epoch keys for scopeID.
func (t *CallMediaTransport) UpdateSFrameBundle(bundle *cot.SFrameKeyBundle, grace time.Duration) error {
	if bundle == nil || bundle.ScopeID == "" {
		return errors.New("cotillartc: invalid SFrame bundle")
	}
	t.mu.Lock()
	sc, err := t.getOrCreateScopeLocked(bundle.ScopeID)
	t.mu.Unlock()
	if err != nil {
		return err
	}
	return sc.keyring.InstallBundle(bundle, grace)
}

// RevokeAndClosePeer immediately zeroes peerAddr's SFrame keys in scopeID and closes its secondary PC.
func (t *CallMediaTransport) RevokeAndClosePeer(scopeID, peerAddr string) {
	t.mu.Lock()
	sc := t.scopes[scopeID]
	t.mu.Unlock()
	if sc != nil {
		sc.keyring.RevokePeer(peerAddr)
	}
	t.ClosePeer(scopeID, peerAddr)
}

func isCallPeerActiveOrPending(c *callPeerConn) bool {
	if c == nil || c.closed {
		return false
	}
	if c.state == webrtc.PeerConnectionStateFailed || c.state == webrtc.PeerConnectionStateClosed {
		return false
	}
	if c.state != webrtc.PeerConnectionStateConnected && !c.createdAt.IsZero() && time.Since(c.createdAt) > defaultCallPendingOfferTTL {
		return false
	}
	return true
}

// HasPeer reports whether an active or connecting secondary PeerConnection exists for (scopeID, peerAddr).
func (t *CallMediaTransport) HasPeer(scopeID, peerAddr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return isCallPeerActiveOrPending(t.peers[callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}])
}

func (t *CallMediaTransport) peerOpMutex(scopeID, peerAddr string) *sync.Mutex {
	key := callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}
	t.mu.Lock()
	if t.peerOps == nil {
		t.peerOps = make(map[callPeerKey]*sync.Mutex)
	}
	mu := t.peerOps[key]
	if mu == nil {
		mu = &sync.Mutex{}
		t.peerOps[key] = mu
	}
	t.mu.Unlock()
	return mu
}

func (t *CallMediaTransport) closePeerIfMatches(scopeID, peerAddr string, target *callPeerConn) {
	if target == nil {
		return
	}
	key := callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}
	t.mu.Lock()
	if t.peers[key] == target {
		delete(t.peers, key)
	}
	target.closed = true
	target.stopOnce.Do(func() { close(target.stopCh) })
	pc := target.pc
	t.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (t *CallMediaTransport) isPeerClosed(scopeID, peerAddr string, target *callPeerConn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if target == nil || target.closed {
		return true
	}
	return t.peers[callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}] != target
}

// ConnectedPeers returns peer addresses currently connected for secondary media in scopeID.
func (t *CallMediaTransport) ConnectedPeers(scopeID string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for k, c := range t.peers {
		if k.ScopeID == scopeID && !c.closed && c.state == webrtc.PeerConnectionStateConnected {
			out = append(out, k.PeerAddr)
		}
	}
	return out
}

func (t *CallMediaTransport) newCallPC(scopeID, peerAddr string) (*callPeerConn, error) {
	t.ClosePeer(scopeID, peerAddr)

	t.mu.Lock()
	sc, err := t.getOrCreateScopeLocked(scopeID)
	api := t.api
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}

	pc, err := api.NewPeerConnection(t.config)
	if err != nil {
		return nil, err
	}

	audioSender, err := pc.AddTrack(sc.audioTrack)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	videoSender, err := pc.AddTrack(sc.videoTrack)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}

	c := &callPeerConn{
		pc:          pc,
		createdAt:   time.Now(),
		stopCh:      make(chan struct{}),
		audioSender: audioSender,
		videoSender: videoSender,
	}

	// Drain sender RTCP so feedback packets don't block internal buffers.
	go drainSenderRTCP(audioSender, c.stopCh)
	go drainSenderRTCP(videoSender, c.stopCh)

	key := callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}
	t.mu.Lock()
	t.peers[key] = c
	t.mu.Unlock()

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		t.mu.Lock()
		if t.peers[key] != c {
			t.mu.Unlock()
			return
		}
		c.state = state
		cb := t.onPeerState
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			c.closed = true
			c.stopOnce.Do(func() { close(c.stopCh) })
			delete(t.peers, key)
		}
		t.mu.Unlock()

		if cb != nil {
			cb(scopeID, peerAddr, state)
		}
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		go t.readRemoteTrack(scopeID, peerAddr, sc, track, c.stopCh)
	})

	return c, nil
}

func drainSenderRTCP(sender *webrtc.RTPSender, stopCh <-chan struct{}) {
	if sender == nil {
		return
	}
	rtcpBuf := make([]byte, 1500)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		if _, _, err := sender.Read(rtcpBuf); err != nil {
			return
		}
	}
}

func (t *CallMediaTransport) readRemoteTrack(scopeID, peerAddr string, sc *callScopeState, track *webrtc.TrackRemote, stopCh <-chan struct{}) {
	var kind string
	switch track.Kind() {
	case webrtc.RTPCodecTypeAudio:
		kind = MediaKindAudio
	case webrtc.RTPCodecTypeVideo:
		kind = MediaKindVideo
	default:
		return
	}

	var vp8Buf []byte
	var expectedSeq uint16
	var frameTS uint32
	assembling := false

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		pkt, _, err := track.ReadRTP()
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
		if len(pkt.Payload) == 0 {
			continue
		}

		var encryptedFrame []byte
		if kind == MediaKindAudio {
			encryptedFrame = pkt.Payload
		} else {
			var vp8Pkt codecs.VP8Packet
			if _, err := vp8Pkt.Unmarshal(pkt.Payload); err != nil || len(vp8Pkt.Payload) == 0 {
				assembling = false
				continue
			}
			if vp8Pkt.S == 1 && vp8Pkt.PID == 0 {
				vp8Buf = append(vp8Buf[:0], vp8Pkt.Payload...)
				expectedSeq = pkt.SequenceNumber + 1
				frameTS = pkt.Timestamp
				assembling = true
			} else if assembling && pkt.SequenceNumber == expectedSeq && pkt.Timestamp == frameTS {
				if len(vp8Buf)+len(vp8Pkt.Payload) > 2*1024*1024 {
					assembling = false
					continue
				}
				vp8Buf = append(vp8Buf, vp8Pkt.Payload...)
				expectedSeq++
			} else {
				assembling = false
				continue
			}
			if !pkt.Header.Marker {
				continue
			}
			assembling = false
			encryptedFrame = vp8Buf
		}

		plaintext, kid, decErr := sc.keyring.Decrypt(encryptedFrame, peerAddr)
		if decErr != nil {
			t.rejected.Add(1)
			continue
		}
		if kind == MediaKindAudio {
			t.decAudio.Add(1)
		} else {
			t.decVideo.Add(1)
		}

		t.mu.Lock()
		cb := t.onMediaFrame
		t.mu.Unlock()
		if cb != nil {
			cb(scopeID, peerAddr, kind, kid, plaintext)
		}
	}
}

// CreateOffer allocates a secondary media PeerConnection for (scopeID, peerAddr) and returns the local Offer SDP.
func (t *CallMediaTransport) CreateOffer(scopeID, peerAddr string) (string, error) {
	opMu := t.peerOpMutex(scopeID, peerAddr)
	opMu.Lock()
	defer opMu.Unlock()

	if t.HasPeer(scopeID, peerAddr) {
		return "", fmt.Errorf("cotillartc: peer %s already has active or pending call connection in %s", peerAddr, scopeID)
	}

	c, err := t.newCallPC(scopeID, peerAddr)
	if err != nil {
		return "", err
	}
	offer, err := c.pc.CreateOffer(nil)
	if err != nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", err
	}
	gather := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(offer); err != nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", err
	}
	select {
	case <-gather:
	case <-time.After(2 * time.Second):
	}
	if t.isPeerClosed(scopeID, peerAddr, c) {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", fmt.Errorf("cotillartc: secondary offer aborted for %s", peerAddr)
	}
	ld := c.pc.LocalDescription()
	if ld == nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing secondary offer SDP for %s", peerAddr)
	}
	return ld.SDP, nil
}

// AcceptOffer accepts a remote secondary call Offer SDP and returns an Answer SDP.
func (t *CallMediaTransport) AcceptOffer(scopeID, peerAddr, offerSDP string) (string, error) {
	opMu := t.peerOpMutex(scopeID, peerAddr)
	opMu.Lock()
	defer opMu.Unlock()

	c, err := t.newCallPC(scopeID, peerAddr)
	if err != nil {
		return "", err
	}
	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offerSDP,
	}); err != nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", err
	}
	t.flushCandidates(c)

	answer, err := c.pc.CreateAnswer(nil)
	if err != nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", err
	}
	gather := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(answer); err != nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", err
	}
	select {
	case <-gather:
	case <-time.After(2 * time.Second):
	}
	if t.isPeerClosed(scopeID, peerAddr, c) {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", fmt.Errorf("cotillartc: secondary answer aborted for %s", peerAddr)
	}
	ld := c.pc.LocalDescription()
	if ld == nil {
		t.closePeerIfMatches(scopeID, peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing secondary answer SDP for %s", peerAddr)
	}
	return ld.SDP, nil
}

// AcceptAnswer applies a remote secondary Answer SDP.
func (t *CallMediaTransport) AcceptAnswer(scopeID, peerAddr, answerSDP string) error {
	t.mu.Lock()
	c := t.peers[callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}]
	t.mu.Unlock()
	if c == nil || c.pc == nil || c.closed {
		return fmt.Errorf("cotillartc: no secondary offer pending for (%s, %s)", scopeID, peerAddr)
	}
	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answerSDP,
	}); err != nil {
		return err
	}
	t.flushCandidates(c)
	return nil
}

// AddCandidate applies a serialized trickle ICE candidate JSON to an open/pending secondary PeerConnection.
func (t *CallMediaTransport) AddCandidate(scopeID, peerAddr, candidateJSON string) error {
	var cand webrtc.ICECandidateInit
	if err := json.Unmarshal([]byte(candidateJSON), &cand); err != nil {
		return err
	}
	t.mu.Lock()
	c := t.peers[callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}]
	if c == nil || c.pc == nil || c.closed {
		t.mu.Unlock()
		return nil
	}
	hasRemote := c.pc.RemoteDescription() != nil
	if !hasRemote {
		c.pendingCands = append(c.pendingCands, cand)
		t.mu.Unlock()
		return nil
	}
	pc := c.pc
	t.mu.Unlock()
	return pc.AddICECandidate(cand)
}

func (t *CallMediaTransport) flushCandidates(c *callPeerConn) {
	t.mu.Lock()
	cands := c.pendingCands
	c.pendingCands = nil
	t.mu.Unlock()
	for _, cand := range cands {
		_ = c.pc.AddICECandidate(cand)
	}
}

// WriteAudioFrame SFrame-encrypts an encoded Opus packet and writes it exclusively onto scopeID's
// secondary PeerConnections (fail-closed if no SFrame sender key is installed).
func (t *CallMediaTransport) WriteAudioFrame(scopeID string, opusFrame []byte, duration time.Duration) error {
	if duration <= 0 {
		duration = 20 * time.Millisecond
	}
	t.mu.Lock()
	sc := t.scopes[scopeID]
	t.mu.Unlock()
	if sc == nil {
		return cot.ErrSFrameMissingKey
	}
	ct, err := sc.keyring.Encrypt(opusFrame)
	if err != nil {
		return err
	}
	t.encAudio.Add(1)
	return sc.audioTrack.WriteSample(media.Sample{Data: ct, Duration: duration})
}

// WriteVideoFrame SFrame-encrypts an encoded VP8 frame and writes it exclusively onto scopeID's
// secondary PeerConnections (fail-closed if no SFrame sender key is installed).
func (t *CallMediaTransport) WriteVideoFrame(scopeID string, vp8Frame []byte, duration time.Duration) error {
	if duration <= 0 {
		duration = 33 * time.Millisecond
	}
	t.mu.Lock()
	sc := t.scopes[scopeID]
	t.mu.Unlock()
	if sc == nil {
		return cot.ErrSFrameMissingKey
	}
	ct, err := sc.keyring.Encrypt(vp8Frame)
	if err != nil {
		return err
	}
	t.encVideo.Add(1)
	return sc.videoTrack.WriteSample(media.Sample{Data: ct, Duration: duration})
}

// ClosePeer tears down ONLY the secondary media connection for (scopeID, peerAddr).
func (t *CallMediaTransport) ClosePeer(scopeID, peerAddr string) {
	key := callPeerKey{ScopeID: scopeID, PeerAddr: peerAddr}
	t.mu.Lock()
	c := t.peers[key]
	if c != nil {
		c.closed = true
		c.stopOnce.Do(func() { close(c.stopCh) })
		delete(t.peers, key)
	}
	t.mu.Unlock()
	if c != nil && c.pc != nil {
		_ = c.pc.Close()
	}
}

// CloseScope closes all secondary PeerConnections and clears SFrame keys for scopeID.
func (t *CallMediaTransport) CloseScope(scopeID string) {
	t.mu.Lock()
	var toClose []*callPeerConn
	for k, c := range t.peers {
		if k.ScopeID == scopeID {
			c.closed = true
			c.stopOnce.Do(func() { close(c.stopCh) })
			toClose = append(toClose, c)
			delete(t.peers, k)
		}
	}
	sc := t.scopes[scopeID]
	if sc != nil {
		sc.keyring.Clear()
		delete(t.scopes, scopeID)
	}
	t.mu.Unlock()

	for _, c := range toClose {
		if c.pc != nil {
			_ = c.pc.Close()
		}
	}
}

// Close closes every secondary PeerConnection and zeroes all SFrame keyrings.
func (t *CallMediaTransport) Close() {
	t.mu.Lock()
	var toClose []*callPeerConn
	for k, c := range t.peers {
		c.closed = true
		c.stopOnce.Do(func() { close(c.stopCh) })
		toClose = append(toClose, c)
		delete(t.peers, k)
	}
	for id, sc := range t.scopes {
		sc.keyring.Clear()
		delete(t.scopes, id)
	}
	t.mu.Unlock()
	for _, c := range toClose {
		if c.pc != nil {
			_ = c.pc.Close()
		}
	}
}
