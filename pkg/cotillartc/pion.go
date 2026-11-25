//go:build !js && !wasip1

// Package cotillartc provides the WebRTC transport for Cotilla ephemeral burner rooms, built on pion/webrtc.
// Primary connections (PionTransport) carry strictly DataChannel overlay/protocol traffic;
// secondary per-call media connections (CallMediaTransport) carry MLS-scoped SFrame audio/video tracks.
package cotillartc

import (
	"fmt"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// PionTransport is a DataChannel-only cotilla.Transport backed by pion/webrtc.
type PionTransport struct {
	self   string
	config webrtc.Configuration

	mu     sync.Mutex
	closed bool
	conns  map[string]*peerConn

	onData        func(from string, data []byte)
	onOpen        func(addr string)
	onClose       func(addr string)
	onStateChange func(addr string, state webrtc.PeerConnectionState)

	overlayPlatform
}

const defaultPendingOfferTTL = 3 * time.Second

type peerConn struct {
	pc        *webrtc.PeerConnection
	dc        *webrtc.DataChannel
	open      bool
	state     webrtc.PeerConnectionState
	createdAt time.Time
}

// New creates a DataChannel-only WebRTC overlay transport for the local address `self`.
func New(self string, stunURLs []string, onData func(from string, data []byte)) *PionTransport {
	cfg := webrtc.Configuration{
		BundlePolicy: webrtc.BundlePolicyMaxBundle,
	}
	if len(stunURLs) > 0 {
		cfg.ICEServers = []webrtc.ICEServer{{URLs: stunURLs}}
	}

	t := &PionTransport{
		self:   self,
		config: cfg,
		conns:  map[string]*peerConn{},
		onData: onData,
	}
	t.initPlatform()
	return t
}

// OnOpen registers a callback fired when a peer's data channel opens.
func (t *PionTransport) OnOpen(f func(addr string)) {
	t.mu.Lock()
	t.onOpen = f
	t.mu.Unlock()
}

// OnClose registers a callback fired when a peer's data channel or connection closes.
func (t *PionTransport) OnClose(f func(addr string)) {
	t.mu.Lock()
	t.onClose = f
	t.mu.Unlock()
}

// OnStateChange registers a callback fired when a peer's connection state transitions.
func (t *PionTransport) OnStateChange(f func(addr string, state webrtc.PeerConnectionState)) {
	t.mu.Lock()
	t.onStateChange = f
	t.mu.Unlock()
}

func isPeerActiveOrPending(c *peerConn) bool {
	if c == nil {
		return false
	}
	if c.state == webrtc.PeerConnectionStateFailed ||
		c.state == webrtc.PeerConnectionStateClosed ||
		c.state == webrtc.PeerConnectionStateDisconnected {
		return false
	}
	if !c.open && c.state != webrtc.PeerConnectionStateConnected && !c.createdAt.IsZero() && time.Since(c.createdAt) > defaultPendingOfferTTL {
		return false
	}
	return true
}

// HasActiveOrPending returns true if addr currently has an open or in-progress connection.
func (t *PionTransport) HasActiveOrPending(addr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return isPeerActiveOrPending(t.conns[addr])
}

// ClosePeer closes and cleans up an existing connection to addr.
func (t *PionTransport) ClosePeer(addr string) {
	t.closePeerInternal(addr, true)
}

func (t *PionTransport) closePeerIfMatches(addr string, target *peerConn) {
	if target == nil {
		return
	}
	t.mu.Lock()
	if t.conns[addr] == target {
		delete(t.conns, addr)
	}
	dc := target.dc
	pc := target.pc
	target.open = false
	t.mu.Unlock()

	if dc != nil {
		_ = dc.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
}

func (t *PionTransport) closePeerInternal(addr string, notifyClose bool) {
	t.mu.Lock()
	c := t.conns[addr]
	delete(t.conns, addr)
	wasOpen := c != nil && c.open
	var dc *webrtc.DataChannel
	var pc *webrtc.PeerConnection
	if c != nil {
		c.open = false
		dc = c.dc
		pc = c.pc
	}
	onClose := t.onClose
	t.mu.Unlock()

	if dc != nil {
		_ = dc.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}

	if notifyClose && wasOpen && onClose != nil {
		go onClose(addr)
	}
}

func (t *PionTransport) newPC(addr string, replaceExisting bool) (*peerConn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("cotillartc: transport closed")
	}
	if !replaceExisting && isPeerActiveOrPending(t.conns[addr]) {
		t.mu.Unlock()
		return nil, fmt.Errorf("cotillartc: peer %s already has active or pending connection", addr)
	}
	t.mu.Unlock()

	if replaceExisting {
		// Cleanly teardown any prior connection to this peer without firing onClose
		t.closePeerInternal(addr, false)
	}

	pc, err := t.createPeerConnection(t.config)
	if err != nil {
		return nil, err
	}

	c := &peerConn{pc: pc, createdAt: time.Now()}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = pc.Close()
		return nil, fmt.Errorf("cotillartc: transport closed")
	}
	if !replaceExisting && isPeerActiveOrPending(t.conns[addr]) {
		t.mu.Unlock()
		_ = pc.Close()
		return nil, fmt.Errorf("cotillartc: peer %s already has active or pending connection", addr)
	}
	prev := t.conns[addr]
	t.conns[addr] = c
	t.mu.Unlock()
	if prev != nil {
		if prev.dc != nil {
			_ = prev.dc.Close()
		}
		if prev.pc != nil {
			_ = prev.pc.Close()
		}
	}

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		t.mu.Lock()
		// Only apply state change if this is still the active connection for addr
		if t.conns[addr] != c {
			t.mu.Unlock()
			return
		}
		c.state = state
		wasOpen := c.open
		shouldClosePC := false
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			c.open = false
			delete(t.conns, addr)
			shouldClosePC = true
		}
		onClose := t.onClose
		onStateChange := t.onStateChange
		t.mu.Unlock()

		if shouldClosePC {
			go func(p *webrtc.PeerConnection) { _ = p.Close() }(pc)
		}
		if wasOpen && (state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed) {
			if onClose != nil {
				go onClose(addr)
			}
		}

		if onStateChange != nil {
			onStateChange(addr, state)
		}
	})

	return c, nil
}

func (t *PionTransport) bindChannel(addr string, c *peerConn, dc *webrtc.DataChannel) {
	t.mu.Lock()
	if t.closed || t.conns[addr] != c {
		t.mu.Unlock()
		_ = dc.Close()
		return
	}
	c.dc = dc
	t.mu.Unlock()
	dc.OnOpen(func() {
		t.mu.Lock()
		if t.closed || t.conns[addr] != c {
			t.mu.Unlock()
			return
		}
		c.open = true
		onOpen := t.onOpen
		t.mu.Unlock()
		if onOpen != nil {
			onOpen(addr)
		}
	})
	dc.OnClose(func() {
		t.mu.Lock()
		if t.closed || t.conns[addr] != c {
			t.mu.Unlock()
			return
		}
		delete(t.conns, addr)
		wasOpen := c.open
		c.open = false
		onClose := t.onClose
		t.mu.Unlock()
		go func(p *webrtc.PeerConnection) { _ = p.Close() }(c.pc)
		if wasOpen && onClose != nil {
			go onClose(addr)
		}
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return
		}
		onData := t.onData
		t.mu.Unlock()
		if onData != nil {
			onData(addr, msg.Data)
		}
	})
}

// CreateOffer starts a connection to peerAddr and returns the local SDP offer (with ICE candidates gathered).
func (t *PionTransport) CreateOffer(peerAddr string) (string, error) {
	c, err := t.newPC(peerAddr, false)
	if err != nil {
		return "", err
	}
	dc, err := c.pc.CreateDataChannel("cotilla", nil)
	if err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	t.bindChannel(peerAddr, c, dc)

	offer, err := c.pc.CreateOffer(nil)
	if err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	gather := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(offer); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	select {
	case <-gather:
	case <-time.After(2 * time.Second):
	}
	t.mu.Lock()
	stillCurrent := !t.closed && t.conns[peerAddr] == c
	t.mu.Unlock()
	if !stillCurrent {
		return "", fmt.Errorf("cotillartc: offer for %s superseded", peerAddr)
	}
	ld := c.pc.LocalDescription()
	if ld == nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing local offer SDP for %s", peerAddr)
	}
	return ld.SDP, nil
}

// AcceptOffer handles an inbound offer from peerAddr and returns the local answer SDP.
func (t *PionTransport) AcceptOffer(peerAddr, offerSDP string) (string, error) {
	t.mu.Lock()
	existing := t.conns[peerAddr]
	glareImpolite := isPeerActiveOrPending(existing) &&
		existing.pc != nil &&
		!existing.open &&
		existing.pc.SignalingState() == webrtc.SignalingStateHaveLocalOffer &&
		t.self != "" &&
		t.self > peerAddr
	t.mu.Unlock()
	if glareImpolite {
		return "", fmt.Errorf("cotillartc: offer glare with %s (keeping local offer)", peerAddr)
	}

	c, err := t.newPC(peerAddr, true)
	if err != nil {
		return "", err
	}
	c.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		t.bindChannel(peerAddr, c, dc)
	})

	if err := c.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: offerSDP,
	}); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	answer, err := c.pc.CreateAnswer(nil)
	if err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	gather := webrtc.GatheringCompletePromise(c.pc)
	if err := c.pc.SetLocalDescription(answer); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}
	select {
	case <-gather:
	case <-time.After(2 * time.Second):
	}
	t.mu.Lock()
	stillCurrent := !t.closed && t.conns[peerAddr] == c
	t.mu.Unlock()
	if !stillCurrent {
		return "", fmt.Errorf("cotillartc: answer for %s superseded", peerAddr)
	}
	ld := c.pc.LocalDescription()
	if ld == nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing local answer SDP for %s", peerAddr)
	}
	return ld.SDP, nil
}

// AcceptAnswer completes the handshake for an offered connection.
func (t *PionTransport) AcceptAnswer(peerAddr, answerSDP string) error {
	t.mu.Lock()
	c := t.conns[peerAddr]
	t.mu.Unlock()
	if c == nil || c.pc == nil {
		return fmt.Errorf("cotillartc: no pending offer for %s", peerAddr)
	}
	return c.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: answerSDP,
	})
}

// Send delivers data to one peer over its data channel.
func (t *PionTransport) Send(addr string, data []byte) error {
	t.mu.Lock()
	c := t.conns[addr]
	var dc *webrtc.DataChannel
	open := false
	if c != nil {
		dc = c.dc
		open = c.open
	}
	t.mu.Unlock()
	if dc == nil || !open {
		return fmt.Errorf("cotillartc: no open channel to %s", addr)
	}
	return dc.Send(data)
}

// Broadcast delivers to every open peer channel.
func (t *PionTransport) Broadcast(data []byte) {
	for _, addr := range t.Peers() {
		_ = t.Send(addr, data)
	}
}

// Peers returns addresses with an open data channel.
func (t *PionTransport) Peers() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for addr, c := range t.conns {
		if c.open {
			out = append(out, addr)
		}
	}
	return out
}

// PeerTransceiverCount returns the number of RTP transceivers on the primary overlay connection to addr,
// or -1 if not connected. Overlay connections must remain DataChannel-only (0 transceivers).
func (t *PionTransport) PeerTransceiverCount(addr string) int {
	t.mu.Lock()
	c := t.conns[addr]
	t.mu.Unlock()
	if c == nil || c.pc == nil {
		return -1
	}
	return len(c.pc.GetTransceivers())
}

// Close tears down all connections.
func (t *PionTransport) Close() {
	t.mu.Lock()
	t.closed = true
	t.onData = nil
	t.onOpen = nil
	t.onClose = nil
	t.onStateChange = nil
	conns := make([]*peerConn, 0, len(t.conns))
	for _, c := range t.conns {
		c.open = false
		conns = append(conns, c)
	}
	t.conns = map[string]*peerConn{}
	t.mu.Unlock()

	for _, c := range conns {
		if c.dc != nil {
			_ = c.dc.Close()
		}
		if c.pc != nil {
			_ = c.pc.Close()
		}
	}
}
