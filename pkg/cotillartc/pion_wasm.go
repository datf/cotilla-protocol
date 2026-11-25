//go:build js && wasm

package cotillartc

import (
	"errors"
	"fmt"
	"sync"
	"syscall/js"
	"time"
)

const defaultPendingOfferTTL = 3 * time.Second

// PionTransport is a DataChannel-only WebRTC transport running directly in the browser via syscall/js.
// It avoids linking pion/webrtc and its native network dependencies into the WebAssembly build.
type PionTransport struct {
	self     string
	stunURLs []string

	mu     sync.Mutex
	closed bool
	conns  map[string]*peerConn

	onData  func(from string, data []byte)
	onOpen  func(addr string)
	onClose func(addr string)
}

type peerConn struct {
	pc        js.Value
	dc        js.Value
	open      bool
	state     string
	createdAt time.Time

	funcs []js.Func
}

func (c *peerConn) close() {
	c.open = false
	c.state = "closed"

	if !c.dc.IsUndefined() && !c.dc.IsNull() {
		c.dc.Set("onopen", js.Null())
		c.dc.Set("onclose", js.Null())
		c.dc.Set("onmessage", js.Null())
		c.dc.Call("close")
	}
	if !c.pc.IsUndefined() && !c.pc.IsNull() {
		c.pc.Set("onconnectionstatechange", js.Null())
		c.pc.Set("onicecandidate", js.Null())
		c.pc.Set("onicegatheringstatechange", js.Null())
		c.pc.Set("ondatachannel", js.Null())
		c.pc.Call("close")
	}
	for _, fn := range c.funcs {
		fn.Release()
	}
	c.funcs = nil
}

func getRTCPeerConnectionCtor() js.Value {
	ctor := js.Global().Get("RTCPeerConnection")
	if !ctor.IsUndefined() && !ctor.IsNull() {
		return ctor
	}
	win := js.Global().Get("window")
	if !win.IsUndefined() && !win.IsNull() {
		ctor = win.Get("RTCPeerConnection")
		if !ctor.IsUndefined() && !ctor.IsNull() {
			return ctor
		}
	}
	return js.Undefined()
}

func awaitPromise(promise js.Value) (js.Value, error) {
	resultsChan := make(chan js.Value, 1)
	errChan := make(chan error, 1)

	var thenFunc, catchFunc js.Func

	thenFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
		var res js.Value
		if len(args) > 0 {
			res = args[0]
		}
		resultsChan <- res
		return js.Undefined()
	})
	defer thenFunc.Release()

	catchFunc = js.FuncOf(func(this js.Value, args []js.Value) any {
		errMsg := "promise rejected"
		if len(args) > 0 {
			if !args[0].IsNull() && !args[0].IsUndefined() {
				if msg := args[0].Get("message"); !msg.IsUndefined() && !msg.IsNull() {
					errMsg = msg.String()
				} else {
					errMsg = args[0].String()
				}
			}
		}
		errChan <- errors.New(errMsg)
		return js.Undefined()
	})
	defer catchFunc.Release()

	promise.Call("then", thenFunc).Call("catch", catchFunc)

	select {
	case res := <-resultsChan:
		return res, nil
	case err := <-errChan:
		return js.Undefined(), err
	}
}

// New creates a DataChannel-only WebRTC overlay transport for the local address self.
func New(self string, stunURLs []string, onData func(from string, data []byte)) *PionTransport {
	return &PionTransport{
		self:     self,
		stunURLs: stunURLs,
		conns:    make(map[string]*peerConn),
		onData:   onData,
	}
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

func isPeerActiveOrPending(c *peerConn) bool {
	if c == nil {
		return false
	}
	if c.state == "failed" || c.state == "closed" || c.state == "disconnected" {
		return false
	}
	if !c.open && c.state != "connected" && !c.createdAt.IsZero() && time.Since(c.createdAt) > defaultPendingOfferTTL {
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
	t.mu.Unlock()
	target.close()
}

func (t *PionTransport) closePeerInternal(addr string, notifyClose bool) {
	t.mu.Lock()
	c := t.conns[addr]
	delete(t.conns, addr)
	wasOpen := c != nil && c.open
	onClose := t.onClose
	t.mu.Unlock()

	if c != nil {
		c.close()
	}

	if notifyClose && wasOpen && onClose != nil {
		go onClose(addr)
	}
}

func (t *PionTransport) newPC(addr string) (*peerConn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("cotillartc: transport closed")
	}
	t.mu.Unlock()

	// Cleanly teardown any prior connection to this peer without firing onClose
	t.closePeerInternal(addr, false)

	ctor := getRTCPeerConnectionCtor()
	if ctor.IsUndefined() || ctor.IsNull() {
		return nil, errors.New("cotillartc: RTCPeerConnection unavailable")
	}

	cfg := js.Global().Get("Object").New()
	cfg.Set("bundlePolicy", "max-bundle")
	if len(t.stunURLs) > 0 {
		iceServers := js.Global().Get("Array").New()
		server := js.Global().Get("Object").New()
		urls := js.Global().Get("Array").New()
		for _, u := range t.stunURLs {
			urls.Call("push", u)
		}
		server.Set("urls", urls)
		iceServers.Call("push", server)
		cfg.Set("iceServers", iceServers)
	}

	pc := ctor.New(cfg)
	c := &peerConn{
		pc:        pc,
		createdAt: time.Now(),
		state:     "new",
	}

	stateChangeFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		state := pc.Get("connectionState").String()
		t.mu.Lock()
		if t.conns[addr] != c {
			t.mu.Unlock()
			return js.Undefined()
		}
		c.state = state
		wasOpen := c.open
		if state == "failed" || state == "closed" {
			c.open = false
			delete(t.conns, addr)
		}
		onClose := t.onClose
		t.mu.Unlock()

		if wasOpen && (state == "failed" || state == "closed") {
			if onClose != nil {
				go onClose(addr)
			}
		}
		return js.Undefined()
	})

	c.funcs = append(c.funcs, stateChangeFn)
	pc.Set("onconnectionstatechange", stateChangeFn)

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.close()
		return nil, fmt.Errorf("cotillartc: transport closed")
	}
	t.conns[addr] = c
	t.mu.Unlock()

	return c, nil
}

func (t *PionTransport) bindChannel(addr string, c *peerConn, dc js.Value) {
	t.mu.Lock()
	if t.closed || t.conns[addr] != c {
		t.mu.Unlock()
		dc.Call("close")
		return
	}
	c.dc = dc
	t.mu.Unlock()

	dc.Set("binaryType", "arraybuffer")

	var onOpenFn, onCloseFn, onMsgFn js.Func

	onOpenFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		t.mu.Lock()
		if t.closed || t.conns[addr] != c {
			t.mu.Unlock()
			return js.Undefined()
		}
		c.open = true
		c.state = "connected"
		onOpen := t.onOpen
		t.mu.Unlock()

		if onOpen != nil {
			go onOpen(addr)
		}
		return js.Undefined()
	})

	onCloseFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		t.mu.Lock()
		if t.closed || t.conns[addr] != c {
			t.mu.Unlock()
			return js.Undefined()
		}
		delete(t.conns, addr)
		wasOpen := c.open
		c.open = false
		c.state = "closed"
		onClose := t.onClose
		t.mu.Unlock()

		if wasOpen && onClose != nil {
			go onClose(addr)
		}
		return js.Undefined()
	})

	onMsgFn = js.FuncOf(func(this js.Value, args []js.Value) any {
		t.mu.Lock()
		closed := t.closed
		onData := t.onData
		t.mu.Unlock()
		if closed || onData == nil || len(args) == 0 {
			return js.Undefined()
		}

		data := args[0].Get("data")
		var buf []byte
		if data.Type() == js.TypeString {
			buf = []byte(data.String())
		} else {
			var u8 js.Value
			cName := ""
			ctor := data.Get("constructor")
			if !ctor.IsUndefined() && !ctor.IsNull() {
				cName = ctor.Get("name").String()
			}
			if cName == "Uint8Array" {
				u8 = data
			} else {
				u8 = js.Global().Get("Uint8Array").New(data)
			}
			n := u8.Get("byteLength").Int()
			buf = make([]byte, n)
			js.CopyBytesToGo(buf, u8)
		}

		go onData(addr, buf)
		return js.Undefined()
	})

	t.mu.Lock()
	c.funcs = append(c.funcs, onOpenFn, onCloseFn, onMsgFn)
	t.mu.Unlock()

	dc.Set("onopen", onOpenFn)
	dc.Set("onclose", onCloseFn)
	dc.Set("onmessage", onMsgFn)
}

// CreateOffer starts a connection to peerAddr and returns the local SDP offer.
func (t *PionTransport) CreateOffer(peerAddr string) (string, error) {
	if t.HasActiveOrPending(peerAddr) {
		return "", fmt.Errorf("cotillartc: peer %s already has active or pending connection", peerAddr)
	}
	c, err := t.newPC(peerAddr)
	if err != nil {
		return "", err
	}
	pc := c.pc

	dc := pc.Call("createDataChannel", "cotilla")
	t.bindChannel(peerAddr, c, dc)

	gatherCh := make(chan struct{})
	var gatherOnce sync.Once
	signalGather := func() {
		gatherOnce.Do(func() {
			close(gatherCh)
		})
	}

	iceCandidateFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			cand := args[0].Get("candidate")
			if cand.IsNull() || cand.IsUndefined() {
				signalGather()
			}
		}
		return js.Undefined()
	})
	iceGatheringFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if !pc.IsUndefined() && !pc.IsNull() && pc.Get("iceGatheringState").String() == "complete" {
			signalGather()
		}
		return js.Undefined()
	})

	pc.Set("onicecandidate", iceCandidateFn)
	pc.Set("onicegatheringstatechange", iceGatheringFn)
	defer func() {
		if !pc.IsUndefined() && !pc.IsNull() {
			pc.Set("onicecandidate", js.Null())
			pc.Set("onicegatheringstatechange", js.Null())
		}
		iceCandidateFn.Release()
		iceGatheringFn.Release()
	}()

	offerPromise := pc.Call("createOffer")
	offer, err := awaitPromise(offerPromise)
	if err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}

	setLocalPromise := pc.Call("setLocalDescription", offer)
	if _, err := awaitPromise(setLocalPromise); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}

	if pc.Get("iceGatheringState").String() == "complete" {
		signalGather()
	}

	select {
	case <-gatherCh:
	case <-time.After(2 * time.Second):
	}

	t.mu.Lock()
	closed := t.closed || t.conns[peerAddr] != c
	t.mu.Unlock()
	if closed {
		return "", fmt.Errorf("cotillartc: peer connection closed during offer creation")
	}

	ld := pc.Get("localDescription")
	if ld.IsNull() || ld.IsUndefined() {
		t.closePeerIfMatches(peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing local offer SDP for %s", peerAddr)
	}
	return ld.Get("sdp").String(), nil
}

// AcceptOffer handles an inbound offer from peerAddr and returns the local answer SDP.
func (t *PionTransport) AcceptOffer(peerAddr, offerSDP string) (string, error) {
	t.mu.Lock()
	existing := t.conns[peerAddr]
	glareImpolite := isPeerActiveOrPending(existing) &&
		!existing.pc.IsUndefined() && !existing.pc.IsNull() &&
		!existing.open &&
		existing.pc.Get("signalingState").String() == "have-local-offer" &&
		t.self != "" &&
		t.self > peerAddr
	t.mu.Unlock()
	if glareImpolite {
		return "", fmt.Errorf("cotillartc: offer glare with %s (keeping local offer)", peerAddr)
	}

	c, err := t.newPC(peerAddr)
	if err != nil {
		return "", err
	}
	pc := c.pc

	dataChannelFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			dc := args[0].Get("channel")
			t.bindChannel(peerAddr, c, dc)
		}
		return js.Undefined()
	})
	c.funcs = append(c.funcs, dataChannelFn)
	pc.Set("ondatachannel", dataChannelFn)

	gatherCh := make(chan struct{})
	var gatherOnce sync.Once
	signalGather := func() {
		gatherOnce.Do(func() {
			close(gatherCh)
		})
	}

	iceCandidateFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			cand := args[0].Get("candidate")
			if cand.IsNull() || cand.IsUndefined() {
				signalGather()
			}
		}
		return js.Undefined()
	})
	iceGatheringFn := js.FuncOf(func(this js.Value, args []js.Value) any {
		if !pc.IsUndefined() && !pc.IsNull() && pc.Get("iceGatheringState").String() == "complete" {
			signalGather()
		}
		return js.Undefined()
	})

	pc.Set("onicecandidate", iceCandidateFn)
	pc.Set("onicegatheringstatechange", iceGatheringFn)
	defer func() {
		if !pc.IsUndefined() && !pc.IsNull() {
			pc.Set("onicecandidate", js.Null())
			pc.Set("onicegatheringstatechange", js.Null())
		}
		iceCandidateFn.Release()
		iceGatheringFn.Release()
	}()

	remoteDesc := js.Global().Get("Object").New()
	remoteDesc.Set("type", "offer")
	remoteDesc.Set("sdp", offerSDP)

	setRemotePromise := pc.Call("setRemoteDescription", remoteDesc)
	if _, err := awaitPromise(setRemotePromise); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}

	answerPromise := pc.Call("createAnswer")
	answer, err := awaitPromise(answerPromise)
	if err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}

	setLocalPromise := pc.Call("setLocalDescription", answer)
	if _, err := awaitPromise(setLocalPromise); err != nil {
		t.closePeerIfMatches(peerAddr, c)
		return "", err
	}

	if pc.Get("iceGatheringState").String() == "complete" {
		signalGather()
	}

	select {
	case <-gatherCh:
	case <-time.After(2 * time.Second):
	}

	t.mu.Lock()
	closed := t.closed || t.conns[peerAddr] != c
	t.mu.Unlock()
	if closed {
		return "", fmt.Errorf("cotillartc: peer connection closed during answer creation")
	}

	ld := pc.Get("localDescription")
	if ld.IsNull() || ld.IsUndefined() {
		t.closePeerIfMatches(peerAddr, c)
		return "", fmt.Errorf("cotillartc: missing local answer SDP for %s", peerAddr)
	}
	return ld.Get("sdp").String(), nil
}

// AcceptAnswer completes the handshake for an offered connection.
func (t *PionTransport) AcceptAnswer(peerAddr, answerSDP string) error {
	t.mu.Lock()
	c := t.conns[peerAddr]
	t.mu.Unlock()
	if c == nil || c.pc.IsUndefined() || c.pc.IsNull() {
		return fmt.Errorf("cotillartc: no pending offer for %s", peerAddr)
	}

	remoteDesc := js.Global().Get("Object").New()
	remoteDesc.Set("type", "answer")
	remoteDesc.Set("sdp", answerSDP)

	promise := c.pc.Call("setRemoteDescription", remoteDesc)
	_, err := awaitPromise(promise)
	return err
}

// Send delivers data to one peer over its data channel.
func (t *PionTransport) Send(addr string, data []byte) (err error) {
	t.mu.Lock()
	c := t.conns[addr]
	var dc js.Value
	open := false
	if c != nil {
		dc = c.dc
		open = c.open
	}
	t.mu.Unlock()

	if dc.IsUndefined() || dc.IsNull() || !open {
		return fmt.Errorf("cotillartc: no open channel to %s", addr)
	}

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cotillartc send panic: %v", r)
		}
	}()

	array := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(array, data)
	dc.Call("send", array)
	return nil
}

// Broadcast delivers data to every open peer channel.
func (t *PionTransport) Broadcast(data []byte) {
	for _, addr := range t.Peers() {
		_ = t.Send(addr, data)
	}
}

// Peers returns addresses with an open data channel.
func (t *PionTransport) Peers() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.conns))
	for addr, c := range t.conns {
		if c.open {
			out = append(out, addr)
		}
	}
	return out
}

// PeerTransceiverCount returns the number of RTP transceivers on the connection to addr.
// Primary overlay connections are strictly DataChannel-only (0 transceivers).
func (t *PionTransport) PeerTransceiverCount(addr string) int {
	t.mu.Lock()
	c := t.conns[addr]
	t.mu.Unlock()
	if c == nil || c.pc.IsUndefined() || c.pc.IsNull() {
		return -1
	}
	transceivers := c.pc.Call("getTransceivers")
	if transceivers.IsUndefined() || transceivers.IsNull() {
		return 0
	}
	return transceivers.Length()
}

// Close tears down all connections.
func (t *PionTransport) Close() {
	t.mu.Lock()
	t.closed = true
	t.onData = nil
	t.onOpen = nil
	t.onClose = nil
	conns := make([]*peerConn, 0, len(t.conns))
	for _, c := range t.conns {
		c.open = false
		conns = append(conns, c)
	}
	t.conns = make(map[string]*peerConn)
	t.mu.Unlock()

	for _, c := range conns {
		c.close()
	}
}
