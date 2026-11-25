//go:build js && wasm

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"syscall/js"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

var (
	self        *cot.Identity
	node        *cot.Node
	pion        *rtc.PionTransport
	protocolCfg = cot.DefaultConfig()
	stunConfig  []string

	jsOnMessage            js.Value
	jsOnAttachmentOffer    js.Value
	jsOnAttachmentProgress js.Value
	jsOnAttachment         js.Value
	jsOnCallPresence       js.Value
	jsOnCallSignal         js.Value
	jsOnSFrameKeysUpdated  js.Value
	jsOnCallPeerClosed     js.Value
	jsOnDirectInvite       js.Value
	jsOnInviteResponse     js.Value
	jsOnPeerJoined         js.Value
	jsOnPeerLeft           js.Value
	jsOnOpen               js.Value
	jsOnDMMessage          js.Value
	jsOnMemberEvicted      js.Value
	jsOnEpochCommit        js.Value
	jsOnAnchorIntro        js.Value
	jsOnAnchorDeficit      js.Value
	jsOnAnchorSolicit      js.Value
	jsOnChannelDiscovered  js.Value
	jsOnAppManifest        js.Value
	jsOnAppBundleReady     js.Value

	quitCh        = make(chan struct{})
	quitOnce      sync.Once
	quitTimerOnce sync.Once
	dmMu          sync.RWMutex
	dmSessions    = make(map[string]cot.RoomKey)
	dmInvitePeers = make(map[string]string)
)

// protocolJSON mirrors configurable protocol knobs accepted by cotilla.init(configJSON).
type protocolJSON struct {
	MaxPeers               int      `json:"maxPeers"`
	MinPrivateGroupPeers   int      `json:"minPrivateGroupPeers"`
	MinPublicGroupPeers    int      `json:"minPublicGroupPeers"`
	InitialBroadcastTTL    int      `json:"initialBroadcastTTL"`
	InitialBroadcastFanout int      `json:"initialBroadcastFanout"`
	PrivateGroupTTL        int      `json:"privateGroupTTL"`
	PublicGroupTTL         int      `json:"publicGroupTTL"`
	ShuffleIntervalMs      int64    `json:"shuffleIntervalMs"`
	BroadcastHopTimeoutMs  int64    `json:"broadcastHopTimeoutMs"`
	STUNServers            []string `json:"stunServers"`
}

// initConfigJSON is the declarative JSON object accepted by cotilla.init(configJSON).
type initConfigJSON struct {
	Seed     string        `json:"seed"`
	Protocol *protocolJSON `json:"protocol"`
}

func applyProtocolConfig(p *protocolJSON) {
	cfg := cot.DefaultConfig()
	if p == nil {
		protocolCfg = cfg
		stunConfig = nil
		return
	}
	if p.MaxPeers > 0 {
		cfg.MaxPeers = p.MaxPeers
	}
	if p.MinPrivateGroupPeers > 0 {
		cfg.MinPrivateGroupPeers = p.MinPrivateGroupPeers
	}
	if p.MinPublicGroupPeers > 0 {
		cfg.MinPublicGroupPeers = p.MinPublicGroupPeers
	}
	if p.InitialBroadcastTTL > 0 {
		cfg.InitialBroadcastTTL = p.InitialBroadcastTTL
	}
	if p.InitialBroadcastFanout > 0 {
		cfg.InitialBroadcastFanout = p.InitialBroadcastFanout
	}
	if p.PrivateGroupTTL > 0 {
		cfg.PrivateGroupTTL = p.PrivateGroupTTL
	}
	if p.PublicGroupTTL > 0 {
		cfg.PublicGroupTTL = p.PublicGroupTTL
	}
	if p.ShuffleIntervalMs > 0 {
		cfg.ShuffleInterval = time.Duration(p.ShuffleIntervalMs) * time.Millisecond
	}
	if p.BroadcastHopTimeoutMs > 0 {
		cfg.BroadcastHopTimeout = time.Duration(p.BroadcastHopTimeoutMs) * time.Millisecond
	}
	protocolCfg = cfg
	stunConfig = append([]string(nil), p.STUNServers...)
}

func newPromise(fn func() (any, error)) any {
	var handler js.Func
	handler = js.FuncOf(func(this js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			defer handler.Release()
			res, err := fn()
			if err != nil {
				reject.Invoke(err.Error())
			} else {
				resolve.Invoke(res)
			}
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func result(v any) any {
	b, _ := json.Marshal(v)
	return string(b)
}

func errResult(e error) any {
	return result(map[string]string{"error": e.Error()})
}

func jsBytesToGo(v js.Value) ([]byte, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, errors.New("expected Uint8Array or ArrayBuffer")
	}
	if v.InstanceOf(js.Global().Get("ArrayBuffer")) {
		v = js.Global().Get("Uint8Array").New(v)
	} else if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, errors.New("expected Uint8Array or ArrayBuffer (zero-copy binary boundary)")
	}
	byteLen := v.Get("byteLength").Int()
	if byteLen == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, byteLen)
	js.CopyBytesToGo(buf, v)
	return buf, nil
}

func bytesToJSUint8Array(data []byte) js.Value {
	u8 := js.Global().Get("Uint8Array").New(len(data))
	if len(data) > 0 {
		js.CopyBytesToJS(u8, data)
	}
	return u8
}

func uint64ToJSBytesBE(v uint64) js.Value {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return bytesToJSUint8Array(buf[:])
}

func sframeKeyEntryToJS(e cot.SFrameKeyEntry) map[string]any {
	return map[string]any{
		"kidBE":     uint64ToJSBytesBE(e.KID),
		"epoch":     float64(e.Epoch),
		"leafIndex": e.LeafIndex,
		"address":   e.Address,
		"key":       bytesToJSUint8Array(e.Key[:]),
		"salt":      bytesToJSUint8Array(e.Salt[:]),
	}
}

func sframeBundleToJS(b *cot.SFrameKeyBundle) map[string]any {
	receivers := make([]any, 0, len(b.Receivers))
	for _, r := range b.Receivers {
		receivers = append(receivers, sframeKeyEntryToJS(r))
	}
	return map[string]any{
		"scopeID":   b.ScopeID,
		"epoch":     float64(b.Epoch),
		"leafIndex": b.LeafIndex,
		"sender":    sframeKeyEntryToJS(b.Sender),
		"receivers": receivers,
	}
}

func cleanupSession() {
	if node != nil {
		node.StopMeshSupervisor()
		_ = node.Leave()
		node = nil
	}
	if pion != nil {
		pion.Close()
		pion = nil
	}
	dmMu.Lock()
	for k, rk := range dmSessions {
		for i := range rk {
			rk[i] = 0
		}
		delete(dmSessions, k)
	}
	for k := range dmInvitePeers {
		delete(dmInvitePeers, k)
	}
	dmMu.Unlock()
}

func ensureTransport(stunURLs []string) {
	if len(stunURLs) == 0 {
		stunURLs = stunConfig
	}
	pion = rtc.New(self.Address(), stunURLs, func(from string, data []byte) {
		if node != nil {
			node.HandleWire(from, data)
		}
	})
	pion.OnOpen(func(addr string) {
		if node != nil {
			node.AddPeer(addr)
			if !node.IsGatewayPeer(addr) {
				_ = node.RequestCatchUp()
				go node.BroadcastPeerInfo()
			}
		}
		if jsOnOpen.Type() == js.TypeFunction {
			jsOnOpen.Invoke(addr)
		}
	})
	pion.OnClose(func(addr string) {
		if node != nil {
			node.RemovePeer(addr)
		}
		if jsOnPeerLeft.Type() == js.TypeFunction {
			jsOnPeerLeft.Invoke(addr)
		}
	})
}

func handleDMRelayPayload(payload []byte) {
	var env cot.Envelope
	if err := json.Unmarshal(payload, &env); err != nil || env.RoomID == "" {
		return
	}
	dmMu.RLock()
	key, ok := dmSessions[env.RoomID]
	dmMu.RUnlock()
	if !ok {
		return
	}
	if err := env.Verify(env.RoomID, 5*time.Minute); err != nil {
		return
	}
	plaintext, err := env.Decrypt(key)
	if err != nil {
		return
	}
	var chat cot.ChatPayload
	if err := json.Unmarshal(plaintext, &chat); err != nil {
		return
	}
	if jsOnDMMessage.Type() == js.TypeFunction {
		jsOnDMMessage.Invoke(env.AuthorPubKey, env.RoomID, chat.Text)
	}
}

func buildNodeHooks() cot.Hooks {
	return cot.Hooks{
		OnMessage: func(env *cot.Envelope, plaintext []byte) {
			if jsOnMessage.Type() == js.TypeFunction {
				envJSON, _ := json.Marshal(env)
				jsOnMessage.Invoke(string(envJSON), string(plaintext))
			}
		},
		OnAttachmentOffer: func(meta *cot.AttachmentMeta) {
			if jsOnAttachmentOffer.Type() == js.TypeFunction {
				metaJSON, _ := json.Marshal(meta)
				jsOnAttachmentOffer.Invoke(string(metaJSON))
			}
		},
		OnAttachmentProgress: func(fileID string, receivedChunks, totalChunks int) {
			if jsOnAttachmentProgress.Type() == js.TypeFunction {
				jsOnAttachmentProgress.Invoke(fileID, receivedChunks, totalChunks)
			}
		},
		OnAttachment: func(meta *cot.AttachmentMeta, data []byte) {
			if jsOnAttachment.Type() == js.TypeFunction {
				metaJSON, _ := json.Marshal(meta)
				jsOnAttachment.Invoke(string(metaJSON))
			}
		},
		OnCallPresence: func(scopeID string, isDM bool, from string, payload *cot.CallPresencePayload) {
			if jsOnCallPresence.Type() == js.TypeFunction {
				payJSON, _ := json.Marshal(payload)
				jsOnCallPresence.Invoke(scopeID, isDM, from, string(payJSON))
			}
		},
		OnCallSignal: func(sig *cot.CallSignalPayload) {
			if jsOnCallSignal.Type() == js.TypeFunction {
				sigJSON, _ := json.Marshal(sig)
				jsOnCallSignal.Invoke(string(sigJSON))
			}
		},
		OnSFrameKeysUpdated: func(scopeID string, isDM bool, bundle *cot.SFrameKeyBundle) {
			if bundle == nil {
				return
			}
			defer bundle.Zeroize()
			if jsOnSFrameKeysUpdated.Type() == js.TypeFunction {
				jsOnSFrameKeysUpdated.Invoke(scopeID, isDM, js.ValueOf(sframeBundleToJS(bundle)))
			}
		},
		OnCallPeerClosed: func(scopeID, peerAddr string) {
			if jsOnCallPeerClosed.Type() == js.TypeFunction {
				jsOnCallPeerClosed.Invoke(scopeID, peerAddr)
			}
		},
		OnDirectInvite: func(invite *cot.DirectInvite, payload *cot.InvitePayload) {
			if payload != nil && invite != nil && payload.Type == "dm" && payload.RoomID != "" && invite.FromSignPub != "" {
				dmMu.Lock()
				dmInvitePeers[payload.RoomID] = invite.FromSignPub
				dmMu.Unlock()
			}
			if jsOnDirectInvite.Type() == js.TypeFunction {
				invJSON, _ := json.Marshal(invite)
				payJSON, _ := json.Marshal(payload)
				jsOnDirectInvite.Invoke(string(invJSON), string(payJSON))
			}
		},
		OnInviteResponse: func(res *cot.InviteResponse) {
			if jsOnInviteResponse.Type() == js.TypeFunction {
				resJSON, _ := json.Marshal(res)
				jsOnInviteResponse.Invoke(string(resJSON))
			}
		},
		OnPeerJoined: func(addr string) {
			if jsOnPeerJoined.Type() == js.TypeFunction {
				jsOnPeerJoined.Invoke(addr)
			}
		},
		OnPeerLeft: func(addr string) {
			if jsOnPeerLeft.Type() == js.TypeFunction {
				jsOnPeerLeft.Invoke(addr)
			}
		},
		OnMemberEvicted: func(evictedPeer, evictor, reason string, epochID int64) {
			if jsOnMemberEvicted.Type() == js.TypeFunction {
				jsOnMemberEvicted.Invoke(evictedPeer, evictor, reason, float64(epochID))
			}
		},
		OnEpochCommit: func(commit *cot.EpochCommit) {
			if jsOnEpochCommit.Type() == js.TypeFunction {
				commitJSON, _ := json.Marshal(commit)
				jsOnEpochCommit.Invoke(string(commitJSON))
			}
		},
		OnAnchorIntro: func(anchors []string, fallback bool) {
			if jsOnAnchorIntro.Type() == js.TypeFunction {
				anchorsJSON, _ := json.Marshal(anchors)
				jsOnAnchorIntro.Invoke(string(anchorsJSON), fallback)
			}
		},
		OnAnchorDeficit: func(currentAnchors, activePeers int) {
			if jsOnAnchorDeficit.Type() == js.TypeFunction {
				jsOnAnchorDeficit.Invoke(currentAnchors, activePeers)
			}
		},
		OnAnchorSolicit: func(needed int) {
			if jsOnAnchorSolicit.Type() == js.TypeFunction {
				jsOnAnchorSolicit.Invoke(needed)
			}
		},
		OnChannelDiscovered: func(channelID string, peer string) {
			if jsOnChannelDiscovered.Type() == js.TypeFunction {
				jsOnChannelDiscovered.Invoke(channelID, peer)
			}
		},
		OnAppManifest: func(m *cot.AppManifest, from string) {
			if jsOnAppManifest.Type() == js.TypeFunction {
				b, _ := json.Marshal(m)
				jsOnAppManifest.Invoke(string(b), from)
			}
		},
		OnAppBundleReady: func(m *cot.AppManifest, data []byte) {
			if jsOnAppBundleReady.Type() == js.TypeFunction {
				mBytes, _ := json.Marshal(m)
				jsOnAppBundleReady.Invoke(string(mBytes), bytesToJSUint8Array(data))
			}
		},
		Log: func(msg string) {
			js.Global().Get("console").Call("debug", "[wasm-node]", msg)
		},
		OnRelayPayload: func(from, relayType string, payload []byte) {
			if relayType == "dm" {
				handleDMRelayPayload(payload)
			}
		},
	}
}
