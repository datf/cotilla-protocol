//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

// jsInit initializes or restores the client identity and optional protocol configuration.
// Accepts either a hex seed string or a JSON object `{ seed, protocol: { maxPeers, ... } }`.
func jsInit(this js.Value, args []js.Value) any {
	seedHex := ""
	if len(args) > 0 {
		switch args[0].Type() {
		case js.TypeString:
			raw := strings.TrimSpace(args[0].String())
			if strings.HasPrefix(raw, "{") {
				var cfg initConfigJSON
				if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
					return errResult(fmt.Errorf("invalid init config JSON: %w", err))
				}
				seedHex = cfg.Seed
				applyProtocolConfig(cfg.Protocol)
			} else {
				seedHex = raw
			}
		case js.TypeObject:
			raw := js.Global().Get("JSON").Call("stringify", args[0]).String()
			var cfg initConfigJSON
			if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
				return errResult(fmt.Errorf("invalid init config object: %w", err))
			}
			seedHex = cfg.Seed
			applyProtocolConfig(cfg.Protocol)
		}
	}

	var (
		id  *cot.Identity
		err error
	)
	if seedHex != "" {
		seed, decErr := hex.DecodeString(seedHex)
		if decErr != nil {
			return errResult(decErr)
		}
		id, err = cot.NewIdentityFromSeed(seed)
	} else {
		id, err = cot.NewIdentity()
	}
	if err != nil {
		return errResult(err)
	}
	self = id

	return result(map[string]any{
		"address": id.Address(),
		"signPub": hex.EncodeToString(id.SignPub),
	})
}

func jsCreateOffer(this js.Value, args []js.Value) any {
	if pion == nil || len(args) < 1 {
		return newPromise(func() (any, error) {
			return nil, fmt.Errorf("transport not initialized or missing peer")
		})
	}
	peer := args[0].String()
	return newPromise(func() (any, error) { return pion.CreateOffer(peer) })
}

func jsAcceptOffer(this js.Value, args []js.Value) any {
	if pion == nil || len(args) < 2 {
		return newPromise(func() (any, error) {
			return nil, fmt.Errorf("transport not initialized or missing offer args")
		})
	}
	peer, sdp := args[0].String(), args[1].String()
	return newPromise(func() (any, error) { return pion.AcceptOffer(peer, sdp) })
}

func jsAcceptAnswer(this js.Value, args []js.Value) any {
	if pion == nil || len(args) < 2 {
		return newPromise(func() (any, error) {
			return nil, fmt.Errorf("transport not initialized or missing answer args")
		})
	}
	peer, sdp := args[0].String(), args[1].String()
	return newPromise(func() (any, error) { return nil, pion.AcceptAnswer(peer, sdp) })
}

func jsConnectedPeers(this js.Value, args []js.Value) any {
	if pion == nil {
		return result([]string{})
	}
	return result(pion.Peers())
}

func jsAddPeer(this js.Value, args []js.Value) any {
	if node != nil && len(args) > 0 {
		node.AddPeer(args[0].String())
	}
	return nil
}

func jsRemovePeer(this js.Value, args []js.Value) any {
	if node != nil && len(args) > 0 {
		node.RemovePeer(args[0].String())
	}
	return nil
}

func jsClosePeer(this js.Value, args []js.Value) any {
	if pion != nil && len(args) > 0 {
		pion.ClosePeer(args[0].String())
	}
	return nil
}

func jsPeerEncKeys(this js.Value, args []js.Value) any {
	if node == nil {
		return result(map[string]string{})
	}
	return result(node.PeerEncKeys())
}

func jsBroadcastPeerInfo(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	go node.BroadcastPeerInfo()
	return result(map[string]string{"status": "ok"})
}

func jsSignSignaling(this js.Value, args []js.Value) any {
	if self == nil {
		return errResult(fmt.Errorf("identity not initialized"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("signSignaling requires msgType[, target, sdp]"))
	}
	msgType := args[0].String()
	target, sdp := "", ""
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		target = args[1].String()
	}
	if len(args) > 2 && !args[2].IsUndefined() && !args[2].IsNull() {
		sdp = args[2].String()
	}
	ts := time.Now().UnixMilli()
	canonical := cot.CanonicalSignalingMsg(msgType, self.Address(), target, sdp, ts)
	sig := hex.EncodeToString(self.Sign(canonical))
	msg := map[string]any{
		"type":      msgType,
		"peer":      self.Address(),
		"timestamp": ts,
		"signature": sig,
	}
	if target != "" {
		msg["target"] = target
	}
	if sdp != "" {
		msg["sdp"] = sdp
	}
	return result(msg)
}

func jsVerifySignaling(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return false
	}
	var msg struct {
		Type      string `json:"type"`
		Peer      string `json:"peer"`
		Target    string `json:"target"`
		SDP       string `json:"sdp"`
		Timestamp int64  `json:"timestamp"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal([]byte(args[0].String()), &msg); err != nil {
		return false
	}
	if (msg.Type != "signal" && msg.Type != "offer" && msg.Type != "answer") ||
		msg.Peer == "" || msg.Target == "" || msg.SDP == "" || msg.Signature == "" {
		return false
	}
	if self != nil && msg.Target != self.Address() {
		return false
	}
	diff := time.Now().UnixMilli() - msg.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if diff > cot.DefaultConfig().ReplayWindow.Milliseconds() {
		return false
	}
	canonical := cot.CanonicalSignalingMsg(msg.Type, msg.Peer, msg.Target, msg.SDP, msg.Timestamp)
	return cot.Verify(msg.Peer, canonical, msg.Signature)
}

func jsAddGatewayPeer(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 || args[0].String() == "" {
		return false
	}
	node.AddGatewayPeer(args[0].String())
	return true
}

func jsIsGatewayPeer(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return false
	}
	return node.IsGatewayPeer(args[0].String())
}

func jsHasGatewayConn(this js.Value, args []js.Value) any {
	if node == nil || pion == nil {
		return false
	}
	for _, p := range pion.Peers() {
		if node.IsGatewayPeer(p) {
			return true
		}
	}
	return false
}

func jsQueryPeers(this js.Value, args []js.Value) any {
	if node == nil {
		return false
	}
	go node.QueryPeers()
	return true
}

func jsNetworkStatus(this js.Value, args []js.Value) any {
	if node == nil {
		return result(map[string]any{"status": "uninitialized"})
	}
	peers := []string{}
	if pion != nil {
		peers = pion.Peers()
	}
	return result(map[string]any{
		"anchors":  node.AnchorPeers(),
		"fallback": node.IsFallbackMode(),
		"peers":    peers,
	})
}

func jsAddAnchorPeer(this js.Value, args []js.Value) any {
	if node != nil && len(args) >= 1 && args[0].String() != "" {
		node.AddAnchorPeer(args[0].String())
	}
	return nil
}

func jsSetFallbackMode(this js.Value, args []js.Value) any {
	if node != nil && len(args) >= 1 {
		node.SetFallbackMode(args[0].Bool())
	}
	return nil
}

func jsSolicitAnchors(this js.Value, args []js.Value) any {
	if node == nil {
		return nil
	}
	needed := 1
	if len(args) >= 1 && args[0].Type() == js.TypeNumber {
		needed = args[0].Int()
	}
	var exclude []string
	if len(args) >= 2 && args[1].Type() == js.TypeString && args[1].String() != "" {
		_ = json.Unmarshal([]byte(args[1].String()), &exclude)
	}
	node.SolicitAnchors(needed, exclude)
	return nil
}

func jsShutdown(this js.Value, args []js.Value) any {
	jsOnMessage = js.Undefined()
	jsOnAttachmentOffer = js.Undefined()
	jsOnAttachmentProgress = js.Undefined()
	jsOnAttachment = js.Undefined()
	jsOnCallPresence = js.Undefined()
	jsOnCallSignal = js.Undefined()
	jsOnSFrameKeysUpdated = js.Undefined()
	jsOnCallPeerClosed = js.Undefined()
	jsOnDirectInvite = js.Undefined()
	jsOnInviteResponse = js.Undefined()
	jsOnPeerJoined = js.Undefined()
	jsOnPeerLeft = js.Undefined()
	jsOnOpen = js.Undefined()
	jsOnDMMessage = js.Undefined()
	jsOnMemberEvicted = js.Undefined()
	jsOnEpochCommit = js.Undefined()
	jsOnAnchorIntro = js.Undefined()
	jsOnAnchorDeficit = js.Undefined()
	jsOnAnchorSolicit = js.Undefined()
	jsOnChannelDiscovered = js.Undefined()
	jsOnAppManifest = js.Undefined()
	jsOnAppBundleReady = js.Undefined()

	if node != nil {
		node.StopMeshSupervisor()
		node = nil
	}
	if pion != nil {
		pion.Close()
		pion = nil
	}
	return result(map[string]any{"ok": true})
}
