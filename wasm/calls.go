//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

func parseCallOptionsArg(v js.Value) cot.CallOptions {
	var opts cot.CallOptions
	if v.IsUndefined() || v.IsNull() {
		return opts
	}
	if v.Type() == js.TypeString {
		_ = json.Unmarshal([]byte(v.String()), &opts)
		return opts
	}
	if v.Type() == js.TypeObject {
		if f := v.Get("listenOnly"); !f.IsUndefined() {
			opts.ListenOnly = f.Bool()
		} else if f := v.Get("listen_only"); !f.IsUndefined() {
			opts.ListenOnly = f.Bool()
		}
		if f := v.Get("audio"); !f.IsUndefined() {
			opts.Audio = f.Bool()
		}
		if f := v.Get("video"); !f.IsUndefined() {
			opts.Video = f.Bool()
		}
		if f := v.Get("screen"); !f.IsUndefined() {
			opts.Screen = f.Bool()
		}
	}
	return opts
}

func jsJoinCall(this js.Value, args []js.Value) any {
	if node == nil {
		return js.ValueOf(map[string]any{"error": "room not joined"})
	}
	if len(args) < 2 {
		return js.ValueOf(map[string]any{"error": "joinCall requires scopeID, isDM[, opts]"})
	}
	scopeID := args[0].String()
	isDM := args[1].Bool()
	var opts cot.CallOptions
	if len(args) >= 3 {
		opts = parseCallOptionsArg(args[2])
	}
	bundle, err := node.JoinCall(scopeID, isDM, opts)
	if err != nil {
		return js.ValueOf(map[string]any{"error": err.Error()})
	}
	defer bundle.Zeroize()
	return js.ValueOf(map[string]any{
		"status":  "ok",
		"scopeID": scopeID,
		"isDM":    isDM,
		"bundle":  sframeBundleToJS(bundle),
	})
}

func jsUpdateCallOptions(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 2 {
		return errResult(fmt.Errorf("updateCallOptions requires scopeID, opts"))
	}
	if err := node.UpdateCallOptions(args[0].String(), parseCallOptionsArg(args[1])); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok"})
}

func jsLeaveCall(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("leaveCall requires scopeID"))
	}
	if err := node.LeaveCall(args[0].String()); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok"})
}

func jsSendCallSignal(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 4 {
		return errResult(fmt.Errorf("sendCallSignal requires scopeID, target, kind, payload"))
	}
	if err := node.SendCallSignal(args[0].String(), args[1].String(), args[2].String(), args[3].String()); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok"})
}

func jsExportSFrameKeys(this js.Value, args []js.Value) any {
	if node == nil {
		return js.ValueOf(map[string]any{"error": "room not joined"})
	}
	if len(args) < 1 {
		return js.ValueOf(map[string]any{"error": "exportSFrameKeys requires scopeID"})
	}
	scopeID := args[0].String()
	bundle, err := node.ExportSFrameKeys(scopeID)
	if err != nil {
		return js.ValueOf(map[string]any{"error": err.Error()})
	}
	defer bundle.Zeroize()
	return js.ValueOf(map[string]any{
		"status":  "ok",
		"scopeID": scopeID,
		"bundle":  sframeBundleToJS(bundle),
	})
}

func jsActiveCallPeers(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return result([]cot.CallPeerState{})
	}
	return result(node.ActiveCallPeers(args[0].String()))
}

func jsIsInCall(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return false
	}
	return node.IsInCall(args[0].String())
}
