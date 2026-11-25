//go:build js && wasm

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"syscall/js"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

func ensureBootstrapNode(distRoomID string, roomKey cot.RoomKey) error {
	if self == nil {
		id, err := cot.NewIdentity()
		if err != nil {
			return err
		}
		self = id
	}
	if pion == nil {
		ensureTransport(nil)
	}
	if node == nil {
		node = cot.NewNode(self, distRoomID, roomKey, protocolCfg, pion, buildNodeHooks())
	}
	return nil
}

// jsBootstrapApp joins a public app seeder group and requests the pinned app using a single
// declarative JSON config: `{ appName, version, minSeq, validSignatures, seederGroup: { name, psk, channel } }`.
func jsBootstrapApp(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return errResult(errors.New("bootstrapApp requires appConfig JSON"))
	}
	var raw string
	switch args[0].Type() {
	case js.TypeString:
		raw = args[0].String()
	case js.TypeObject:
		raw = js.Global().Get("JSON").Call("stringify", args[0]).String()
	default:
		return errResult(errors.New("bootstrapApp requires JSON string or object"))
	}

	var cfg cot.AppBootstrapConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return errResult(fmt.Errorf("invalid appConfig JSON: %w", err))
	}
	if cfg.SeederGroup.Name == "" {
		cfg.SeederGroup.Name = cot.DefaultAppDistRoomID
	}
	if cfg.SeederGroup.Channel == "" {
		cfg.SeederGroup.Channel = cot.DefaultAppChannel
	}
	if cfg.AppName == "" {
		cfg.AppName = cot.DefaultAppID
	}

	roomKey := resolveAppDistKey(cfg.SeederGroup.Name, cfg.SeederGroup.PSK)
	if err := ensureBootstrapNode(cfg.SeederGroup.Name, roomKey); err != nil {
		return errResult(err)
	}
	if _, err := node.BootstrapApp(cfg); err != nil {
		return errResult(err)
	}
	return result(map[string]any{
		"room_id":          cfg.SeederGroup.Name,
		"room_key":         roomKey.String(),
		"app_id":           cfg.AppName,
		"version":          cfg.Version,
		"channel":          cfg.SeederGroup.Channel,
		"valid_signatures": cfg.ValidSignatures,
		"min_seq":          cfg.MinSeq,
	})
}

func resolveAppDistKey(distRoomID, keyStr string) cot.RoomKey {
	if keyStr != "" {
		if parsed, err := cot.ParseRoomKey(keyStr); err == nil {
			return parsed
		}
	}
	return cot.AppDistRoomKeyFor(distRoomID)
}

func jsJoinBootstrap(this js.Value, args []js.Value) any {
	distRoomID := cot.DefaultAppDistRoomID
	if len(args) > 0 && args[0].Type() == js.TypeString && args[0].String() != "" {
		distRoomID = args[0].String()
	}
	keyArg := ""
	if len(args) > 1 && args[1].Type() == js.TypeString {
		keyArg = args[1].String()
	}
	roomKey := resolveAppDistKey(distRoomID, keyArg)

	appID := cot.DefaultAppID
	if len(args) > 2 && args[2].Type() == js.TypeString && args[2].String() != "" {
		appID = args[2].String()
	}
	channel := cot.DefaultAppChannel
	if len(args) > 3 && args[3].Type() == js.TypeString && args[3].String() != "" {
		channel = args[3].String()
	}
	pinnedPub := ""
	if len(args) > 4 && args[4].Type() == js.TypeString {
		pinnedPub = args[4].String()
	}
	var minSeq uint64
	if len(args) > 5 && args[5].Type() == js.TypeNumber {
		minSeq = uint64(args[5].Int())
	}

	if err := ensureBootstrapNode(distRoomID, roomKey); err != nil {
		return errResult(err)
	}
	if err := node.JoinAppDistChannel(distRoomID, roomKey, pinnedPub, minSeq); err != nil {
		return errResult(err)
	}
	return result(map[string]any{
		"room_id":    distRoomID,
		"room_key":   roomKey.String(),
		"app_id":     appID,
		"channel":    channel,
		"pinned_pub": pinnedPub,
		"min_seq":    minSeq,
	})
}

func jsRequestAppManifest(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(errors.New("cotilla: node not initialized"))
	}
	distRoomID := cot.DefaultAppDistRoomID
	if len(args) > 0 && args[0].Type() == js.TypeString && args[0].String() != "" {
		distRoomID = args[0].String()
	}
	appID := cot.DefaultAppID
	if len(args) > 1 && args[1].Type() == js.TypeString && args[1].String() != "" {
		appID = args[1].String()
	}
	channel := cot.DefaultAppChannel
	if len(args) > 2 && args[2].Type() == js.TypeString && args[2].String() != "" {
		channel = args[2].String()
	}
	var minSeq uint64
	if len(args) > 3 && args[3].Type() == js.TypeNumber {
		minSeq = uint64(args[3].Int())
	}
	node.RequestAppManifest(distRoomID, appID, channel, minSeq)
	return result(map[string]any{"ok": true})
}

func parseValidSignaturesArg(v js.Value) []string {
	if v.IsUndefined() || v.IsNull() {
		return nil
	}
	if v.Type() == js.TypeString {
		raw := strings.TrimSpace(v.String())
		if raw == "" {
			return nil
		}
		if strings.HasPrefix(raw, "[") {
			var list []string
			if err := json.Unmarshal([]byte(raw), &list); err == nil {
				return list
			}
		}
		return []string{raw}
	}
	if v.Type() == js.TypeObject {
		raw := js.Global().Get("JSON").Call("stringify", v).String()
		var list []string
		if err := json.Unmarshal([]byte(raw), &list); err == nil {
			return list
		}
	}
	return nil
}

func jsVerifyAppBundle(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult(errors.New("expected manifestJSON and bundleBytes"))
	}
	var m cot.AppManifest
	if err := json.Unmarshal([]byte(args[0].String()), &m); err != nil {
		return errResult(fmt.Errorf("unmarshal manifest: %w", err))
	}
	bundleBytes, err := jsBytesToGo(args[1])
	if err != nil {
		return errResult(err)
	}
	var validSigs []string
	if len(args) > 2 {
		validSigs = parseValidSignaturesArg(args[2])
	}
	expectedAppID := ""
	if len(args) > 3 && args[3].Type() == js.TypeString {
		expectedAppID = args[3].String()
	}
	expectedChannel := ""
	if len(args) > 4 && args[4].Type() == js.TypeString {
		expectedChannel = args[4].String()
	}
	var minSeq uint64
	if len(args) > 5 && args[5].Type() == js.TypeNumber {
		minSeq = uint64(args[5].Int())
	}
	expectedVersion := ""
	if len(args) > 6 && args[6].Type() == js.TypeString {
		expectedVersion = args[6].String()
	}

	now := time.Now().UnixMilli()
	if err := cot.VerifyAppBundleWithKeys(&m, bundleBytes, validSigs, expectedAppID, expectedVersion, expectedChannel, minSeq, now); err != nil {
		return errResult(err)
	}
	return result(map[string]any{"valid": true, "file_id": m.FileID, "sha256": m.SHA256, "size": m.Size, "version": m.Version})
}

func jsRegisterAppBundle(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(errors.New("cotilla: node not initialized"))
	}
	if len(args) < 2 {
		return errResult(errors.New("expected manifestJSON and bundleBytes"))
	}
	var m cot.AppManifest
	if err := json.Unmarshal([]byte(args[0].String()), &m); err != nil {
		return errResult(fmt.Errorf("unmarshal manifest: %w", err))
	}
	bundleBytes, err := jsBytesToGo(args[1])
	if err != nil {
		return errResult(err)
	}
	distRoomID := cot.DefaultAppDistRoomID
	if len(args) > 2 && args[2].Type() == js.TypeString && args[2].String() != "" {
		distRoomID = args[2].String()
	}
	keyArg := ""
	if len(args) > 3 && args[3].Type() == js.TypeString {
		keyArg = args[3].String()
	}
	roomKey := resolveAppDistKey(distRoomID, keyArg)
	pinnedPub := ""
	if len(args) > 4 && args[4].Type() == js.TypeString {
		pinnedPub = args[4].String()
	}
	if err := node.RegisterAppBundle(distRoomID, roomKey, &m, bundleBytes, pinnedPub); err != nil {
		return errResult(err)
	}
	return result(map[string]any{"ok": true, "app_id": m.AppID, "seq": m.Seq, "version": m.Version})
}
