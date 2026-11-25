//go:build js && wasm

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"syscall/js"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

func jsCreateRoom(this js.Value, args []js.Value) any {
	var uuidBuf [16]byte
	_, _ = io.ReadFull(rand.Reader, uuidBuf[:])
	uuidBuf[6] = (uuidBuf[6] & 0x0f) | 0x40
	uuidBuf[8] = (uuidBuf[8] & 0x3f) | 0x80
	roomID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuidBuf[0:4], uuidBuf[4:6], uuidBuf[6:8], uuidBuf[8:10], uuidBuf[10:16])

	key, err := cot.GenerateRoomKey()
	if err != nil {
		return errResult(err)
	}
	return result(map[string]string{
		"roomID":  roomID,
		"roomKey": key.String(),
	})
}

func jsJoinRoom(this js.Value, args []js.Value) any {
	if self == nil {
		return errResult(fmt.Errorf("identity not initialized"))
	}
	if len(args) < 2 {
		return errResult(fmt.Errorf("expected roomID and roomKey arguments"))
	}
	roomID := args[0].String()
	key, err := cot.ParseRoomKey(args[1].String())
	if err != nil {
		return errResult(err)
	}

	cleanupSession()

	var stunURLs []string
	if len(args) >= 4 && args[3].Type() == js.TypeString && args[3].String() != "" {
		stunURLs = []string{args[3].String()}
	}
	ensureTransport(stunURLs)
	node = cot.NewNode(self, roomID, key, protocolCfg, pion, buildNodeHooks())

	if len(args) >= 3 && args[2].Bool() {
		if err := node.InitGenesisEpoch(); err != nil {
			return errResult(err)
		}
	}
	node.StartMeshSupervisor(context.Background(), 2*time.Second)
	return result(map[string]string{"status": "ok", "roomID": roomID})
}

func jsLeaveRoom(this js.Value, args []js.Value) any {
	cleanupSession()
	return result(map[string]string{"status": "left"})
}

func jsJoinChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("node not initialized"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("expected channelID"))
	}
	chID := args[0].String()
	var err error
	if len(args) >= 2 && args[1].Type() == js.TypeString && args[1].String() != "" {
		var key cot.RoomKey
		key, err = cot.ParseRoomKey(args[1].String())
		if err != nil {
			return errResult(err)
		}
		err = node.JoinChannelWithKey(chID, key)
	} else {
		err = node.JoinChannel(chID)
	}
	if err != nil {
		return errResult(err)
	}
	return result(map[string]any{"status": "query_broadcast", "channelID": chID})
}

func jsSendMessage(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("sendMessage requires text"))
	}
	env, err := node.SendMessage(args[0].String())
	if err != nil {
		return errResult(err)
	}
	return result(env)
}

func jsSendChannelMessage(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 2 {
		return errResult(fmt.Errorf("sendChannelMessage requires channelID and text"))
	}
	env, err := node.SendChannelMessage(args[0].String(), args[1].String())
	if err != nil {
		return errResult(err)
	}
	return result(env)
}

func jsShareAttachment(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 3 {
		return errResult(fmt.Errorf("shareAttachment requires name, mime, and Uint8Array data"))
	}
	data, err := jsBytesToGo(args[2])
	if err != nil {
		return errResult(err)
	}
	meta, err := node.ShareAttachment(args[0].String(), args[1].String(), data)
	if err != nil {
		return errResult(err)
	}
	return result(meta)
}

func jsShareAttachmentInChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 4 {
		return errResult(fmt.Errorf("shareAttachmentInChannel requires channelID, name, mime, and Uint8Array data"))
	}
	data, err := jsBytesToGo(args[3])
	if err != nil {
		return errResult(err)
	}
	meta, err := node.ShareAttachmentInChannel(args[0].String(), args[1].String(), args[2].String(), data)
	if err != nil {
		return errResult(err)
	}
	return result(meta)
}

func jsDownloadAttachment(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("downloadAttachment requires fileID"))
	}
	fileID := args[0].String()
	if err := node.DownloadAttachment(fileID); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok", "fileID": fileID})
}

func jsGetAttachmentData(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("getAttachmentData requires fileID"))
	}
	data, err := node.GetAttachmentData(args[0].String())
	if err != nil {
		return errResult(err)
	}
	return bytesToJSUint8Array(data)
}

func jsAttachmentOffers(this js.Value, args []js.Value) any {
	if node == nil {
		return result([]any{})
	}
	return result(node.AttachmentOffers())
}

func jsRequestCatchUp(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	_ = node.RequestCatchUp()
	return nil
}

func jsRequestCatchUpForChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("requestCatchUpForChannel requires channelID"))
	}
	if err := node.RequestCatchUpForChannel(args[0].String()); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok"})
}

func jsSendDirectInvite(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("sendDirectInvite requires targetSignPub"))
	}
	target := args[0].String()
	invType := "dm"
	if len(args) > 1 && args[1].String() != "" {
		invType = args[1].String()
	}
	title := "Direct Message"
	if len(args) > 2 && args[2].String() != "" {
		title = args[2].String()
	}
	invite, payload, err := node.SendDirectInvite(target, invType, title)
	if err != nil {
		return errResult(err)
	}
	if k, err := cot.ParseRoomKey(payload.RoomKey); err == nil {
		dmMu.Lock()
		dmSessions[payload.RoomID] = k
		dmInvitePeers[payload.RoomID] = target
		dmMu.Unlock()
		if invType == "dm" {
			_ = node.RegisterDMScope(payload.RoomID, target, k)
		}
	}
	return result(map[string]any{"status": "ok", "invite": invite, "payload": payload})
}

func jsRespondDirectInvite(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 2 {
		return errResult(fmt.Errorf("respondDirectInvite requires inviteJSON, accepted"))
	}
	var invite cot.DirectInvite
	if err := json.Unmarshal([]byte(args[0].String()), &invite); err != nil {
		return errResult(err)
	}
	if err := node.RespondDirectInvite(&invite, args[1].Bool()); err != nil {
		return errResult(err)
	}
	return result(map[string]string{"status": "ok"})
}

func jsRegisterDMSession(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return errResult(fmt.Errorf("registerDMSession requires roomID and roomKey"))
	}
	roomID := args[0].String()
	key, err := cot.ParseRoomKey(args[1].String())
	if err != nil {
		return errResult(err)
	}
	peerAddr := ""
	if len(args) >= 3 && !args[2].IsUndefined() && !args[2].IsNull() {
		peerAddr = args[2].String()
	}
	dmMu.Lock()
	dmSessions[roomID] = key
	if peerAddr == "" {
		peerAddr = dmInvitePeers[roomID]
	} else {
		dmInvitePeers[roomID] = peerAddr
	}
	dmMu.Unlock()
	if node != nil && peerAddr != "" {
		_ = node.RegisterDMScope(roomID, peerAddr, key)
	}
	return result(map[string]string{"status": "ok"})
}

func jsSendDMMessage(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 4 {
		return errResult(fmt.Errorf("sendDMMessage requires targetPeer, roomID, roomKey, text"))
	}
	targetPeer, roomID, keyStr, text := args[0].String(), args[1].String(), args[2].String(), args[3].String()
	key, err := cot.ParseRoomKey(keyStr)
	if err != nil {
		return errResult(err)
	}
	dmMu.Lock()
	dmSessions[roomID] = key
	dmInvitePeers[roomID] = targetPeer
	dmMu.Unlock()
	_ = node.RegisterDMScope(roomID, targetPeer, key)

	chatPayload, _ := json.Marshal(cot.ChatPayload{Type: "chat", Text: text})
	env, err := cot.NewEnvelope(self, roomID, key, chatPayload)
	if err != nil {
		return errResult(err)
	}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return errResult(err)
	}
	if err := node.SendViaRelay(targetPeer, "dm", envBytes); err != nil {
		return errResult(err)
	}
	return result(env)
}

func jsCreateChannelInvite(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	ttlMs := int64(15 * 60 * 1000)
	if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
		ttlMs = int64(args[0].Int())
	}
	inv, err := node.CreateChannelInvite(time.Duration(ttlMs) * time.Millisecond)
	if err != nil {
		return errResult(err)
	}
	return result(inv)
}

func jsCreateChannelInviteForChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 || args[0].String() == "" {
		return errResult(fmt.Errorf("createChannelInviteForChannel requires channelID"))
	}
	ttlMs := int64(15 * 60 * 1000)
	if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
		ttlMs = int64(args[1].Int())
	}
	var invitee []string
	if len(args) > 2 && args[2].Type() == js.TypeString && args[2].String() != "" {
		invitee = append(invitee, args[2].String())
	}
	inv, err := node.CreateChannelInviteForChannel(args[0].String(), time.Duration(ttlMs)*time.Millisecond, invitee...)
	if err != nil {
		return errResult(err)
	}
	return result(inv)
}

func jsSetChannelInvite(this js.Value, args []js.Value) any {
	if node != nil && len(args) >= 1 {
		var inv cot.ChannelInvite
		if err := json.Unmarshal([]byte(args[0].String()), &inv); err == nil {
			node.SetChannelInvite(&inv)
		}
	}
	return result(nil)
}

func jsSetChannelInviteForChannel(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 2 {
		return errResult(fmt.Errorf("setChannelInviteForChannel requires channelID and inviteJSON"))
	}
	var inv cot.ChannelInvite
	if err := json.Unmarshal([]byte(args[1].String()), &inv); err != nil {
		return errResult(err)
	}
	node.SetChannelInviteForChannel(args[0].String(), &inv)
	return result(map[string]string{"status": "ok"})
}

func jsEvictPeer(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("expected targetAddr argument"))
	}
	reason := "policy violation"
	if len(args) > 1 && args[1].String() != "" {
		reason = args[1].String()
	}
	commit, err := node.EvictPeer(args[0].String(), reason)
	if err != nil {
		return errResult(err)
	}
	commitJSON, _ := json.Marshal(commit)
	return result(string(commitJSON))
}

func jsEvictPeerInChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 2 {
		return errResult(fmt.Errorf("evictPeerInChannel requires channelID and targetAddr"))
	}
	reason := "policy violation"
	if len(args) > 2 && args[2].String() != "" {
		reason = args[2].String()
	}
	commit, err := node.EvictPeerInChannel(args[0].String(), args[1].String(), reason)
	if err != nil {
		return errResult(err)
	}
	return result(commit)
}

func jsInvitedBy(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return result("")
	}
	return result(node.InvitedBy(args[0].String()))
}

func jsCurrentEpoch(this js.Value, args []js.Value) any {
	if node == nil {
		return float64(0)
	}
	return float64(node.CurrentEpoch())
}

func jsChannelCurrentEpoch(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return float64(0)
	}
	return float64(node.ChannelCurrentEpoch(args[0].String()))
}

func jsJoinedEpoch(this js.Value, args []js.Value) any {
	if node == nil {
		return float64(0)
	}
	return float64(node.JoinedEpoch())
}

func jsRotateEpochKey(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(errors.New("cotilla: node not initialized"))
	}
	commit, err := node.RotateEpochKey()
	if err != nil {
		return errResult(err)
	}
	return result(commit)
}

func jsRotateEpochKeyInChannel(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(errors.New("cotilla: node not initialized"))
	}
	if len(args) < 1 {
		return errResult(errors.New("rotateEpochKeyInChannel requires channelID"))
	}
	commit, err := node.RotateEpochKeyInChannel(args[0].String())
	if err != nil {
		return errResult(err)
	}
	return result(commit)
}

func jsInitGenesisEpoch(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if err := node.InitGenesisEpoch(); err != nil {
		return errResult(err)
	}
	return result(map[string]any{"epoch": node.CurrentEpoch()})
}

func jsInitChannelMLS(this js.Value, args []js.Value) any {
	if node == nil {
		return errResult(fmt.Errorf("room not joined"))
	}
	if len(args) < 1 {
		return errResult(fmt.Errorf("initChannelMLS requires channelID"))
	}
	channelID := args[0].String()
	if err := node.InitChannelMLS(channelID); err != nil {
		return errResult(err)
	}
	return result(map[string]any{"channelID": channelID, "epoch": node.ChannelCurrentEpoch(channelID)})
}

func jsIsAdmittedMember(this js.Value, args []js.Value) any {
	if node == nil || len(args) < 1 {
		return false
	}
	return node.IsAdmittedMember(args[0].String())
}
