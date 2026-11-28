//go:build js && wasm

// Command wasm builds the Cotilla protocol core and browser WebRTC transport for WebAssembly execution.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/datf/cotilla-protocol/internal/buildinfo"
)

func jsVersion(this js.Value, args []js.Value) any {
	raw, _ := json.Marshal(map[string]string{
		"version": buildinfo.Version,
		"commit":  buildinfo.Commit,
		"date":    buildinfo.Date,
	})
	return string(raw)
}

func register() {
	c := map[string]any{
		// Build metadata
		"version": js.FuncOf(jsVersion),

		// Identity & Overlay
		"init":              js.FuncOf(jsInit),
		"shutdown":          js.FuncOf(jsShutdown),
		"createOffer":       js.FuncOf(jsCreateOffer),
		"acceptOffer":       js.FuncOf(jsAcceptOffer),
		"acceptAnswer":      js.FuncOf(jsAcceptAnswer),
		"signSignaling":     js.FuncOf(jsSignSignaling),
		"verifySignaling":   js.FuncOf(jsVerifySignaling),
		"addPeer":           js.FuncOf(jsAddPeer),
		"removePeer":        js.FuncOf(jsRemovePeer),
		"closePeer":         js.FuncOf(jsClosePeer),
		"connectedPeers":    js.FuncOf(jsConnectedPeers),
		"peerEncKeys":       js.FuncOf(jsPeerEncKeys),
		"broadcastPeerInfo": js.FuncOf(jsBroadcastPeerInfo),
		"addGatewayPeer":    js.FuncOf(jsAddGatewayPeer),
		"isGatewayPeer":     js.FuncOf(jsIsGatewayPeer),
		"hasGatewayConn":    js.FuncOf(jsHasGatewayConn),
		"queryPeers":        js.FuncOf(jsQueryPeers),
		"networkStatus":     js.FuncOf(jsNetworkStatus),
		"addAnchorPeer":     js.FuncOf(jsAddAnchorPeer),
		"setFallbackMode":   js.FuncOf(jsSetFallbackMode),
		"solicitAnchors":    js.FuncOf(jsSolicitAnchors),

		// Rooms, Channels, MLS, Attachments & DMs
		"createRoom":                    js.FuncOf(jsCreateRoom),
		"joinRoom":                      js.FuncOf(jsJoinRoom),
		"leave":                         js.FuncOf(jsLeaveRoom),
		"leaveRoom":                     js.FuncOf(jsLeaveRoom),
		"joinChannel":                   js.FuncOf(jsJoinChannel),
		"sendMessage":                   js.FuncOf(jsSendMessage),
		"sendChannelMessage":            js.FuncOf(jsSendChannelMessage),
		"sendDMMessage":                 js.FuncOf(jsSendDMMessage),
		"registerDMSession":             js.FuncOf(jsRegisterDMSession),
		"sendDirectInvite":              js.FuncOf(jsSendDirectInvite),
		"respondDirectInvite":           js.FuncOf(jsRespondDirectInvite),
		"shareAttachment":               js.FuncOf(jsShareAttachment),
		"shareAttachmentInChannel":      js.FuncOf(jsShareAttachmentInChannel),
		"downloadAttachment":            js.FuncOf(jsDownloadAttachment),
		"getAttachmentData":             js.FuncOf(jsGetAttachmentData),
		"attachmentOffers":              js.FuncOf(jsAttachmentOffers),
		"requestCatchUp":                js.FuncOf(jsRequestCatchUp),
		"requestCatchUpForChannel":      js.FuncOf(jsRequestCatchUpForChannel),
		"createChannelInvite":           js.FuncOf(jsCreateChannelInvite),
		"createChannelInviteForChannel": js.FuncOf(jsCreateChannelInviteForChannel),
		"setChannelInvite":              js.FuncOf(jsSetChannelInvite),
		"setChannelInviteForChannel":    js.FuncOf(jsSetChannelInviteForChannel),
		"rotateEpochKey":                js.FuncOf(jsRotateEpochKey),
		"rotateEpochKeyInChannel":       js.FuncOf(jsRotateEpochKeyInChannel),
		"isAdmittedMember":              js.FuncOf(jsIsAdmittedMember),
		"initGenesisEpoch":              js.FuncOf(jsInitGenesisEpoch),
		"initChannelMLS":                js.FuncOf(jsInitChannelMLS),
		"evictPeer":                     js.FuncOf(jsEvictPeer),
		"evictPeerInChannel":            js.FuncOf(jsEvictPeerInChannel),
		"invitedBy":                     js.FuncOf(jsInvitedBy),
		"currentEpoch":                  js.FuncOf(jsCurrentEpoch),
		"channelCurrentEpoch":           js.FuncOf(jsChannelCurrentEpoch),
		"joinedEpoch":                   js.FuncOf(jsJoinedEpoch),

		// A/V Calls & SFrame
		"joinCall":          js.FuncOf(jsJoinCall),
		"updateCallOptions": js.FuncOf(jsUpdateCallOptions),
		"leaveCall":         js.FuncOf(jsLeaveCall),
		"sendCallSignal":    js.FuncOf(jsSendCallSignal),
		"exportSFrameKeys":  js.FuncOf(jsExportSFrameKeys),
		"activeCallPeers":   js.FuncOf(jsActiveCallPeers),
		"isInCall":          js.FuncOf(jsIsInCall),

		// App Bootstrap & Swarm Seeding
		"bootstrapApp":       js.FuncOf(jsBootstrapApp),
		"joinBootstrap":      js.FuncOf(jsJoinBootstrap),
		"requestAppManifest": js.FuncOf(jsRequestAppManifest),
		"verifyAppBundle":    js.FuncOf(jsVerifyAppBundle),
		"registerAppBundle":  js.FuncOf(jsRegisterAppBundle),

		// Event Callbacks
		"setOnMessage":            js.FuncOf(func(this js.Value, args []js.Value) any { jsOnMessage = args[0]; return nil }),
		"setOnDMMessage":          js.FuncOf(func(this js.Value, args []js.Value) any { jsOnDMMessage = args[0]; return nil }),
		"setOnAttachmentOffer":    js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAttachmentOffer = args[0]; return nil }),
		"setOnAttachmentProgress": js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAttachmentProgress = args[0]; return nil }),
		"setOnAttachment":         js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAttachment = args[0]; return nil }),
		"setOnCallPresence":       js.FuncOf(func(this js.Value, args []js.Value) any { jsOnCallPresence = args[0]; return nil }),
		"setOnCallSignal":         js.FuncOf(func(this js.Value, args []js.Value) any { jsOnCallSignal = args[0]; return nil }),
		"setOnSFrameKeysUpdated":  js.FuncOf(func(this js.Value, args []js.Value) any { jsOnSFrameKeysUpdated = args[0]; return nil }),
		"setOnCallPeerClosed":     js.FuncOf(func(this js.Value, args []js.Value) any { jsOnCallPeerClosed = args[0]; return nil }),
		"setOnDirectInvite":       js.FuncOf(func(this js.Value, args []js.Value) any { jsOnDirectInvite = args[0]; return nil }),
		"setOnInviteResponse":     js.FuncOf(func(this js.Value, args []js.Value) any { jsOnInviteResponse = args[0]; return nil }),
		"setOnPeerJoined":         js.FuncOf(func(this js.Value, args []js.Value) any { jsOnPeerJoined = args[0]; return nil }),
		"setOnPeerLeft":           js.FuncOf(func(this js.Value, args []js.Value) any { jsOnPeerLeft = args[0]; return nil }),
		"setOnMemberEvicted":      js.FuncOf(func(this js.Value, args []js.Value) any { jsOnMemberEvicted = args[0]; return nil }),
		"setOnEpochCommit":        js.FuncOf(func(this js.Value, args []js.Value) any { jsOnEpochCommit = args[0]; return nil }),
		"setOnOpen":               js.FuncOf(func(this js.Value, args []js.Value) any { jsOnOpen = args[0]; return nil }),
		"setOnAnchorIntro":        js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAnchorIntro = args[0]; return nil }),
		"setOnAnchorDeficit":      js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAnchorDeficit = args[0]; return nil }),
		"setOnAnchorSolicit":      js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAnchorSolicit = args[0]; return nil }),
		"setOnChannelDiscovered":  js.FuncOf(func(this js.Value, args []js.Value) any { jsOnChannelDiscovered = args[0]; return nil }),
		"setOnAppManifest":        js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAppManifest = args[0]; return nil }),
		"setOnAppBundleReady":     js.FuncOf(func(this js.Value, args []js.Value) any { jsOnAppBundleReady = args[0]; return nil }),
	}
	js.Global().Set("cotilla", js.ValueOf(c))
}

func main() {
	register()
	js.Global().Get("console").Call("debug", "cotilla ephemeral wasm initialized")
	<-quitCh
	js.Global().Get("console").Call("debug", "cotilla wasm shutdown")
}
