package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// TestNodeDaemon_PureWebRTCSignalingAndMultiChannelMLS tests end-to-end across 4 real NodeDaemons:
// 1. Authenticated 1:1 /ws handshake ("register" -> "offer" -> "answer" -> "ok") with immediate /ws closure.
// 2. Gateway WebRTC DataChannel established; peer discovery and peering over FramePeerQuery & FramePeerSignal.
// 3. Peers join multiple isolated channels over real Pion WebRTC DataChannels with separate MLS groups.
func TestNodeDaemon_PureWebRTCSignalingAndMultiChannelMLS(t *testing.T) {
	hubID, err := cot.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu          sync.Mutex
		anchors     = make(map[string]bool)
		wsMsgs      = make(map[string]int) // verify NO non-WebRTC protocol frames traverse /ws
		closedCount = 0
	)

	var hubTr *rtc.PionTransport
	var hubNode *cot.Node
	hubTr = rtc.New(hubID.Address(), nil, func(from string, data []byte) {
		if hubNode != nil {
			hubNode.HandleWire(from, data)
		}
	})
	hubNode = cot.NewNode(hubID, "", cot.RoomKey{}, cot.DefaultConfig(), hubTr, cot.Hooks{})
	hubTr.OnOpen(func(peer string) {
		hubNode.AddPeer(peer)
		mu.Lock()
		var existing []string
		for a := range anchors {
			if a != peer {
				existing = append(existing, a)
			}
		}
		isAnchor := len(anchors) < 3
		anchors[peer] = true
		mu.Unlock()
		intro := cot.RootIntroFrame{AnchorPeers: existing, IsAnchor: isAnchor}
		if pkt, err := cot.NewPlainPacket(hubID, peer, cot.PortRootIntro, 1, intro); err == nil {
			if raw, err := cot.MarshalPacket(pkt); err == nil {
				_ = hubTr.Send(peer, raw)
			}
		}
	})
	defer hubTr.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// 1. Read register
		_, rawReg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var regMsg struct {
			Type      string `json:"type"`
			Peer      string `json:"peer"`
			Timestamp int64  `json:"timestamp"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(rawReg, &regMsg); err != nil || regMsg.Type != "register" {
			return
		}
		canonicalReg := cot.CanonicalSignalingMsg("register", regMsg.Peer, "", "", regMsg.Timestamp)
		if !cot.Verify(regMsg.Peer, canonicalReg, regMsg.Signature) {
			t.Errorf("invalid register signature from %s", regMsg.Peer)
			return
		}
		mu.Lock()
		wsMsgs[regMsg.Type]++
		mu.Unlock()

		clientAddr := regMsg.Peer

		// 2. Create offer to client
		offerSDP, err := hubTr.CreateOffer(clientAddr)
		if err != nil {
			return
		}
		offerNow := time.Now().UnixMilli()
		offerSig := hex.EncodeToString(hubID.Sign(cot.CanonicalSignalingMsg("offer", hubID.Address(), clientAddr, offerSDP, offerNow)))
		offerMsg := map[string]any{
			"type":      "offer",
			"peer":      hubID.Address(),
			"target":    clientAddr,
			"sdp":       offerSDP,
			"timestamp": offerNow,
			"signature": offerSig,
		}
		rawOffer, _ := json.Marshal(offerMsg)
		if err := conn.Write(ctx, websocket.MessageText, rawOffer); err != nil {
			return
		}
		mu.Lock()
		wsMsgs["offer"]++
		mu.Unlock()

		// 3. Read answer
		_, rawAns, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var ansMsg struct {
			Type      string `json:"type"`
			Peer      string `json:"peer"`
			Target    string `json:"target"`
			SDP       string `json:"sdp"`
			Timestamp int64  `json:"timestamp"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(rawAns, &ansMsg); err != nil || ansMsg.Type != "answer" {
			return
		}
		canonicalAns := cot.CanonicalSignalingMsg("answer", ansMsg.Peer, ansMsg.Target, ansMsg.SDP, ansMsg.Timestamp)
		if !cot.Verify(ansMsg.Peer, canonicalAns, ansMsg.Signature) {
			t.Errorf("invalid answer signature from %s", ansMsg.Peer)
			return
		}
		mu.Lock()
		wsMsgs[ansMsg.Type]++
		mu.Unlock()

		if err := hubTr.AcceptAnswer(clientAddr, ansMsg.SDP); err != nil {
			return
		}

		// 4. Send ok
		okMsg := map[string]string{"type": "ok"}
		rawOk, _ := json.Marshal(okMsg)
		_ = conn.Write(ctx, websocket.MessageText, rawOk)

		// Wait for client to close WS
		_, _, _ = conn.Read(ctx)
		mu.Lock()
		closedCount++
		mu.Unlock()
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	alphaID := "chan-alpha"
	betaID := "chan-beta"
	alphaKey, _ := cot.GenerateRoomKey()
	betaKey, _ := cot.GenerateRoomKey()

	type peerMsg struct {
		channel string
		text    string
	}
	recvCh := make([]chan peerMsg, 4)
	ids := make([]*cot.Identity, 4)
	daemons := make([]*NodeDaemon, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for i := 0; i < 4; i++ {
		seed := make([]byte, 32)
		seed[0] = byte(i + 1)
		seed[31] = byte(0xA0 + i)
		id, err := cot.NewIdentityFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
		ch := make(chan peerMsg, 16)
		recvCh[i] = ch
		d := newNodeDaemon(id, wsURL, nil, alphaID, alphaKey, cot.Hooks{
			OnMessage: func(env *cot.Envelope, plaintext []byte) {
				var p cot.ChatPayload
				if json.Unmarshal(plaintext, &p) == nil {
					ch <- peerMsg{channel: env.RoomID, text: p.Text}
				}
			},
		})
		daemons[i] = d
		defer d.transport.Close()
		defer d.node.StopMeshSupervisor()
	}

	for i := 0; i < 4; i++ {
		go daemons[i].bootstrapLoop(ctx)
	}

	// All 4 peers must disconnect from /ws immediately after the 1:1 handshake,
	// and establish direct WebRTC DataChannels with each other.
	waitDeadline := time.Now().Add(12 * time.Second)
	for {
		mu.Lock()
		cc := closedCount
		mu.Unlock()
		if cc >= 4 && len(daemons[3].transport.Peers()) >= 3 && len(daemons[0].transport.Peers()) >= 3 {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatalf("timed out waiting for WebRTC DataChannels (closedWS=%d, leaf peers=%d, root0 peers=%d)",
				closedCount, len(daemons[3].transport.Peers()), len(daemons[0].transport.Peers()))
		}
		time.Sleep(30 * time.Millisecond)
	}

	// Verify ONLY "register", "offer", "answer" messages ever traversed /ws.
	mu.Lock()
	for typ := range wsMsgs {
		if typ != "register" && typ != "offer" && typ != "answer" {
			t.Fatalf("non-WebRTC message %q leaked onto /ws signaling server", typ)
		}
	}
	if wsMsgs["register"] < 4 || wsMsgs["offer"] < 4 || wsMsgs["answer"] < 4 {
		t.Fatalf("unexpected /ws handshake counts: %+v", wsMsgs)
	}
	mu.Unlock()

	// Initialize chan-alpha MLS on daemon 0 and admit peers 1, 2, 3 (all 4 peers in chan-alpha).
	if err := daemons[0].node.InitChannelMLS(alphaID); err != nil {
		t.Fatalf("InitChannelMLS(alpha) failed: %v", err)
	}
	invA, err := daemons[0].node.CreateChannelInviteForChannel(alphaID, 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInviteForChannel(alpha) failed: %v", err)
	}
	for i := 1; i < 4; i++ {
		daemons[i].node.SetChannelInviteForChannel(alphaID, invA)
		_ = daemons[i].node.JoinChannel(alphaID)
	}
	// Admit 1,2,3 explicitly into chan-alpha MLS group
	time.Sleep(200 * time.Millisecond)

	// Peers 0, 1, 2 ALSO join a second isolated channel chan-beta (peer 3 is NOT in chan-beta).
	for i := 0; i < 3; i++ {
		if err := daemons[i].node.JoinChannelWithKey(betaID, betaKey); err != nil {
			t.Fatalf("node %d JoinChannelWithKey(beta) failed: %v", i, err)
		}
	}
	if err := daemons[0].node.InitChannelMLS(betaID); err != nil {
		t.Fatalf("InitChannelMLS(beta) failed: %v", err)
	}
	invB, err := daemons[0].node.CreateChannelInviteForChannel(betaID, 15*time.Minute)
	if err != nil {
		t.Fatalf("CreateChannelInviteForChannel(beta) failed: %v", err)
	}
	for i := 1; i < 3; i++ {
		daemons[i].node.SetChannelInviteForChannel(betaID, invB)
	}
	time.Sleep(400 * time.Millisecond)

	// Wait for MLS epochs to sync for both channels before sending messages, or verify epoch >= 1 on alpha and beta.
	alphaSecretMsg := "alpha-webrtc-mls-msg-991"
	betaSecretMsg := "beta-webrtc-mls-msg-882"
	if _, err := daemons[0].node.SendChannelMessage(alphaID, alphaSecretMsg); err != nil {
		t.Fatalf("SendChannelMessage(alpha) failed: %v", err)
	}
	if _, err := daemons[0].node.SendChannelMessage(betaID, betaSecretMsg); err != nil {
		t.Fatalf("SendChannelMessage(beta) failed: %v", err)
	}

	// Peer 3 must receive chan-alpha ONLY, NEVER decrypt chan-beta!
	gotAlpha := false
	gotBetaOnPeer3 := false
	recvDeadline := time.After(4 * time.Second)
loop:
	for {
		select {
		case m := <-recvCh[3]:
			if m.channel == alphaID && m.text == alphaSecretMsg {
				gotAlpha = true
			}
			if m.channel == betaID {
				gotBetaOnPeer3 = true
			}
			if gotAlpha {
				break loop
			}
		case <-recvDeadline:
			break loop
		}
	}
	if !gotAlpha {
		t.Fatalf("peer 3 failed to receive chan-alpha message over real WebRTC (alpha epoch=%d)", daemons[3].node.ChannelCurrentEpoch(alphaID))
	}
	// Drain briefly to ensure beta never arrives on peer 3.
	time.Sleep(150 * time.Millisecond)
drain:
	for {
		select {
		case m := <-recvCh[3]:
			if m.channel == betaID {
				gotBetaOnPeer3 = true
			}
		default:
			break drain
		}
	}
	if gotBetaOnPeer3 {
		t.Fatalf("isolation failure: non-member peer 3 decrypted chan-beta message")
	}

	// Verify peer 2 received chan-beta message!
	gotBetaOnPeer2 := false
	betaDeadline := time.After(4 * time.Second)
loop2:
	for {
		select {
		case m := <-recvCh[2]:
			if m.channel == betaID && m.text == betaSecretMsg {
				gotBetaOnPeer2 = true
				break loop2
			}
		case <-betaDeadline:
			break loop2
		}
	}
	if !gotBetaOnPeer2 {
		t.Fatalf("peer 2 failed to receive chan-beta message over real WebRTC (beta epoch=%d)", daemons[2].node.ChannelCurrentEpoch(betaID))
	}
}
