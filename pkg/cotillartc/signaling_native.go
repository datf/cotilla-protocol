//go:build !js && !wasip1

package cotillartc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coder/websocket"
	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

type wsSignalingHandshakeMsg struct {
	Type      string `json:"type"`
	Peer      string `json:"peer"`
	Target    string `json:"target,omitempty"`
	SDP       string `json:"sdp,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

// DialSignalingWS executes an authenticated 1:1 WebRTC DataChannel handshake with the signaling
// server over /ws, closes the WebSocket immediately once the handshake completes, and registers
// the signaling server as a gateway peer on node.
func DialSignalingWS(ctx context.Context, wsURL string, id *cot.Identity, tr *PionTransport, node *cot.Node) (string, error) {
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{})
	if err != nil {
		return "", fmt.Errorf("cotillartc: websocket dial %s: %w", wsURL, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	conn.SetReadLimit(1 << 20)
	wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// 1. Send register
	now := time.Now().UnixMilli()
	regSig := hex.EncodeToString(id.Sign(cot.CanonicalSignalingMsg("register", id.Address(), "", "", now)))
	regMsg := wsSignalingHandshakeMsg{
		Type:      "register",
		Peer:      id.Address(),
		Timestamp: now,
		Signature: regSig,
	}
	rawReg, _ := json.Marshal(regMsg)
	if err := conn.Write(wctx, websocket.MessageText, rawReg); err != nil {
		return "", fmt.Errorf("cotillartc: write register: %w", err)
	}

	// 2. Read offer from server
	_, rawOffer, err := conn.Read(wctx)
	if err != nil {
		return "", fmt.Errorf("cotillartc: read offer: %w", err)
	}
	var offerMsg wsSignalingHandshakeMsg
	if err := json.Unmarshal(rawOffer, &offerMsg); err != nil {
		return "", fmt.Errorf("cotillartc: unmarshal offer: %w", err)
	}
	if offerMsg.Type == "error" {
		return "", fmt.Errorf("cotillartc: signaling server error: %s", offerMsg.Error)
	}
	if offerMsg.Type != "offer" || offerMsg.Peer == "" || offerMsg.SDP == "" {
		return "", fmt.Errorf("cotillartc: unexpected signaling message type %q, want offer", offerMsg.Type)
	}
	if offerMsg.Target != id.Address() {
		return "", fmt.Errorf("cotillartc: offer target %s does not match client %s", offerMsg.Target, id.Address())
	}
	canonicalOffer := cot.CanonicalSignalingMsg("offer", offerMsg.Peer, offerMsg.Target, offerMsg.SDP, offerMsg.Timestamp)
	if !cot.Verify(offerMsg.Peer, canonicalOffer, offerMsg.Signature) {
		return "", errors.New("cotillartc: invalid signature on server offer")
	}

	serverAddr := offerMsg.Peer

	// Register gateway peer on node BEFORE accepting offer so OnOpen correctly
	// recognizes it as a gateway peer immediately.
	if node != nil {
		node.AddGatewayPeer(serverAddr)
	}

	// 3. Accept server offer on Pion transport -> generate answer
	answerSDP, err := tr.AcceptOffer(serverAddr, offerMsg.SDP)
	if err != nil {
		return "", fmt.Errorf("cotillartc: accept server offer: %w", err)
	}

	// 4. Send answer back to server
	ansNow := time.Now().UnixMilli()
	ansSig := hex.EncodeToString(id.Sign(cot.CanonicalSignalingMsg("answer", id.Address(), serverAddr, answerSDP, ansNow)))
	ansMsg := wsSignalingHandshakeMsg{
		Type:      "answer",
		Peer:      id.Address(),
		Target:    serverAddr,
		SDP:       answerSDP,
		Timestamp: ansNow,
		Signature: ansSig,
	}
	rawAns, _ := json.Marshal(ansMsg)
	if err := conn.Write(wctx, websocket.MessageText, rawAns); err != nil {
		return "", fmt.Errorf("cotillartc: write answer: %w", err)
	}

	// 5. Read confirmation or wait briefly for completion
	conn.SetReadLimit(4096)
	_, _, _ = conn.Read(wctx)

	// Wait up to 5s for the WebRTC DataChannel to reach open state
	openDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(openDeadline) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		for _, p := range tr.Peers() {
			if p == serverAddr {
				return serverAddr, nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	return serverAddr, nil
}
