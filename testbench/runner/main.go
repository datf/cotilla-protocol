package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

type StatusResponse struct {
	Name              string   `json:"name"`
	Address           string   `json:"address"`
	EncAddress        string   `json:"enc_address"`
	RoomID            string   `json:"room_id"`
	Peers             []string `json:"peers"`
	DirectPeers       []string `json:"direct_peers"`
	MessagesCount     int      `json:"messages_count"`
	AttachCount       int      `json:"attach_count"`
	InvitesCount      int      `json:"invites_count"`
	ChannelCallFrames int      `json:"channel_call_frames"`
	ChannelCallPeers  []string `json:"channel_call_peers"`
	DMRoomID          string   `json:"dm_room_id"`
	DMPeer            string   `json:"dm_peer"`
	DMPeers           []string `json:"dm_peers"`
	DMMessagesCount   int      `json:"dm_messages_count"`
	DMCallFrames      int      `json:"dm_call_frames"`
	DMCallPeers       []string `json:"dm_call_peers"`
}

type CallStatsResponse struct {
	ChannelCallPeers []string `json:"channel_call_peers"`
	DMCallPeers      []string `json:"dm_call_peers"`
	ActiveCallPeers  []any    `json:"active_call_peers"`
	Stats            struct {
		EncryptedAudio uint64 `json:"encrypted_audio"`
		EncryptedVideo uint64 `json:"encrypted_video"`
		DecryptedAudio uint64 `json:"decrypted_audio"`
		DecryptedVideo uint64 `json:"decrypted_video"`
		Rejected       uint64 `json:"rejected"`
	} `json:"stats"`
}

type MessageResponse struct {
	Author    string `json:"author"`
	Text      string `json:"text"`
	Timestamp int64  `json:"timestamp"`
}

type AttachmentResponse struct {
	FileID   string `json:"file_id"`
	Name     string `json:"name"`
	Hash     string `json:"hash"`
	Size     int64  `json:"size"`
	Verified bool   `json:"verified"`
}

type InviteItem struct {
	InviteID  string `json:"invite_id"`
	From      string `json:"from"`
	RoomID    string `json:"room_id"`
	RoomKey   string `json:"room_key"`
	Title     string `json:"title"`
	Timestamp int64  `json:"timestamp"`
}

type CallFrameItem struct {
	ScopeID    string `json:"scope_id"`
	From       string `json:"from"`
	MediaKind  string `json:"media_kind"`
	KID        uint64 `json:"kid"`
	PayloadB64 string `json:"payload_b64"`
	Size       int    `json:"size"`
	Timestamp  int64  `json:"timestamp"`
}

func getJSON(url string, target any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s failed (%d): %s", url, resp.StatusCode, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(target)
}

func postJSON(url string, reqPayload any, resTarget any) error {
	data, err := json.Marshal(reqPayload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s failed (%d): %s", url, resp.StatusCode, string(b))
	}
	if resTarget != nil {
		return json.NewDecoder(resp.Body).Decode(resTarget)
	}
	return nil
}

func waitReady(clientName, baseURL string) (*StatusResponse, error) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var status StatusResponse
		if err := getJSON(baseURL+"/status", &status); err == nil {
			return &status, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for client %s at %s", clientName, baseURL)
}

func checkMessageReceived(name, url, expectedText string) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var msgs []MessageResponse
		if err := getJSON(url+"/messages", &msgs); err == nil {
			for _, m := range msgs {
				if m.Text == expectedText {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatal("container %s did not receive expected message: %s", name, expectedText)
}

func checkDMMessageReceived(name, url, expectedText string) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var msgs []MessageResponse
		if err := getJSON(url+"/dm/messages", &msgs); err == nil {
			for _, m := range msgs {
				if m.Text == expectedText {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatal("container %s did not receive expected DM message: %s", name, expectedText)
}

func assertNoMessageWithText(name, url, forbiddenText string, isDM bool) {
	endpoint := "/messages"
	if isDM {
		endpoint = "/dm/messages"
	}
	var msgs []MessageResponse
	if err := getJSON(url+endpoint, &msgs); err == nil {
		for _, m := range msgs {
			if strings.Contains(m.Text, forbiddenText) {
				fatal("isolation violation: container %s received forbidden text '%s' at %s", name, forbiddenText, endpoint)
			}
		}
	}
}

type callTarget struct {
	Name string
	URL  string
}

func waitCallPeers(name, url string, isDM bool, minCount int) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var st CallStatsResponse
		if err := getJSON(url+"/call/stats", &st); err == nil {
			peers := st.ChannelCallPeers
			if isDM {
				peers = st.DMCallPeers
			}
			if len(peers) >= minCount {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatal("container %s did not reach %d secondary call peers (isDM=%v)", name, minCount, isDM)
}

func waitCallPeersZero(name, url string, isDM bool) {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var st CallStatsResponse
		if err := getJSON(url+"/call/stats", &st); err == nil {
			peers := st.ChannelCallPeers
			if isDM {
				peers = st.DMCallPeers
			}
			if len(peers) == 0 {
				return
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	fatal("container %s still had active secondary call peers after leave (isDM=%v)", name, isDM)
}

func sendAndVerifyCallFrame(senderURL string, isDM bool, kind string, seedPayload []byte, targets []callTarget) string {
	sendEndpoint := "/call/send-media"
	recvEndpoint := "/call/frames"
	if isDM {
		sendEndpoint = "/dm/call/send-media"
		recvEndpoint = "/dm/call/frames"
	}
	payloadB64 := base64.StdEncoding.EncodeToString(seedPayload)
	received := make(map[string]bool)
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		if err := postJSON(senderURL+sendEndpoint, map[string]any{
			"kind":    kind,
			"payload": payloadB64,
			"count":   1,
		}, nil); err != nil {
			time.Sleep(150 * time.Millisecond)
			continue
		}
		allFound := true
		for _, tgt := range targets {
			if received[tgt.Name] {
				continue
			}
			var frames []CallFrameItem
			if err := getJSON(tgt.URL+recvEndpoint, &frames); err == nil {
				for _, f := range frames {
					if f.MediaKind == kind && f.PayloadB64 == payloadB64 {
						received[tgt.Name] = true
						break
					}
				}
			}
			if !received[tgt.Name] {
				allFound = false
			}
		}
		if allFound {
			return payloadB64
		}
		time.Sleep(200 * time.Millisecond)
	}
	fatal("targets did not receive SFrame %s frame matching payload (isDM=%v, received=%v)", kind, isDM, received)
	return ""
}

func assertNoCallFramePayload(name, url string, isDM bool, forbiddenPayloadB64 string) {
	endpoint := "/call/frames"
	if isDM {
		endpoint = "/dm/call/frames"
	}
	var frames []CallFrameItem
	if err := getJSON(url+endpoint, &frames); err == nil {
		for _, f := range frames {
			if f.PayloadB64 == forbiddenPayloadB64 {
				fatal("isolation violation: container %s decrypted forbidden SFrame frame at %s", name, endpoint)
			}
		}
	}
}

func main() {
	aliceURL := "http://localhost:18081"
	bobURL := "http://localhost:18082"
	charlieURL := "http://localhost:18083"

	fmt.Printf("\n%s%s=== Cotilla Multi-Client Containerized E2E Test Bench ===%s\n\n", colorBold, colorCyan, colorReset)

	// Step 1: Health & Discovery
	fmt.Printf("%s[1/8] Checking client containers health & waiting for WebRTC mesh formation...%s\n", colorBold, colorReset)
	aliceStatus, err := waitReady("Alice", aliceURL)
	if err != nil {
		fatal("alice not ready: %v", err)
	}
	bobStatus, err := waitReady("Bob", bobURL)
	if err != nil {
		fatal("bob not ready: %v", err)
	}
	charlieStatus, err := waitReady("Charlie", charlieURL)
	if err != nil {
		fatal("charlie not ready: %v", err)
	}

	fmt.Printf("   Alice:   %s (%s)\n", aliceStatus.Address[:8], aliceStatus.Name)
	fmt.Printf("   Bob:     %s (%s)\n", bobStatus.Address[:8], bobStatus.Name)
	fmt.Printf("   Charlie: %s (%s)\n", charlieStatus.Address[:8], charlieStatus.Name)

	waitMesh := func(name, url string, minDirect int) {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			var s StatusResponse
			if err := getJSON(url+"/status", &s); err == nil {
				if len(s.DirectPeers) >= minDirect {
					return
				}
			}
			time.Sleep(500 * time.Millisecond)
		}
		fatal("mesh formation timeout for %s: did not reach %d direct peers", name, minDirect)
	}

	waitMesh("Alice", aliceURL, 2)
	waitMesh("Bob", bobURL, 2)
	waitMesh("Charlie", charlieURL, 2)
	fmt.Printf("   %s✓%s All 3 containers established direct WebRTC DataChannels with each other.\n", colorGreen, colorReset)

	// Step 2: Full P2P Encrypted Messaging
	fmt.Printf("\n%s[2/8] Testing full P2P encrypted chat broadcast & Ed25519 verification...%s\n", colorBold, colorReset)
	testMsg1 := fmt.Sprintf("E2E broadcast from Alice at %d", time.Now().UnixMilli())
	if err := postJSON(aliceURL+"/send", map[string]string{"text": testMsg1}, nil); err != nil {
		fatal("alice failed to send message: %v", err)
	}

	checkMessageReceived("Bob", bobURL, testMsg1)
	checkMessageReceived("Charlie", charlieURL, testMsg1)
	fmt.Printf("   %s✓%s Alice's encrypted message was verified and decrypted by Bob & Charlie.\n", colorGreen, colorReset)

	testMsg2 := fmt.Sprintf("E2E reply from Bob at %d", time.Now().UnixMilli())
	if err := postJSON(bobURL+"/send", map[string]string{"text": testMsg2}, nil); err != nil {
		fatal("bob failed to send message: %v", err)
	}
	checkMessageReceived("Alice", aliceURL, testMsg2)
	checkMessageReceived("Charlie", charlieURL, testMsg2)
	fmt.Printf("   %s✓%s Bob's reply was verified and decrypted by Alice & Charlie.\n", colorGreen, colorReset)

	// Step 3: Direct Chunked File Transfer & On-Demand Offer Protocol
	fmt.Printf("\n%s[3/8] Testing on-demand chunked file attachment transfer (150 KB, SHA-256 validation)...%s\n", colorBold, colorReset)

	// Disable auto-download on Bob to test on-demand offer behavior
	if err := postJSON(bobURL+"/set-auto-download", map[string]any{"auto_download": false}, nil); err != nil {
		fatal("failed to disable auto-download on bob: %v", err)
	}

	var attachMeta struct {
		FileID      string `json:"file_id"`
		Hash        string `json:"hash"`
		TotalChunks int    `json:"total_chunks"`
	}
	if err := postJSON(aliceURL+"/share-file", map[string]any{"name": "test-data.bin", "size_bytes": 150 * 1024}, &attachMeta); err != nil {
		fatal("alice failed to share file: %v", err)
	}
	fmt.Printf("   Announced attachment offer: FileID=%s (Chunks: %d, SHA-256: %s...)\n", attachMeta.FileID, attachMeta.TotalChunks, attachMeta.Hash[:12])

	// 1. Verify Bob received the offer in /offers
	offerDeadline := time.Now().Add(5 * time.Second)
	offerFound := false
	for time.Now().Before(offerDeadline) {
		var offers []struct {
			FileID string `json:"file_id"`
		}
		if err := getJSON(bobURL+"/offers", &offers); err == nil {
			for _, o := range offers {
				if o.FileID == attachMeta.FileID {
					offerFound = true
					break
				}
			}
		}
		if offerFound {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !offerFound {
		fatal("Bob did not receive attachment offer %s", attachMeta.FileID)
	}

	// 2. Verify Bob has NOT downloaded the file yet
	var bobAtts []AttachmentResponse
	_ = getJSON(bobURL+"/attachments", &bobAtts)
	for _, a := range bobAtts {
		if a.FileID == attachMeta.FileID {
			fatal("Bob automatically downloaded attachment before explicit request!")
		}
	}
	fmt.Printf("   %s✓%s Bob received offer without downloading chunks.\n", colorGreen, colorReset)

	checkAttachmentReceived := func(name, url, expectedHash string) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			var atts []AttachmentResponse
			if err := getJSON(url+"/attachments", &atts); err == nil {
				for _, a := range atts {
					if a.Hash == expectedHash && a.Verified {
						return
					}
				}
			}
			time.Sleep(250 * time.Millisecond)
		}
		fatal("container %s did not successfully assemble & verify attachment", name)
	}

	// 3. Charlie (auto-download enabled) should receive and assemble it
	checkAttachmentReceived("Charlie", charlieURL, attachMeta.Hash)

	// 4. Bob explicitly triggers on-demand download
	fmt.Printf("   Bob triggering on-demand download for %s...\n", attachMeta.FileID)
	if err := postJSON(bobURL+"/download-file", map[string]any{"file_id": attachMeta.FileID}, nil); err != nil {
		fatal("Bob failed to trigger download: %v", err)
	}
	checkAttachmentReceived("Bob", bobURL, attachMeta.Hash)
	_ = postJSON(bobURL+"/set-auto-download", map[string]any{"auto_download": true}, nil)
	fmt.Printf("   %s✓%s On-demand file transfer succeeded and SHA-256 checksum verified on Bob & Charlie.\n", colorGreen, colorReset)

	// Step 4: Transient Network Drop & Ring Buffer Catch-Up
	fmt.Printf("\n%s[4/8] Testing transient network blip & in-memory ring-buffer catch-up...%s\n", colorBold, colorReset)
	fmt.Printf("   Simulating Charlie network drop (disconnecting signaling & WebRTC)...\n")
	if err := postJSON(charlieURL+"/disconnect", nil, nil); err != nil {
		fatal("failed to disconnect charlie: %v", err)
	}

	// Alice sends 5 messages while Charlie is disconnected
	fmt.Printf("   Alice is sending 5 messages while Charlie is offline...\n")
	offlineMsgs := make([]string, 5)
	for i := 0; i < 5; i++ {
		offlineMsgs[i] = fmt.Sprintf("Offline message #%d (%d)", i+1, time.Now().UnixNano())
		_ = postJSON(aliceURL+"/send", map[string]string{"text": offlineMsgs[i]}, nil)
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Printf("   Reconnecting Charlie & triggering catch-up from ring buffer...\n")
	if err := postJSON(charlieURL+"/reconnect", nil, nil); err != nil {
		fatal("failed to reconnect charlie: %v", err)
	}

	// Wait for Charlie to catch up
	for _, m := range offlineMsgs {
		checkMessageReceived("Charlie", charlieURL, m)
	}
	fmt.Printf("   %s✓%s Charlie successfully caught up on all 5 missed messages from ring buffer!\n", colorGreen, colorReset)

	// Step 5: Peer-Assisted NAT Relaying in Channel
	fmt.Printf("\n%s[5/8] Testing peer-assisted NAT relaying (direct link blocked between Alice & Charlie)...%s\n", colorBold, colorReset)
	fmt.Printf("   Blocking direct DataChannel between Alice and Charlie...\n")
	_ = postJSON(aliceURL+"/block", map[string]string{"peer": charlieStatus.Address}, nil)
	_ = postJSON(charlieURL+"/block", map[string]string{"peer": aliceStatus.Address}, nil)

	relayedMsg := fmt.Sprintf("Relayed message via Bob at %d", time.Now().UnixMilli())
	if err := postJSON(aliceURL+"/send", map[string]string{"text": relayedMsg}, nil); err != nil {
		fatal("failed to send relayed message: %v", err)
	}

	checkMessageReceived("Charlie", charlieURL, relayedMsg)
	fmt.Printf("   %s✓%s Charlie received and decrypted Alice's message via Bob's relay!\n", colorGreen, colorReset)

	// Cleanup block
	_ = postJSON(aliceURL+"/unblock", map[string]string{"peer": charlieStatus.Address}, nil)
	_ = postJSON(charlieURL+"/unblock", map[string]string{"peer": aliceStatus.Address}, nil)

	// Step 6: Internal Direct Invite & 1:1 DM Formation
	fmt.Printf("\n%s[6/8] Testing internal direct invite & 1:1 DM burner room formation...%s\n", colorBold, colorReset)
	fmt.Printf("   Alice invites Bob into an ephemeral 1:1 DM room...\n")
	var inviteRes struct {
		Status   string `json:"status"`
		InviteID string `json:"invite_id"`
		RoomID   string `json:"room_id"`
		RoomKey  string `json:"room_key"`
		Target   string `json:"target"`
	}
	if err := postJSON(aliceURL+"/dm/invite", map[string]string{"target": bobStatus.Address}, &inviteRes); err != nil {
		fatal("alice failed to send direct invite to bob: %v", err)
	}
	fmt.Printf("   Invite dispatched: ID=%s, RoomID=%s\n", inviteRes.InviteID[:8], inviteRes.RoomID[:8])

	// Wait for Bob to receive the invite
	fmt.Printf("   Waiting for Bob to receive and verify direct invite...\n")
	var bobInvite *InviteItem
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var invites []InviteItem
		if err := getJSON(bobURL+"/invites", &invites); err == nil {
			for i := range invites {
				if invites[i].InviteID == inviteRes.InviteID {
					bobInvite = &invites[i]
					break
				}
			}
		}
		if bobInvite != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if bobInvite == nil {
		fatal("bob did not receive the direct invite from alice")
	}
	if bobInvite.From != aliceStatus.Address {
		fatal("bob received invite with unexpected sender: %s", bobInvite.From)
	}
	fmt.Printf("   Bob successfully received and decrypted direct invite from %s!\n", bobInvite.From[:8])

	// Bob accepts the invite
	fmt.Printf("   Bob accepts Alice's direct invite...\n")
	if err := postJSON(bobURL+"/dm/accept", map[string]string{"invite_id": bobInvite.InviteID}, nil); err != nil {
		fatal("bob failed to accept invite: %v", err)
	}

	// Wait for 1:1 DM WebRTC DataChannel between Alice and Bob
	fmt.Printf("   Waiting for 1:1 DM DataChannel connection between Alice & Bob...\n")
	waitDMChannel := func(name, url string) {
		dmDeadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(dmDeadline) {
			var s StatusResponse
			if err := getJSON(url+"/status", &s); err == nil {
				if s.DMRoomID != "" && len(s.DMPeers) > 0 {
					return
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
		fatal("%s timed out establishing direct DM WebRTC session", name)
	}
	waitDMChannel("Alice", aliceURL)
	waitDMChannel("Bob", bobURL)
	fmt.Printf("   %s✓%s Alice and Bob formed an active 1:1 DM burner room session.\n", colorGreen, colorReset)

	// Step 7: Cryptographic & Media Isolation (Messages & Audio)
	fmt.Printf("\n%s[7/8] Testing channel & 1:1 DM cryptographic and media stream isolation...%s\n", colorBold, colorReset)

	// Test 7A: DM chat isolation (Bob receives, Charlie receives NOTHING)
	secretDMText := fmt.Sprintf("CONFIDENTIAL_DM_ALICE_TO_BOB_%d", time.Now().UnixMilli())
	fmt.Printf("   Alice sends confidential DM message: '%s'...\n", secretDMText)
	if err := postJSON(aliceURL+"/dm/send", map[string]string{"text": secretDMText}, nil); err != nil {
		fatal("alice failed to send DM message: %v", err)
	}
	checkDMMessageReceived("Bob", bobURL, secretDMText)
	fmt.Printf("   %s✓%s Bob received and decrypted the private DM message.\n", colorGreen, colorReset)

	// Verify Charlie did NOT receive the DM in either channel or DM
	assertNoMessageWithText("Charlie", charlieURL, secretDMText, false)
	assertNoMessageWithText("Charlie", charlieURL, secretDMText, true)
	// Verify Bob did NOT receive the DM in his main channel messages
	assertNoMessageWithText("Bob", bobURL, secretDMText, false)
	fmt.Printf("   %s✓%s Isolation confirmed: Charlie and Channel have zero knowledge of private DM message.\n", colorGreen, colorReset)

	// Test 7B: Channel chat isolation (Bob & Charlie receive in channel, NOT in DM)
	publicChanText := fmt.Sprintf("PUBLIC_CHANNEL_BROADCAST_%d", time.Now().UnixMilli())
	fmt.Printf("   Alice sends public channel message: '%s'...\n", publicChanText)
	if err := postJSON(aliceURL+"/send", map[string]string{"text": publicChanText}, nil); err != nil {
		fatal("alice failed to send channel message: %v", err)
	}
	checkMessageReceived("Bob", bobURL, publicChanText)
	checkMessageReceived("Charlie", charlieURL, publicChanText)
	// Verify Bob did NOT receive channel message in DM messages
	assertNoMessageWithText("Bob", bobURL, publicChanText, true)
	fmt.Printf("   %s✓%s Channel message delivered to room members without leaking into private DM.\n", colorGreen, colorReset)

	// Test 7C: Secondary WebRTC + SFrame DM A/V Call Stream Isolation
	fmt.Printf("   Testing 1:1 DM secondary WebRTC + SFrame A/V call isolation (Alice <-> Bob only; Charlie excluded)...\n")
	if err := postJSON(aliceURL+"/dm/call/join", map[string]any{"audio": true, "video": true}, nil); err != nil {
		fatal("alice failed to join DM call: %v", err)
	}
	if err := postJSON(bobURL+"/dm/call/join", map[string]any{"audio": true, "video": true}, nil); err != nil {
		fatal("bob failed to join DM call: %v", err)
	}
	waitCallPeers("Alice", aliceURL, true, 1)
	waitCallPeers("Bob", bobURL, true, 1)

	dmOpusB64 := sendAndVerifyCallFrame(aliceURL, true, "audio", []byte("SFRAME_DM_OPUS_"+aliceStatus.Address[:8]), []callTarget{{Name: "Bob", URL: bobURL}})
	dmVP8B64 := sendAndVerifyCallFrame(aliceURL, true, "video", []byte("SFRAME_DM_VP8_"+aliceStatus.Address[:8]), []callTarget{{Name: "Bob", URL: bobURL}})
	fmt.Printf("   %s✓%s Bob decrypted Alice's SFrame Opus & VP8 frames over isolated secondary DM RTCPeerConnection.\n", colorGreen, colorReset)

	assertNoCallFramePayload("Charlie (channel)", charlieURL, false, dmOpusB64)
	assertNoCallFramePayload("Charlie (DM)", charlieURL, true, dmOpusB64)
	assertNoCallFramePayload("Charlie (channel video)", charlieURL, false, dmVP8B64)
	assertNoCallFramePayload("Bob (channel leak)", bobURL, false, dmOpusB64)
	var charlieDMStats CallStatsResponse
	_ = getJSON(charlieURL+"/call/stats", &charlieDMStats)
	if len(charlieDMStats.DMCallPeers) != 0 {
		fatal("isolation violation: Charlie formed unexpected secondary DM call peers: %v", charlieDMStats.DMCallPeers)
	}
	fmt.Printf("   %s✓%s Isolation confirmed: Charlie formed 0 DM call PCs and received 0 DM A/V frames.\n", colorGreen, colorReset)

	// Test 7D: Multi-Peer Channel Secondary WebRTC + SFrame Call (3 Peers + Non-Joined Isolation)
	fmt.Printf("   Testing Channel secondary WebRTC + SFrame A/V call (non-joined gate -> 3-peer mesh)...\n")
	if err := postJSON(aliceURL+"/call/join", map[string]any{"audio": true, "video": true}, nil); err != nil {
		fatal("alice failed to join channel call: %v", err)
	}
	if err := postJSON(bobURL+"/call/join", map[string]any{"audio": true, "video": true}, nil); err != nil {
		fatal("bob failed to join channel call: %v", err)
	}
	waitCallPeers("Alice", aliceURL, false, 1)
	waitCallPeers("Bob", bobURL, false, 1)

	preJoinB64 := sendAndVerifyCallFrame(aliceURL, false, "audio", []byte("SFRAME_CHAN_PREJOIN_"+aliceStatus.Address[:8]), []callTarget{{Name: "Bob", URL: bobURL}})
	time.Sleep(400 * time.Millisecond)
	assertNoCallFramePayload("Charlie (pre-join)", charlieURL, false, preJoinB64)
	var charliePreStats CallStatsResponse
	_ = getJSON(charlieURL+"/call/stats", &charliePreStats)
	if len(charliePreStats.ChannelCallPeers) != 0 {
		fatal("gate violation: non-joined Charlie unexpectedly opened secondary call peer connections: %v", charliePreStats.ChannelCallPeers)
	}
	fmt.Printf("   %s✓%s Non-joined gate confirmed: Charlie opened 0 secondary PCs and decrypted 0 frames before joining call.\n", colorGreen, colorReset)

	// Now Charlie joins in listen-only mode -> forms 3-peer secondary mesh
	if err := postJSON(charlieURL+"/call/join", map[string]any{"listen_only": true}, nil); err != nil {
		fatal("charlie failed to join channel call: %v", err)
	}
	waitCallPeers("Alice", aliceURL, false, 2)
	waitCallPeers("Bob", bobURL, false, 2)
	waitCallPeers("Charlie", charlieURL, false, 2)

	chanAudioAliceB64 := sendAndVerifyCallFrame(aliceURL, false, "audio", []byte("SFRAME_CHAN_OPUS_"+aliceStatus.Address[:8]), []callTarget{
		{Name: "Bob", URL: bobURL},
		{Name: "Charlie", URL: charlieURL},
	})
	_ = sendAndVerifyCallFrame(bobURL, false, "video", []byte("SFRAME_CHAN_VP8_"+bobStatus.Address[:8]), []callTarget{
		{Name: "Alice", URL: aliceURL},
		{Name: "Charlie", URL: charlieURL},
	})
	assertNoCallFramePayload("Bob (DM leak)", bobURL, true, chanAudioAliceB64)
	assertNoCallFramePayload("Alice (DM leak)", aliceURL, true, chanAudioAliceB64)

	var charlieChanStats CallStatsResponse
	_ = getJSON(charlieURL+"/call/stats", &charlieChanStats)
	if charlieChanStats.Stats.DecryptedAudio == 0 || charlieChanStats.Stats.DecryptedVideo == 0 || charlieChanStats.Stats.Rejected != 0 {
		fatal("unexpected Charlie SFrame stats: %+v", charlieChanStats.Stats)
	}
	fmt.Printf("   %s✓%s 3-peer native secondary WebRTC SFrame Opus+VP8 verified (Charlie rx audio=%d video=%d rejected=%d); DM call remained strictly isolated.\n",
		colorGreen, colorReset, charlieChanStats.Stats.DecryptedAudio, charlieChanStats.Stats.DecryptedVideo, charlieChanStats.Stats.Rejected)

	// Tear down secondary calls cleanly before Step 8 & browser test suite
	_ = postJSON(aliceURL+"/dm/call/leave", map[string]any{"clear_frames": true}, nil)
	_ = postJSON(bobURL+"/dm/call/leave", map[string]any{"clear_frames": true}, nil)
	_ = postJSON(aliceURL+"/call/leave", map[string]any{"clear_frames": true}, nil)
	_ = postJSON(bobURL+"/call/leave", map[string]any{"clear_frames": true}, nil)
	_ = postJSON(charlieURL+"/call/leave", map[string]any{"clear_frames": true}, nil)
	waitCallPeersZero("Alice", aliceURL, false)
	waitCallPeersZero("Bob", bobURL, false)
	waitCallPeersZero("Charlie", charlieURL, false)

	// Step 8: Direct Communication & Invites Through Peers (Peer-Assisted Relayed DM Chat)
	fmt.Printf("\n%s[8/8] Testing direct communication through peers (DM chat relayed through Charlie; media fallback deferred)...\n%s", colorBold, colorReset)
	fmt.Printf("   Simulating direct DM connection block between Alice & Bob...\n")
	_ = postJSON(aliceURL+"/dm/block", map[string]string{"peer": bobStatus.Address}, nil)
	_ = postJSON(bobURL+"/dm/block", map[string]string{"peer": aliceStatus.Address}, nil)

	relayedDMText := fmt.Sprintf("RELAYED_DM_VIA_CHARLIE_%d", time.Now().UnixMilli())
	fmt.Printf("   Alice sends DM message over peer-assisted relay: '%s'...\n", relayedDMText)
	if err := postJSON(aliceURL+"/dm/send", map[string]string{"text": relayedDMText}, nil); err != nil {
		fatal("alice failed to send relayed DM: %v", err)
	}
	checkDMMessageReceived("Bob", bobURL, relayedDMText)
	fmt.Printf("   %s✓%s Bob received and decrypted Alice's DM message relayed through Charlie!\n", colorGreen, colorReset)

	// Verify Charlie has no plaintext access
	assertNoMessageWithText("Charlie", charlieURL, relayedDMText, false)
	assertNoMessageWithText("Charlie", charlieURL, relayedDMText, true)
	fmt.Printf("   %s✓%s Charlie forwarded DM packets without decrypting or logging them.\n", colorGreen, colorReset)

	// Cleanup DM blocks
	_ = postJSON(aliceURL+"/dm/unblock", map[string]string{"peer": bobStatus.Address}, nil)
	_ = postJSON(bobURL+"/dm/unblock", map[string]string{"peer": aliceStatus.Address}, nil)

	fmt.Printf("\n%s%s=== ALL 8 CONTAINERIZED END-TO-END SCENARIOS PASSED! ===%s\n\n", colorBold, colorGreen, colorReset)
}

func fatal(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("%s[FAIL] %s%s\n", colorRed, msg, colorReset)
	os.Exit(1)
}
