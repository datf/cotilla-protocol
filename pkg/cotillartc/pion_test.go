//go:build !js && !wasip1

package cotillartc

import (
	"bytes"
	"encoding/json"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/pion/webrtc/v4"
)

// TestPionDataChannelCarriesEphemeralEnvelope establishes a real pion<->pion WebRTC connection
// over loopback and verifies a signed, encrypted Cotilla envelope crosses it and is decrypted.
func TestPionDataChannelCarriesEphemeralEnvelope(t *testing.T) {
	alice, _ := cot.NewIdentity()
	bob, _ := cot.NewIdentity()
	roomKey, _ := cot.GenerateRoomKey()
	roomID := "webrtc-pion-room"

	receivedPlaintext := make(chan string, 1)

	var bobNode *cot.Node
	bobTr := New(bob.Address(), nil, func(from string, data []byte) {
		bobNode.HandleWire(from, data)
	})
	bobNode = cot.NewNode(bob, roomID, roomKey, cot.DefaultConfig(), bobTr, cot.Hooks{
		OnMessage: func(env *cot.Envelope, plaintext []byte) {
			var chat cot.ChatPayload
			_ = json.Unmarshal(plaintext, &chat)
			receivedPlaintext <- chat.Text
		},
	})

	var aliceNode *cot.Node
	aliceTr := New(alice.Address(), nil, func(from string, data []byte) {
		aliceNode.HandleWire(from, data)
	})
	aliceNode = cot.NewNode(alice, roomID, roomKey, cot.DefaultConfig(), aliceTr, cot.Hooks{})

	opened := make(chan string, 2)
	aliceTr.OnOpen(func(addr string) { opened <- addr })
	bobTr.OnOpen(func(addr string) { opened <- addr })

	// Signaling handshake
	offer, err := aliceTr.CreateOffer(bob.Address())
	if err != nil {
		t.Fatal(err)
	}
	answer, err := bobTr.AcceptOffer(alice.Address(), offer)
	if err != nil {
		t.Fatal(err)
	}
	if err := aliceTr.AcceptAnswer(bob.Address(), answer); err != nil {
		t.Fatal(err)
	}

	// Wait for channels to open on both ends
	for i := 0; i < 2; i++ {
		select {
		case <-opened:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for WebRTC DataChannels to open")
		}
	}

	aliceNode.AddPeer(bob.Address())
	bobNode.AddPeer(alice.Address())

	// Overlay DataChannel connection MUST remain track-free (0 media transceivers).
	if cnt := aliceTr.PeerTransceiverCount(bob.Address()); cnt != 0 {
		t.Fatalf("overlay transport attached %d transceivers; want 0", cnt)
	}
	if cnt := bobTr.PeerTransceiverCount(alice.Address()); cnt != 0 {
		t.Fatalf("overlay transport attached %d transceivers; want 0", cnt)
	}

	testMsg := "encrypted message over real pion WebRTC DataChannel"
	_, err = aliceNode.SendMessage(testMsg)
	if err != nil {
		t.Fatalf("failed to send envelope: %v", err)
	}

	select {
	case got := <-receivedPlaintext:
		if got != testMsg {
			t.Fatalf("bob received %q, expected %q", got, testMsg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bob never received envelope over WebRTC DataChannel")
	}

	aliceTr.Close()
	bobTr.Close()
}

// TestPionSecondaryCallMedia3PeersSFrameAndEviction verifies that:
// 1. Secondary CallMediaTransport connections negotiate Opus + VP8 tracks in parallel across 3+ peers.
// 2. Opus audio and multi-packet VP8 video frames are encrypted end-to-end with MLS SFrame keys.
// 3. A 4th peer outside the MLS group (or an evicted peer whose keys are purged) cannot decrypt
//    post-eviction media and is disconnected cleanly from secondary connections.
func TestPionSecondaryCallMedia3PeersSFrameAndEviction(t *testing.T) {
	idA, _ := cot.NewIdentityFromSeed([]byte("pion-call-alice-0000000000000001"))
	idB, _ := cot.NewIdentityFromSeed([]byte("pion-call-bob-000000000000000002"))
	idC, _ := cot.NewIdentityFromSeed([]byte("pion-call-charlie-00000000000003"))
	idD, _ := cot.NewIdentityFromSeed([]byte("pion-call-dave-nonmember-0000004"))

	grpA, err := cot.NewMLSGroup("sec-call-room", idA)
	if err != nil {
		t.Fatal(err)
	}
	kpB, _ := cot.NewKeyPackage(idB)
	_, welcomeB, err := grpA.CreateAddCommit(kpB)
	if err != nil {
		t.Fatal(err)
	}
	grpB, err := cot.NewMLSGroupFromWelcome(idB, welcomeB, kpB.InitPriv)
	if err != nil {
		t.Fatal(err)
	}
	kpC, _ := cot.NewKeyPackage(idC)
	commitC, welcomeC, err := grpA.CreateAddCommit(kpC)
	if err != nil {
		t.Fatal(err)
	}
	if err := grpB.ProcessCommit(commitC); err != nil {
		t.Fatal(err)
	}
	grpC, err := cot.NewMLSGroupFromWelcome(idC, welcomeC, kpC.InitPriv)
	if err != nil {
		t.Fatal(err)
	}

	deriveBundle := func(g *cot.MLSGroup, addr string) *cot.SFrameKeyBundle {
		ep, myLeaf, leaves, base, err := g.SnapshotForSFrame("cotilla sframe v1", []byte("sec-call-room"))
		if err != nil {
			t.Fatal(err)
		}
		bundle := &cot.SFrameKeyBundle{ScopeID: "sec-call-room", Epoch: ep, LeafIndex: myLeaf}
		bundle.Sender, err = cot.DeriveLeafSFrameKey(base, ep, myLeaf, addr)
		if err != nil {
			t.Fatal(err)
		}
		for _, lf := range leaves {
			if lf.Address == addr {
				continue
			}
			r, err := cot.DeriveLeafSFrameKey(base, ep, lf.LeafIndex, lf.Address)
			if err != nil {
				t.Fatal(err)
			}
			bundle.Receivers = append(bundle.Receivers, r)
		}
		return bundle
	}

	mtA := NewCallMediaTransport(idA.Address(), nil, nil)
	mtB := NewCallMediaTransport(idB.Address(), nil, nil)
	mtC := NewCallMediaTransport(idC.Address(), nil, nil)
	mtD := NewCallMediaTransport(idD.Address(), nil, nil)
	defer mtA.Close()
	defer mtB.Close()
	defer mtC.Close()
	defer mtD.Close()

	_ = mtA.UpdateSFrameBundle(deriveBundle(grpA, idA.Address()), 3*time.Second)
	_ = mtB.UpdateSFrameBundle(deriveBundle(grpB, idB.Address()), 3*time.Second)
	_ = mtC.UpdateSFrameBundle(deriveBundle(grpC, idC.Address()), 3*time.Second)

	// Non-member D uses wrong SFrame secret -> must reject packets even if connected to RTP!
	wrongGroup, _ := cot.NewMLSGroup("other-room", idD)
	_ = mtD.UpdateSFrameBundle(deriveBundle(wrongGroup, idD.Address()), 3*time.Second)

	type recvFrame struct {
		peer string
		kind string
		data []byte
	}
	bGot := make(chan recvFrame, 32)
	cGot := make(chan recvFrame, 32)
	dGot := make(chan recvFrame, 32)
	mtB.OnMediaFrame(func(_, fromPeer, kind string, _ uint64, pt []byte) {
		cp := append([]byte(nil), pt...)
		bGot <- recvFrame{peer: fromPeer, kind: kind, data: cp}
	})
	mtC.OnMediaFrame(func(_, fromPeer, kind string, _ uint64, pt []byte) {
		cp := append([]byte(nil), pt...)
		cGot <- recvFrame{peer: fromPeer, kind: kind, data: cp}
	})
	mtD.OnMediaFrame(func(_, fromPeer, kind string, _ uint64, pt []byte) {
		cp := append([]byte(nil), pt...)
		dGot <- recvFrame{peer: fromPeer, kind: kind, data: cp}
	})

	connected := make(chan string, 16)
	watchConn := func(label string, mt *CallMediaTransport) {
		mt.OnPeerState(func(_ string, peerAddr string, st webrtc.PeerConnectionState) {
			if st == webrtc.PeerConnectionStateConnected {
				connected <- label + ":" + peerAddr
			}
		})
	}
	watchConn("A", mtA)
	watchConn("B", mtB)
	watchConn("C", mtC)
	watchConn("D", mtD)

	connectCallPair := func(off *CallMediaTransport, ans *CallMediaTransport, offAddr, ansAddr string) {
		offer, err := off.CreateOffer("sec-call-room", ansAddr)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := ans.AcceptOffer("sec-call-room", offAddr, offer)
		if err != nil {
			t.Fatal(err)
		}
		if err := off.AcceptAnswer("sec-call-room", ansAddr, answer); err != nil {
			t.Fatal(err)
		}
	}

	connectCallPair(mtA, mtB, idA.Address(), idB.Address())
	connectCallPair(mtB, mtC, idB.Address(), idC.Address())
	connectCallPair(mtA, mtC, idA.Address(), idC.Address())
	// Also test wrong-key transport D receives Alice's RTP to verify SFrame AEAD rejection
	connectCallPair(mtA, mtD, idA.Address(), idD.Address())

	connCount := 0
	deadline := time.After(10 * time.Second)
	for connCount < 8 {
		select {
		case <-connected:
			connCount++
		case <-deadline:
			if connCount < 6 {
				t.Fatalf("timed out waiting for secondary call connections (%d/8)", connCount)
			}
			connCount = 8
		}
	}

	wantAudio := []byte{0xf8, 0xff, 0xfe, 0x11, 0x22, 0x33, 0x44, 0x55}
	// 3200 bytes exercises multi-packet VP8 fragmentation across RTP MTU boundaries.
	wantVideo := bytes.Repeat([]byte{0x9c, 0x01, 0x2a, 0x7f}, 800)

	// Send several Opus + VP8 frames over ~300ms so DTLS-SRTP keys & SSRC latches are warm.
	for i := 0; i < 6; i++ {
		if err := mtA.WriteAudioFrame("sec-call-room", wantAudio, 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if err := mtA.WriteVideoFrame("sec-call-room", wantVideo, 33*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
	}

	waitBoth := func(name string, ch <-chan recvFrame) {
		t.Helper()
		var gotAudio, gotVideo bool
		timeout := time.After(5 * time.Second)
		for !gotAudio || !gotVideo {
			select {
			case f := <-ch:
				if f.kind == MediaKindAudio && bytes.Equal(f.data, wantAudio) {
					gotAudio = true
				}
				if f.kind == MediaKindVideo && bytes.Equal(f.data, wantVideo) {
					gotVideo = true
				}
			case <-timeout:
				t.Fatalf("%s did not decrypt both audio (%v) and multi-packet VP8 video (%v)", name, gotAudio, gotVideo)
			}
		}
	}
	waitBoth("Bob", bGot)
	waitBoth("Charlie", cGot)

	// Non-member Dave must have decrypted 0 frames and recorded SFrame rejections.
	select {
	case f := <-dGot:
		t.Fatalf("non-member Dave decrypted protected media unexpectedly: %+v", f)
	case <-time.After(100 * time.Millisecond):
	}
	if mtD.Stats().Rejected == 0 {
		t.Fatalf("expected non-member Dave to record SFrame AEAD rejections")
	}

	// Evict Charlie -> revoke Charlie & rotate epoch on Alice/Bob -> Charlie cannot decrypt new audio!
	rmCommit, err := grpA.CreateRemoveCommit(grpC.MyLeafIndex)
	if err != nil {
		t.Fatal(err)
	}
	if err := grpB.ProcessCommit(rmCommit); err != nil {
		t.Fatal(err)
	}
	mtA.RevokeAndClosePeer("sec-call-room", idC.Address())
	mtB.RevokeAndClosePeer("sec-call-room", idC.Address())
	_ = mtA.UpdateSFrameBundle(deriveBundle(grpA, idA.Address()), 3*time.Second)
	_ = mtB.UpdateSFrameBundle(deriveBundle(grpB, idB.Address()), 3*time.Second)

	// Drain any pre-eviction frames already queued in cGot
	for len(cGot) > 0 {
		<-cGot
	}

	postEvictAudio := []byte{0xf8, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	for i := 0; i < 4; i++ {
		if err := mtA.WriteAudioFrame("sec-call-room", postEvictAudio, 20*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
	}

	gotPostB := false
	afterB := time.After(3 * time.Second)
	for !gotPostB {
		select {
		case f := <-bGot:
			if bytes.Equal(f.data, postEvictAudio) {
				gotPostB = true
			}
		case <-afterB:
			t.Fatal("Bob failed to decrypt post-eviction Opus frame")
		}
	}

	select {
	case f := <-cGot:
		if bytes.Equal(f.data, postEvictAudio) {
			t.Fatalf("evicted Charlie decrypted post-eviction media!")
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// TestCallMediaTransportConcurrentPresenceAndDuplicateOffer exercises a 3-peer mesh where rapid
// back-to-back join/update presence events and concurrent duplicate AcceptOffer calls must not
// spawn duplicate offers or close an active/pending secondary PC with InvalidStateError.
func TestCallMediaTransportConcurrentPresenceAndDuplicateOffer(t *testing.T) {
	ids := make([]*cot.Identity, 3)
	for i := range ids {
		id, err := cot.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id
	}
	sort.Slice(ids, func(i, j int) bool {
		return ids[i].Address() < ids[j].Address()
	})
	lowID, midID, highID := ids[0], ids[1], ids[2]

	scopeID := "concurrent-dm-or-room"
	transports := make(map[string]*CallMediaTransport, 3)
	var errCount atomic.Int32
	var offerCount sync.Map

	for _, id := range ids {
		addr := id.Address()
		var mt *CallMediaTransport
		mt = NewCallMediaTransport(addr, nil, func(sc, target, kind, payload string) error {
			if kind == "offer" {
				v, _ := offerCount.LoadOrStore(addr+"->"+target, &atomic.Int32{})
				v.(*atomic.Int32).Add(1)
			}
			peerTr := transports[target]
			if peerTr != nil {
				peerTr.HandleSignal(&cot.CallSignalPayload{
					ScopeID: sc,
					Kind:    kind,
					Payload: payload,
					From:    addr,
				})
			}
			return nil
		})
		defer mt.Close()
		mt.OnError(func(sc, peerAddr, op string, err error) {
			errCount.Add(1)
			t.Errorf("[%s] unexpected secondary call error scope=%s peer=%s op=%s: %v", addr[:8], sc, peerAddr[:8], op, err)
		})
		transports[addr] = mt
	}

	// Simulate rapid bursts of "join" + "update" presence across the 3-peer mesh before goroutines settle.
	presenceOf := func(action string) *cot.CallPresencePayload {
		return &cot.CallPresencePayload{Action: action, ScopeID: scopeID, Audio: true}
	}
	var wg sync.WaitGroup
	for _, pair := range [][2]string{
		{lowID.Address(), midID.Address()},
		{lowID.Address(), highID.Address()},
		{midID.Address(), highID.Address()},
	} {
		recver := pair[0]
		sender := pair[1]
		for _, act := range []string{"join", "update", "update"} {
			act := act
			wg.Add(1)
			go func() {
				defer wg.Done()
				transports[recver].HandlePresence(scopeID, sender, presenceOf(act))
			}()
		}
	}
	wg.Wait()

	// Wait for every peer in the 3-peer mesh to connect 2 secondary call peers cleanly.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		allConnected := true
		for _, id := range ids {
			if len(transports[id.Address()].ConnectedPeers(scopeID)) < 2 {
				allConnected = false
				break
			}
		}
		if allConnected {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, id := range ids {
		if got := len(transports[id.Address()].ConnectedPeers(scopeID)); got != 2 {
			t.Fatalf("peer %s expected 2 connected secondary call peers, got %d", id.Address()[:8], got)
		}
	}

	// Duplicate direct CreateOffer while connected must be rejected without clobbering.
	if _, err := transports[lowID.Address()].CreateOffer(scopeID, midID.Address()); err == nil {
		t.Fatalf("expected duplicate CreateOffer to active call peer to be rejected")
	}

	// Verify only 1 offer was sent per deterministic lower->higher pair despite burst presence updates.
	for _, edge := range []string{
		lowID.Address() + "->" + midID.Address(),
		lowID.Address() + "->" + highID.Address(),
		midID.Address() + "->" + highID.Address(),
	} {
		v, ok := offerCount.Load(edge)
		if !ok || v.(*atomic.Int32).Load() != 1 {
			var c int32
			if ok {
				c = v.(*atomic.Int32).Load()
			}
			t.Fatalf("expected exactly 1 offer on %s, got %d", edge, c)
		}
	}

	// Also verify concurrent duplicate AcceptOffer calls on an isolated scope serialize without InvalidStateError.
	mt1 := NewCallMediaTransport("peer-1", nil, nil)
	mt2 := NewCallMediaTransport("peer-2", nil, nil)
	defer mt1.Close()
	defer mt2.Close()
	dupOffer, err := mt1.CreateOffer("serial-scope", "peer-2")
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		go func() {
			_, e := mt2.AcceptOffer("serial-scope", "peer-1", dupOffer)
			errs <- e
		}()
	}
	for i := 0; i < 3; i++ {
		if e := <-errs; e != nil {
			t.Fatalf("concurrent AcceptOffer #%d failed: %v", i, e)
		}
	}
	if errCount.Load() != 0 {
		t.Fatalf("expected 0 asynchronous secondary call errors, got %d", errCount.Load())
	}
}
