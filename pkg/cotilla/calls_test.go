package cotilla

import (
	"testing"
	"time"
)

func TestMultiPeerMLSCallIsolationAndEvictionVsDM(t *testing.T) {
	// 4 peers in overlay: Alice, Bob, Charlie in Group A; Dave in Anchor/Group B only;
	// plus active 1:1 DM call between Alice and Charlie.
	idA, _ := NewIdentityFromSeed([]byte("cotilla-call-seed-alice-00000001"))
	idB, _ := NewIdentityFromSeed([]byte("cotilla-call-seed-bob-0000000002"))
	idC, _ := NewIdentityFromSeed([]byte("cotilla-call-seed-charlie-000003"))
	idD, _ := NewIdentityFromSeed([]byte("cotilla-call-seed-dave-anchor-04"))

	roomKeyA, _ := GenerateRoomKey()
	roomID := "group-a"

	closedEvents := make(chan string, 16)
	signalsA := make(chan *CallSignalPayload, 8)
	signalsB := make(chan *CallSignalPayload, 8)
	signalsC := make(chan *CallSignalPayload, 8)
	signalsD := make(chan *CallSignalPayload, 8)

	trA := newMemoryTransport(idA.Address())
	trB := newMemoryTransport(idB.Address())
	trC := newMemoryTransport(idC.Address())
	trD := newMemoryTransport(idD.Address())

	nodeA := NewNode(idA, roomID, roomKeyA, DefaultConfig(), trA, Hooks{
		OnCallSignal:     func(s *CallSignalPayload) { signalsA <- s },
		OnCallPeerClosed: func(scopeID, peer string) { closedEvents <- "A:" + scopeID + ":" + peer },
	})
	nodeB := NewNode(idB, roomID, roomKeyA, DefaultConfig(), trB, Hooks{
		OnCallSignal: func(s *CallSignalPayload) { signalsB <- s },
	})
	nodeC := NewNode(idC, roomID, roomKeyA, DefaultConfig(), trC, Hooks{
		OnCallSignal:     func(s *CallSignalPayload) { signalsC <- s },
		OnCallPeerClosed: func(scopeID, peer string) { closedEvents <- "C:" + scopeID + ":" + peer },
	})
	// Dave is ONLY joined to Group B / Anchor, NOT Group A
	roomKeyB, _ := GenerateRoomKey()
	nodeD := NewNode(idD, "group-b", roomKeyB, DefaultConfig(), trD, Hooks{
		OnCallSignal: func(s *CallSignalPayload) { signalsD <- s },
	})

	trA.onData = func(from string, data []byte) { nodeA.HandleWire(from, data) }
	trB.onData = func(from string, data []byte) { nodeB.HandleWire(from, data) }
	trC.onData = func(from string, data []byte) { nodeC.HandleWire(from, data) }
	trD.onData = func(from string, data []byte) { nodeD.HandleWire(from, data) }

	// Connect overlay through Anchor Dave (A<->D, B<->D, C<->D) + direct overlay links
	nodes := []*Node{nodeA, nodeB, nodeC, nodeD}
	trs := []*memoryTransport{trA, trB, trC, trD}
	for i := 0; i < len(trs); i++ {
		for j := i + 1; j < len(trs); j++ {
			trs[i].Connect(trs[j])
			nodes[i].AddPeer(nodes[j].Address())
			nodes[j].AddPeer(nodes[i].Address())
			nodes[i].SetPeerEncKey(nodes[j].Address(), nodes[j].ID.EncAddress())
			nodes[j].SetPeerEncKey(nodes[i].Address(), nodes[i].ID.EncAddress())
		}
	}

	// Bootstrap Alice as MLS creator for group-a and admit Bob & Charlie
	if err := nodeA.InitChannelMLS(roomID); err != nil {
		t.Fatal(err)
	}
	invB, err := nodeA.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	invC, err := nodeA.CreateChannelInvite(15 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	nodeB.SetChannelInvite(invB)
	nodeC.SetChannelInvite(invC)

	nodeB.BroadcastPeerInfo()
	nodeC.BroadcastPeerInfo()

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if nodeB.CurrentEpoch() >= 2 && nodeC.CurrentEpoch() >= 3 && nodeA.CurrentEpoch() >= 3 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if nodeA.CurrentEpoch() < 3 || nodeB.CurrentEpoch() < 2 || nodeC.CurrentEpoch() < 3 {
		t.Fatalf("MLS admission incomplete: A=%d B=%d C=%d", nodeA.CurrentEpoch(), nodeB.CurrentEpoch(), nodeC.CurrentEpoch())
	}

	// Register 1:1 DM between Alice and Charlie
	dmKey, _ := GenerateRoomKey()
	dmRoom := "dm-alice-charlie"
	if err := nodeA.RegisterDMScope(dmRoom, nodeC.Address(), dmKey); err != nil {
		t.Fatal(err)
	}
	if err := nodeC.RegisterDMScope(dmRoom, nodeA.Address(), dmKey); err != nil {
		t.Fatal(err)
	}

	// Join Group A call on Alice, Bob, Charlie; join DM call on Alice & Charlie
	bundleA, err := nodeA.JoinCall(roomID, false, CallOptions{Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nodeB.JoinCall(roomID, false, CallOptions{Audio: true}); err != nil {
		t.Fatal(err)
	}
	bundleC, err := nodeC.JoinCall(roomID, false, CallOptions{Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	bundleDMA, err := nodeA.JoinCall(dmRoom, true, CallOptions{Audio: true})
	if err != nil {
		t.Fatal(err)
	}
	bundleDMC, err := nodeC.JoinCall(dmRoom, true, CallOptions{Audio: true})
	if err != nil {
		t.Fatal(err)
	}

	// Dave tries to export SFrame keys for Group A or signal into Group A -> MUST fail!
	if _, err := nodeD.ExportSFrameKeys(roomID); err == nil {
		t.Fatalf("non-member Dave must not export SFrame keys for Group A")
	}

	// Verify cross-scope SFrame encryption works between Alice & Charlie on DM, and Alice & Bob on Group A,
	// while Dave (only in Group B) never unlocks Group A or DM signals.
	if err := nodeA.SendCallSignal(roomID, nodeB.Address(), "offer", "group-a-sdp"); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-signalsB:
		if s.ScopeID != roomID || s.Payload != "group-a-sdp" {
			t.Fatalf("unexpected B signal: %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Bob never received Group A secondary offer")
	}

	select {
	case s := <-signalsD:
		t.Fatalf("non-member Dave unexpectedly received signal: %+v", s)
	case <-time.After(150 * time.Millisecond):
	}

	// Evict Charlie from Group A mid-call -> must fire OnCallPeerClosed ONLY for Group A, NOT DM!
	if _, err := nodeA.EvictPeerInChannel(roomID, nodeC.Address(), "test eviction"); err != nil {
		t.Fatal(err)
	}

	sawGroupACloseOnA := false
	waitUntil := time.After(2 * time.Second)
	for !sawGroupACloseOnA {
		select {
		case ev := <-closedEvents:
			if ev == "A:"+roomID+":"+nodeC.Address() {
				sawGroupACloseOnA = true
			}
			if ev == "A:"+dmRoom+":"+nodeC.Address() || ev == "C:"+dmRoom+":"+nodeA.Address() {
				t.Fatalf("DM call closed unexpectedly on Group A eviction: %s", ev)
			}
		case <-waitUntil:
			t.Fatalf("timed out waiting for Alice's Group A secondary call close event for Charlie")
		}
	}

	if !nodeA.IsInCall(dmRoom) || !nodeC.IsInCall(dmRoom) {
		t.Fatalf("1:1 DM call should remain active after Group A eviction")
	}

	// Charlie's DM SFrame traffic with Alice must keep working cleanly even though Group A evicted Charlie!
	krDMA := NewSFrameKeyring()
	krDMC := NewSFrameKeyring()
	_ = krDMA.InstallBundle(bundleDMA, 0)
	_ = krDMC.InstallBundle(bundleDMC, 0)
	dmCT, err := krDMA.Encrypt([]byte("private-dm-opus"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, _, err := krDMC.Decrypt(dmCT, idA.Address()); err != nil || string(pt) != "private-dm-opus" {
		t.Fatalf("1:1 DM SFrame decrypt failed post-channel-eviction: %v", err)
	}
	_ = bundleA
	_ = bundleC
	_ = signalsA
	_ = signalsC
}
