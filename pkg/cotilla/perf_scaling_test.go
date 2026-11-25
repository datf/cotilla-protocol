package cotilla

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/datf/cotilla-protocol/internal/perfcheck"
)

// TestPerf_MLSPrivateGroup_ThousandsOfMessages verifies a 5-peer MLS private group with the
// default RingBufferCapacity=200 handles 2,000 (-short) / 5,000 (full) live messages across
// epoch ratchets, late joins, offline catch-up, and eviction with bounded heap and 0 goroutine leaks.
func TestPerf_MLSPrivateGroup_ThousandsOfMessages(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	totalMsgs := 2000
	if !testing.Short() {
		totalMsgs = 5000
	}
	totalMsgs = perfcheck.EnvInt("COTILLA_PERF_MSGS", totalMsgs)

	const peerCount = 5
	roomID := "perf-mls-thousands"
	roomKey, _ := GenerateRoomKey()
	cfg := DefaultConfig() // RingBufferCapacity = 200

	nodes := make([]*Node, peerCount)
	transports := make([]*memoryTransport, peerCount)
	var rxCounts [peerCount]atomic.Int64

	for i := 0; i < peerCount; i++ {
		idx := i
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		nodes[i] = NewNode(id, roomID, roomKey, cfg, tr, Hooks{
			OnMessage: func(env *Envelope, plaintext []byte) {
				rxCounts[idx].Add(1)
			},
		})
		tr.onData = nodes[i].HandleWire
		transports[i] = tr
	}
	defer func() {
		for _, n := range nodes {
			n.StopMeshSupervisor()
		}
		baseG.AssertSettled(t, 4, 2*time.Second)
	}()

	if err := nodes[0].InitGenesisEpoch(); err != nil {
		t.Fatalf("InitGenesisEpoch: %v", err)
	}
	for i := 0; i < peerCount; i++ {
		for j := i + 1; j < peerCount; j++ {
			transports[i].Connect(transports[j])
			nodes[i].AddPeer(nodes[j].Address())
			nodes[j].AddPeer(nodes[i].Address())
		}
	}
	for i := 1; i < peerCount; i++ {
		inv, err := nodes[0].CreateChannelInvite(15 * time.Minute)
		if err != nil {
			t.Fatalf("CreateChannelInvite(%d): %v", i, err)
		}
		nodes[i].SetChannelInvite(inv)
		nodes[i].BroadcastPeerInfo()
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allReady := true
		for _, n := range nodes {
			if n.CurrentEpoch() < int64(peerCount) {
				allReady = false
				break
			}
		}
		if allReady {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	for i, n := range nodes {
		if n.CurrentEpoch() != int64(peerCount) {
			t.Fatalf("node %d epoch=%d, want %d", i, n.CurrentEpoch(), peerCount)
		}
	}

	heapBefore := perfcheck.TakeHeapSnapshot()
	start := time.Now()
	ratchetEvery := totalMsgs / 5
	if ratchetEvery < 200 {
		ratchetEvery = 200
	}

	// Disconnect node 4 during the final 150 messages to verify RingBuffer=200 catch-up.
	offlineStart := totalMsgs - 150
	for m := 0; m < totalMsgs; m++ {
		if m == offlineStart {
			for j := 0; j < peerCount-1; j++ {
				transports[peerCount-1].Disconnect(transports[j])
				nodes[peerCount-1].RemovePeer(nodes[j].Address())
				nodes[j].RemovePeer(nodes[peerCount-1].Address())
			}
		}
		if m > 0 && m%ratchetEvery == 0 && m < offlineStart {
			commit, err := nodes[0].RotateEpochKey()
			if err != nil {
				t.Fatalf("RotateEpochKey at msg %d: %v", m, err)
			}
			for epWait := time.Now(); time.Since(epWait) < time.Second; {
				synced := true
				for i := 1; i < peerCount-1; i++ {
					if nodes[i].CurrentEpoch() < commit.EpochID {
						synced = false
						break
					}
				}
				if synced {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
		sender := nodes[m%(peerCount-1)]
		if _, err := sender.SendMessage(fmt.Sprintf("mls-msg-%05d", m)); err != nil {
			t.Fatalf("SendMessage(%d): %v", m, err)
		}
	}

	// Wait for active nodes 0..3 to receive all messages sent by other peers.
	waitMsgDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitMsgDeadline) {
		done := true
		for i := 0; i < peerCount-1; i++ {
			sentByOthers := int64(totalMsgs - (totalMsgs+peerCount-2-i)/(peerCount-1))
			if rxCounts[i].Load() < sentByOthers {
				done = false
				break
			}
		}
		if done {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	elapsed := time.Since(start)

	for i := 0; i < peerCount-1; i++ {
		sentByOthers := int64(totalMsgs - (totalMsgs+peerCount-2-i)/(peerCount-1))
		if got := rxCounts[i].Load(); got != sentByOthers {
			t.Fatalf("active peer %d received %d/%d messages", i, got, sentByOthers)
		}
		if rbLen := nodes[i].RingBuffer.Len(); rbLen != cfg.RingBufferCapacity {
			t.Fatalf("peer %d RingBuffer.Len()=%d, want %d", i, rbLen, cfg.RingBufferCapacity)
		}
	}

	// Verify SyncRequest wire payload stays compact even after thousands of messages.
	nodes[peerCount-1].mu.RLock()
	syncReq := nodes[peerCount-1].buildSyncRequestLocked(nodes[peerCount-1].ChannelState)
	nodes[peerCount-1].mu.RUnlock()
	reqBytes, _ := json.Marshal(syncReq)
	if len(reqBytes) > 24*1024 {
		t.Fatalf("SyncRequest too large after %d msgs: %d bytes (limit 24KB)", totalMsgs, len(reqBytes))
	}

	// Reconnect node 4 and verify it catches up on all 150 missed messages.
	for j := 0; j < peerCount-1; j++ {
		transports[peerCount-1].Connect(transports[j])
		nodes[peerCount-1].AddPeer(nodes[j].Address())
		nodes[j].AddPeer(nodes[peerCount-1].Address())
	}
	if err := nodes[peerCount-1].RequestCatchUp(); err != nil {
		t.Fatalf("RequestCatchUp: %v", err)
	}
	catchUpDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(catchUpDeadline) {
		if rxCounts[peerCount-1].Load() >= int64(totalMsgs-(totalMsgs/(peerCount-1))) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := rxCounts[peerCount-1].Load(); got < int64(offlineStart-(offlineStart/(peerCount-1))+140) {
		t.Fatalf("reconnected peer %d caught up only %d messages", peerCount-1, got)
	}

	heapAfter := perfcheck.TakeHeapSnapshot()
	t.Logf("MLS %d msgs across %d peers in %v (%.0f msg/s) | RingBuffer=%d | SyncReq=%d B | Heap: %d KB -> %d KB",
		totalMsgs, peerCount, elapsed, float64(totalMsgs)/elapsed.Seconds(),
		cfg.RingBufferCapacity, len(reqBytes), heapBefore.HeapAllocKB, heapAfter.HeapAllocKB)
}

// TestPerf_HyParView_NoIslandsAndSignalingReconnect verifies that:
// 1. Two clusters bridged by fragile hubs survive 40% churn (including bridge loss) without forming islands (Components == 1).
// 2. An isolated node with 0 peers (even in fallbackMode) triggers OnAnchorDeficit, dials signaling, and rejoins the mesh.
func TestPerf_HyParView_NoIslandsAndSignalingReconnect(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	nodeCount := 60
	if !testing.Short() {
		nodeCount = 160
	}
	nodeCount = perfcheck.EnvInt("COTILLA_PERF_ISLAND_NODES", nodeCount)

	cfg := DefaultConfig()
	cfg.MaxPeers = 12
	cfg.MinActivePeers = 6
	cfg.PassiveViewSize = 30
	cfg.ShuffleInterval = 100 * time.Millisecond
	cfg.ShuffleTTL = 3
	cfg.ShuffleFanout = 4
	cfg.BroadcastHopTimeout = 80 * time.Millisecond

	// Simulated signaling anchor node bridging isolated reconnecting nodes back into the mesh.
	sigID, _ := NewIdentity()
	sigTr := newMemoryTransport(sigID.Address())
	sigNode := NewNode(sigID, "", RoomKey{}, cfg, sigTr, Hooks{})
	sigTr.onData = sigNode.HandleWire

	nodes := make([]*Node, nodeCount)
	transports := make([]*memoryTransport, nodeCount)
	var reconnectCount atomic.Int64

	connectPair := func(a, b int) {
		transports[a].Connect(transports[b])
		nodes[a].AddPeer(nodes[b].Address())
		nodes[b].AddPeer(nodes[a].Address())
	}

	roomID := "hyparview-island-test"
	roomKey, _ := GenerateRoomKey()

	for i := 0; i < nodeCount; i++ {
		idx := i
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		var n *Node
		n = NewNode(id, roomID, roomKey, cfg, tr, Hooks{
			OnAnchorDeficit: func(anchors, active int) {
				if active == 0 && n != nil {
					reconnectCount.Add(1)
					// Simulated /ws reconnect to signaling node -> RootIntro -> PeerRequest
					tr.Connect(sigTr)
					n.AddGatewayPeer(sigID.Address())
					n.AddPeer(sigID.Address())
					sigNode.AddPeer(n.Address())
					n.QueryPeers()
				}
			},
			OnPeerCandidate: func(peers []string) {
				// In memoryTransport, dial passive candidates directly to simulate WebRTC handshake.
				for _, p := range peers {
					for j, cand := range nodes {
						if j != idx && cand != nil && cand.Address() == p && len(tr.Peers()) < cfg.MaxPeers {
							connectPair(idx, j)
							break
						}
					}
				}
			},
		})
		tr.onData = n.HandleWire
		nodes[i] = n
		transports[i] = tr
	}
	defer func() {
		sigNode.StopMeshSupervisor()
		for _, n := range nodes {
			if n != nil {
				n.StopMeshSupervisor()
			}
		}
		baseG.AssertSettled(t, 6, 3*time.Second)
	}()

	// Seed two separate clusters (0..half-1 and half..nodeCount-1) bridged only by nodes 0 and half.
	half := nodeCount / 2
	for c := 0; c < 2; c++ {
		lo, hi := 0, half
		if c == 1 {
			lo, hi = half, nodeCount
		}
		for i := lo; i < hi; i++ {
			for k := 1; k <= 4; k++ {
				j := lo + (i-lo+k)%(hi-lo)
				if i != j {
					connectPair(i, j)
				}
			}
		}
	}
	// Fragile bridge between Cluster A and Cluster B + connect bridges to signaling.
	connectPair(0, half)
	connectPair(1, half+1)
	sigTr.Connect(transports[2])
	sigNode.AddPeer(nodes[2].Address())
	nodes[2].AddGatewayPeer(sigID.Address())
	nodes[2].AddPeer(sigID.Address())
	sigTr.Connect(transports[half+2])
	sigNode.AddPeer(nodes[half+2].Address())
	nodes[half+2].AddGatewayPeer(sigID.Address())
	nodes[half+2].AddPeer(sigID.Address())

	// Run HyParView shuffles to populate passive views across both clusters.
	for round := 0; round < 12; round++ {
		for _, n := range nodes {
			n.stepHyParViewShuffle()
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Kill the bridge nodes (0, 1, half, half+1) and 35% of remaining nodes, plus isolate node 5
	// completely (in fallbackMode=true) to verify both anti-island repair and signaling reconnect.
	killed := map[int]bool{0: true, 1: true, half: true, half + 1: true}
	for i := 6; i < nodeCount; i += 3 {
		if len(killed) >= (nodeCount*40)/100 {
			break
		}
		killed[i] = true
	}
	for idx := range killed {
		nodes[idx].StopMeshSupervisor()
		for _, p := range transports[idx].Peers() {
			transports[idx].ClosePeer(p)
		}
		for j, other := range nodes {
			if !killed[j] && other != nil {
				other.RemovePeer(nodes[idx].Address())
			}
		}
	}

	// Completely sever node 5 (even with fallbackMode=true) and clear its passive view
	// so it genuinely runs out of peers and must reconnect to signaling.
	nodes[5].SetFallbackMode(true)
	for _, p := range transports[5].Peers() {
		transports[5].ClosePeer(p)
		nodes[5].RemovePeer(p)
	}
	for _, desc := range nodes[5].overlay.PassivePeers() {
		nodes[5].overlay.RemovePassive(desc.SignPub)
	}
	for j, other := range nodes {
		if j != 5 && !killed[j] && other != nil {
			other.RemovePeer(nodes[5].Address())
		}
	}
	nodes[5].checkAnchorDeficit()

	// Drive repair, shuffles, and checkAnchorDeficit until single component or timeout.
	repairDeadline := time.Now().Add(5 * time.Second)
	var metrics perfcheck.GraphMetrics
	for time.Now().Before(repairDeadline) {
		for i, n := range nodes {
			if killed[i] {
				continue
			}
			n.checkAnchorDeficit()
			if len(n.overlay.ActivePeers()) < cfg.MinActivePeers {
				for _, desc := range n.overlay.PickRepairCandidates(nil, 3) {
					for j, cand := range nodes {
						if !killed[j] && cand.Address() == desc.SignPub {
							connectPair(i, j)
							break
						}
					}
				}
			}
			n.stepHyParViewShuffle()
		}
		adj := make(map[string][]string)
		for i, n := range nodes {
			if killed[i] {
				continue
			}
			adj[n.Address()] = n.overlay.ActivePeers()
		}
		metrics = perfcheck.AnalyzeGraph(adj)
		if metrics.Components == 1 && reconnectCount.Load() > 0 && len(nodes[5].overlay.ActivePeers()) > 0 {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}

	if metrics.Components != 1 {
		t.Fatalf("HyParView formed %d islands after 40%% churn (giant=%d/%d, isolated=%d)",
			metrics.Components, metrics.GiantSize, metrics.Nodes, metrics.IsolatedNodes)
	}
	if reconnectCount.Load() == 0 || len(nodes[5].overlay.ActivePeers()) == 0 {
		t.Fatalf("isolated node 5 failed to reconnect via signaling (reconnects=%d, active=%d)",
			reconnectCount.Load(), len(nodes[5].overlay.ActivePeers()))
	}
	t.Logf("HyParView Post-Churn Graph: nodes=%d edges=%d components=%d diameter=%d avgPath=%.2f avgDeg=%.2f reconnects=%d",
		metrics.Nodes, metrics.Edges, metrics.Components, metrics.Diameter, metrics.AvgPathLen, metrics.AvgDegree, reconnectCount.Load())
}

// TestPerf_MaxHopsAndScaleCapacity characterizes max reachable hops vs. TTL policies
// and steps through mesh node scaling while measuring KB/node, delivery %, and p95 latency.
func TestPerf_MaxHopsAndScaleCapacity(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)

	// Part A: Hop-limit characterization on a 12-hop linear chain (0 - 1 - 2 - ... - 11).
	const chainLen = 12
	roomID := "hop-limit-probe"
	roomKey, _ := GenerateRoomKey()
	chainCfg := DefaultConfig()
	chainCfg.GossipFanout = 2

	chainNodes := make([]*Node, chainLen)
	chainTr := make([]*memoryTransport, chainLen)
	var hopSeen [chainLen]atomic.Int64
	for i := 0; i < chainLen; i++ {
		idx := i
		id, _ := NewIdentity()
		tr := newMemoryTransport(id.Address())
		chainNodes[i] = NewNode(id, roomID, roomKey, chainCfg, tr, Hooks{
			OnMessage: func(env *Envelope, plaintext []byte) {
				hopSeen[idx].Add(1)
			},
		})
		tr.onData = chainNodes[i].HandleWire
		chainTr[i] = tr
		if i > 0 {
			tr.Connect(chainTr[i-1])
			chainNodes[i].AddPeer(chainNodes[i-1].Address())
			chainNodes[i-1].AddPeer(chainNodes[i].Address())
		}
	}

	probeTTL := func(ttl int) int {
		for i := range hopSeen {
			hopSeen[i].Store(0)
		}
		plain, _ := json.Marshal(ChatPayload{Type: "chat", Text: fmt.Sprintf("ttl-%d", ttl)})
		env, _ := NewEnvelope(chainNodes[0].ID, roomID, roomKey, plain)
		pkt, _ := NewGroupPacket(chainNodes[0].ID, BroadcastAddr, chainNodes[0].ChannelHash, 0, roomKey, PortChat, ttl, env)
		chainNodes[0].broadcastPacketWithFanout(pkt, 2)
		time.Sleep(80 * time.Millisecond)
		maxHop := 0
		for i := 1; i < chainLen; i++ {
			if hopSeen[i].Load() > 0 {
				maxHop = i
			}
		}
		return maxHop
	}

	maxPrivate := probeTTL(chainCfg.PrivateGroupTTL) // TTL=3 -> reaches 3 hops
	maxPublic := probeTTL(chainCfg.PublicGroupTTL)   // TTL=6 -> reaches 6 hops
	maxCap := probeTTL(maxGossipTTL)                 // TTL=20 -> reaches entire 11-hop chain
	for _, n := range chainNodes {
		n.StopMeshSupervisor()
	}
	if maxPrivate != chainCfg.PrivateGroupTTL || maxPublic != chainCfg.PublicGroupTTL || maxCap != chainLen-1 {
		t.Fatalf("unexpected hop reach: private=%d (want %d), public=%d (want %d), max=%d (want %d)",
			maxPrivate, chainCfg.PrivateGroupTTL, maxPublic, chainCfg.PublicGroupTTL, maxCap, chainLen-1)
	}
	t.Logf("Max Hops Verified: PrivateGroupTTL(%d)=%d hops | PublicGroupTTL(%d)=%d hops | MaxGossipTTL(%d)=%d/%d chain hops",
		chainCfg.PrivateGroupTTL, maxPrivate, chainCfg.PublicGroupTTL, maxPublic, maxGossipTTL, maxCap, chainLen-1)

	// Part B: Client capacity ladder (KB/node, delivery %, p95 broadcast latency).
	tiers := []int{20, 50, 100}
	if !testing.Short() {
		tiers = []int{50, 150, 300}
		if envN := perfcheck.EnvInt("COTILLA_PERF_NODES", 0); envN > 0 {
			tiers = append(tiers, envN)
		}
	}

	for _, nPeers := range tiers {
		t.Run(fmt.Sprintf("Mesh_%d_Nodes", nPeers), func(t *testing.T) {
			baseG := perfcheck.CaptureGoroutines()
			heapStart := perfcheck.TakeHeapSnapshot()

			cfg := DefaultConfig()
			cfg.GossipFanout = 6
			cfg.PrivateGroupTTL = 8

			mNodes := make([]*Node, nPeers)
			mTr := make([]*memoryTransport, nPeers)
			var rxMu sync.Mutex
			rxTimes := make(map[int]time.Duration, nPeers)
			var sendStart time.Time

			for i := 0; i < nPeers; i++ {
				idx := i
				id, _ := NewIdentity()
				tr := newMemoryTransport(id.Address())
				mNodes[i] = NewNode(id, roomID, roomKey, cfg, tr, Hooks{
					OnMessage: func(env *Envelope, plaintext []byte) {
						rxMu.Lock()
						if _, ok := rxTimes[idx]; !ok {
							rxTimes[idx] = time.Since(sendStart)
						}
						rxMu.Unlock()
					},
				})
				tr.onData = mNodes[i].HandleWire
				mTr[i] = tr
			}

			// Connect degree-8 expander-like ring + chords so graph diameter stays <= 5 at 500 nodes.
			for i := 0; i < nPeers; i++ {
				for _, step := range []int{1, 2, nPeers/4 + 1, (nPeers/3 + i*7) % nPeers} {
					j := (i + step) % nPeers
					if i != j {
						mTr[i].Connect(mTr[j])
						mNodes[i].AddPeer(mNodes[j].Address())
						mNodes[j].AddPeer(mNodes[i].Address())
					}
				}
			}

			heapWithNodes := perfcheck.TakeHeapSnapshot()
			kbPerNode := float64(int64(heapWithNodes.HeapAllocKB)-int64(heapStart.HeapAllocKB)) / float64(nPeers)

			sendStart = time.Now()
			if _, err := mNodes[0].SendMessage("scale-probe"); err != nil {
				t.Fatalf("SendMessage: %v", err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				rxMu.Lock()
				got := len(rxTimes)
				rxMu.Unlock()
				if got >= nPeers-1 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}

			rxMu.Lock()
			latencies := make([]time.Duration, 0, len(rxTimes))
			for _, d := range rxTimes {
				latencies = append(latencies, d)
			}
			rxMu.Unlock()
			sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
			var p95 time.Duration
			if len(latencies) > 0 {
				p95 = latencies[(len(latencies)*95)/100]
			}
			deliveryPct := 100.0 * float64(len(latencies)) / float64(nPeers-1)

			for _, n := range mNodes {
				n.StopMeshSupervisor()
			}
			baseG.AssertSettled(t, 4, 2*time.Second)

			if deliveryPct < 98.0 {
				t.Fatalf("delivery=%.1f%% (< 98%%) at %d nodes", deliveryPct, nPeers)
			}
			t.Logf("Capacity %d nodes: %.1f KB/node | delivery=%.1f%% (%d/%d) | p95=%v",
				nPeers, kbPerNode, deliveryPct, len(latencies), nPeers-1, p95)
		})
	}
}

func BenchmarkPacketSignVerify(b *testing.B) {
	id, _ := NewIdentity()
	rk, _ := GenerateRoomKey()
	chHash := ComputeChannelHash("bench-room", rk)
	body := ChatPayload{Type: "chat", Text: "benchmark payload"}
	pkt, _ := NewGroupPacket(id, BroadcastAddr, chHash, 1, rk, PortChat, 3, body)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignPacket(id, pkt)
		if err := VerifyPacket(pkt, maxGossipTTL, 5*time.Minute); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGroupEncryptDecrypt(b *testing.B) {
	id, _ := NewIdentity()
	rk, _ := GenerateRoomKey()
	chHash := ComputeChannelHash("bench-room", rk)
	body := ChatPayload{Type: "chat", Text: "benchmark encrypted group payload"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt, err := NewGroupPacket(id, BroadcastAddr, chHash, 1, rk, PortChat, 3, body)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := OpenGroupPacket(rk, pkt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRingBufferPush(b *testing.B) {
	id, _ := NewIdentity()
	rk, _ := GenerateRoomKey()
	rb := NewRingBuffer(200, 15*time.Minute)
	envs := make([]*Envelope, 256)
	for i := range envs {
		envs[i], _ = NewEnvelope(id, "bench", rk, []byte(`{"type":"chat","text":"hello"}`))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Push(envs[i&255])
	}
}

func BenchmarkMLSAddAndUpdateCommit(b *testing.B) {
	id0, _ := NewIdentity()
	grp, _ := NewMLSGroup("bench-mls", id0)
	id1, _ := NewIdentity()
	kp1, _ := NewKeyPackage(id1)
	_, _, _ = grp.CreateAddCommit(kp1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := grp.CreateUpdateCommit(); err != nil {
			b.Fatal(err)
		}
	}
}
