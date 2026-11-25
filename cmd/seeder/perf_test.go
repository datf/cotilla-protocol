package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/datf/cotilla-protocol/internal/perfcheck"
	"github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

// TestPerf_Seeder_ConcurrentWavesAndLeaks benchmarks SeederDaemon serving a ~320 KB bundle
// to concurrent 3-peer leecher waves over real Pion WebRTC DataChannels and checks for leaks.
func TestPerf_Seeder_ConcurrentWavesAndLeaks(t *testing.T) {
	defer perfcheck.AssertNoGoroutineLeaks(t)
	baseG := perfcheck.CaptureGoroutines()

	bundleSize := 320 * 1024 // matches cotilla-svelte.html single-file bundle
	waves := 2
	peersPerWave := 3
	if !testing.Short() {
		waves = 3
		peersPerWave = 4
	}

	tmpDir := t.TempDir()
	pubHex, privHex, err := cotilla.GeneratePublisherKeypair()
	if err != nil {
		t.Fatalf("GeneratePublisherKeypair: %v", err)
	}
	bundleBytes := make([]byte, bundleSize)
	_, _ = rand.Read(bundleBytes)
	bundlePath := filepath.Join(tmpDir, "app.html")
	if err := os.WriteFile(bundlePath, bundleBytes, 0600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	manifest, err := cotilla.SignAppBundle(privHex, "cotilla-svelte", "stable", "1.0.0", 1, bundleBytes, "text/html", cotilla.FormatSingleHTMLV1, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignAppBundle: %v", err)
	}
	manifestBytes, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tmpDir, "app.manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	sigSrv, stopSig := newMiniSignalingServer(t)
	defer stopSig()
	wsURL := "ws" + strings.TrimPrefix(sigSrv.URL, "http") + "/ws"

	seeder, err := NewSeederDaemon(SeederOptions{
		SignalingURL: wsURL,
		BundlePath:   bundlePath,
		ManifestPath: manifestPath,
	})
	if err != nil {
		t.Fatalf("NewSeederDaemon: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seeder.Start(ctx)
	defer seeder.Close()

	// Wait for seeder to connect to signaling.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(seeder.transport.Peers()) == 0 {
		time.Sleep(30 * time.Millisecond)
	}
	if len(seeder.transport.Peers()) == 0 {
		t.Fatal("seeder failed to connect to signaling gateway")
	}

	heapStart := perfcheck.TakeHeapSnapshot()
	var totalBytes atomic.Int64
	totalStart := time.Now()

	for w := 0; w < waves; w++ {
		waveStart := time.Now()
		var wg sync.WaitGroup
		var errs atomic.Int64

		for p := 0; p < peersPerWave; p++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				id, _ := cotilla.NewIdentity()
				doneCh := make(chan []byte, 1)

				var node *cotilla.Node
				tr := cotillartc.New(id.Address(), nil, func(from string, data []byte) {
					if node != nil {
						node.HandleWire(from, data)
					}
				})
				defer tr.Close()

				node = cotilla.NewNode(id, cotilla.DefaultAppDistRoomID, cotilla.AppDistRoomKeyFor(cotilla.DefaultAppDistRoomID), cotilla.DefaultConfig(), tr, cotilla.Hooks{
					OnAppBundleReady: func(m *cotilla.AppManifest, data []byte) {
						if err := cotilla.VerifyAppBundleWithKeys(m, data, []string{pubHex}, "cotilla-svelte", "1.0.0", "stable", 1, time.Now().UnixMilli()); err == nil {
							select {
							case doneCh <- data:
							default:
							}
						}
					},
				})
				tr.OnOpen(func(addr string) {
					node.AddPeer(addr)
					if node.IsGatewayPeer(addr) {
						node.QueryPeers()
					} else {
						node.RequestAppManifest(cotilla.DefaultAppDistRoomID, "cotilla-svelte", "stable", 1)
					}
				})
				tr.OnClose(func(addr string) { node.RemovePeer(addr) })

				if _, err := node.BootstrapApp(cotilla.AppBootstrapConfig{
					AppName:         "cotilla-svelte",
					Version:         "1.0.0",
					MinSeq:          1,
					ValidSignatures: []string{pubHex},
					SeederGroup:     cotilla.SeederGroupConfig{Name: cotilla.DefaultAppDistRoomID, Channel: "stable"},
				}); err != nil {
					errs.Add(1)
					return
				}

				dCtx, dCancel := context.WithTimeout(ctx, 15*time.Second)
				defer dCancel()
				if _, err := cotillartc.DialSignalingWS(dCtx, wsURL, id, tr, node); err != nil {
					errs.Add(1)
					return
				}

				tick := time.NewTicker(400 * time.Millisecond)
				defer tick.Stop()
				timeout := time.NewTimer(20 * time.Second)
				defer timeout.Stop()
				for {
					select {
					case got := <-doneCh:
						totalBytes.Add(int64(len(got)))
						node.StopMeshSupervisor()
						return
					case <-tick.C:
						node.RequestAppManifest(cotilla.DefaultAppDistRoomID, "cotilla-svelte", "stable", 1)
					case <-timeout.C:
						errs.Add(1)
						node.StopMeshSupervisor()
						return
					}
				}
			}(p)
		}
		wg.Wait()
		if e := errs.Load(); e > 0 {
			t.Fatalf("wave %d had %d failed leecher(s)", w, e)
		}
		t.Logf("Seeder Wave %d (%d concurrent peers x %d KB) completed in %v", w+1, peersPerWave, bundleSize/1024, time.Since(waveStart))
	}

	elapsed := time.Since(totalStart)
	heapEnd := perfcheck.TakeHeapSnapshot()
	mbps := float64(totalBytes.Load()) / (1024 * 1024) / elapsed.Seconds()

	cancel()
	seeder.Close()
	stopSig()
	baseG.AssertSettled(t, 8, 8*time.Second)

	t.Logf("Seeder Total: %d waves x %d peers = %.2f MB in %v (%.2f MB/s) | Heap: %d -> %d KB",
		waves, peersPerWave, float64(totalBytes.Load())/(1024*1024), elapsed, mbps, heapStart.HeapAllocKB, heapEnd.HeapAllocKB)
}

func newMiniSignalingServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	hubID, _ := cotilla.NewIdentity()
	var hubTr *cotillartc.PionTransport
	var hubNode *cotilla.Node
	hubTr = cotillartc.New(hubID.Address(), nil, func(from string, data []byte) {
		if hubNode != nil {
			hubNode.HandleWire(from, data)
		}
	})
	hubNode = cotilla.NewNode(hubID, "", cotilla.RoomKey{}, cotilla.DefaultConfig(), hubTr, cotilla.Hooks{})
	hubTr.OnOpen(func(peer string) {
		hubNode.AddPeer(peer)
		intro := cotilla.RootIntroFrame{AnchorPeers: hubTr.Peers(), IsAnchor: true}
		if pkt, err := cotilla.NewPlainPacket(hubID, peer, cotilla.PortRootIntro, 1, intro); err == nil {
			if raw, err := cotilla.MarshalPacket(pkt); err == nil {
				_ = hubTr.Send(peer, raw)
			}
		}
	})
	hubTr.OnClose(func(peer string) { hubNode.RemovePeer(peer) })

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

		_, rawReg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var reg struct {
			Peer string `json:"peer"`
		}
		if json.Unmarshal(rawReg, &reg) != nil || reg.Peer == "" {
			return
		}
		sdp, err := hubTr.CreateOffer(reg.Peer)
		if err != nil {
			return
		}
		ts := time.Now().UnixMilli()
		sig := hex.EncodeToString(hubID.Sign(cotilla.CanonicalSignalingMsg("offer", hubID.Address(), reg.Peer, sdp, ts)))
		offerBytes, _ := json.Marshal(map[string]any{
			"type": "offer", "peer": hubID.Address(), "target": reg.Peer, "sdp": sdp, "timestamp": ts, "signature": sig,
		})
		if err := conn.Write(ctx, websocket.MessageText, offerBytes); err != nil {
			return
		}
		_, rawAns, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var ans struct {
			SDP string `json:"sdp"`
		}
		if json.Unmarshal(rawAns, &ans) != nil || ans.SDP == "" {
			return
		}
		if err := hubTr.AcceptAnswer(reg.Peer, ans.SDP); err != nil {
			return
		}
		okBytes, _ := json.Marshal(map[string]any{"type": "ok", "peer": hubID.Address()})
		_ = conn.Write(ctx, websocket.MessageText, okBytes)
	}))
	stop := func() {
		hubNode.StopMeshSupervisor()
		hubTr.Close()
		srv.Close()
	}
	t.Cleanup(stop)
	return srv, stop
}
