// Command node runs a headless Cotilla node daemon.
//
// In accordance with ADR-0014:
//   - All nodes operate symmetrically in the P2P overlay mesh.
//   - Nodes bootstrap through the signaling server, acquire anchor links, and join channels
//     via epidemic gossip.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
	rtc "github.com/datf/cotilla-protocol/pkg/cotillartc"
)

type NodeDaemon struct {
	id        *cot.Identity
	signaling string
	node      *cot.Node
	transport *rtc.PionTransport
	media     *rtc.CallMediaTransport
	solicitCh chan struct{}
}

func newNodeDaemon(id *cot.Identity, signalingURL string, stuns []string, roomID string, roomKey cot.RoomKey, hooks cot.Hooks) *NodeDaemon {
	cfg := cot.DefaultConfig()

	var node *cot.Node
	solicitCh := make(chan struct{}, 1)
	tr := rtc.New(id.Address(), stuns, func(from string, data []byte) {
		if node != nil {
			node.HandleWire(from, data)
		}
	})
	media := rtc.NewCallMediaTransport(id.Address(), stuns, func(scopeID, target, kind, payload string) error {
		if node == nil {
			return nil
		}
		return node.SendCallSignal(scopeID, target, kind, payload)
	})
	tr.OnOpen(func(addr string) {
		if node != nil {
			node.AddPeer(addr)
			_ = node.RequestCatchUp()
			go node.BroadcastPeerInfo()
		}
	})
	tr.OnClose(func(addr string) {
		if node != nil {
			node.RemovePeer(addr)
		}
	})

	if hooks.OnAnchorIntro == nil {
		hooks.OnAnchorIntro = func(anchors []string, fallback bool) {
			log.Printf("[%s] received anchor intro: %d anchors, fallback=%v", id.Address()[:8], len(anchors), fallback)
		}
	}
	if hooks.OnAnchorDeficit == nil {
		hooks.OnAnchorDeficit = func(currentAnchors, activePeers int) {
			log.Printf("[%s] anchor deficit detected: %d anchors, %d active peers", id.Address()[:8], currentAnchors, activePeers)
			select {
			case solicitCh <- struct{}{}:
			default:
			}
		}
	}
	if hooks.Log == nil {
		hooks.Log = func(msg string) {
			log.Printf("[%s] %s", id.Address()[:8], msg)
		}
	}

	d := &NodeDaemon{
		id:        id,
		signaling: signalingURL,
		transport: tr,
		media:     media,
		solicitCh: solicitCh,
	}
	if hooks.OnAnchorSolicit == nil {
		hooks.OnAnchorSolicit = func(needed int) {
			select {
			case d.solicitCh <- struct{}{}:
			default:
			}
		}
	}

	hooks = media.AttachNode(nil, hooks)
	node = cot.NewNode(id, roomID, roomKey, cfg, tr, hooks)
	d.node = node
	return d
}

func main() {
	signalingURL := flag.String("signaling", "ws://localhost:8080/ws", "signaling WebSocket URL")
	port := flag.String("port", "8081", "HTTP health/status listen port")
	stunServer := flag.String("stun", "stun:stun.l.google.com:19302", "STUN server URL")
	seed := flag.String("seed", "", "identity seed (optional hex)")
	pprofAddr := flag.String("pprof", "", "optional pprof HTTP listen address (e.g. 127.0.0.1:6062)")
	flag.Parse()

	if *pprofAddr != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			log.Printf("Cotilla node pprof listening on %s", *pprofAddr)
			_ = http.ListenAndServe(*pprofAddr, mux)
		}()
	}

	var id *cot.Identity
	var err error
	if *seed != "" {
		seedBytes, errHex := hex.DecodeString(*seed)
		if errHex != nil {
			seedBytes = []byte(*seed)
		}
		id, err = cot.NewIdentityFromSeed(seedBytes)
	} else {
		id, err = cot.NewIdentity()
	}
	if err != nil {
		log.Fatalf("failed to initialize identity: %v", err)
	}

	stuns := []string{}
	if *stunServer != "" {
		stuns = []string{*stunServer}
	}

	dummyKey, _ := cot.GenerateRoomKey()
	daemon := newNodeDaemon(id, *signalingURL, stuns, "network-mesh", dummyKey, cot.Hooks{})
	node := daemon.node
	tr := daemon.transport

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to signaling
	go daemon.bootstrapLoop(ctx)

	// Start mesh supervisor
	node.StartMeshSupervisor(ctx, 3*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"address":    id.Address(),
			"peers":      tr.Peers(),
			"anchors":    node.AnchorPeers(),
			"fallback":   node.IsFallbackMode(),
			"call_stats": daemon.media.Stats(),
		})
	})

	server := &http.Server{
		Addr:    ":" + *port,
		Handler: mux,
	}

	go func() {
		log.Printf("Cotilla daemon [%s] listening on :%s", id.Address()[:8], *port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	log.Println("Shutting down node daemon...")
	node.StopMeshSupervisor()
	daemon.media.Close()
	tr.Close()
	_ = server.Shutdown(context.Background())
}

func (d *NodeDaemon) hasGatewayConn() bool {
	if d.node == nil || d.transport == nil {
		return false
	}
	for _, p := range d.transport.Peers() {
		if d.node.IsGatewayPeer(p) {
			return true
		}
	}
	return false
}

func (d *NodeDaemon) bootstrapLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if d.hasGatewayConn() {
			select {
			case <-ctx.Done():
				return
			case <-d.solicitCh:
				d.node.QueryPeers()
				continue
			case <-time.After(3 * time.Second):
				continue
			}
		}

		// Skip reconnecting to signaling while healthy P2P mesh links are active
		if len(d.transport.Peers()) > 0 {
			select {
			case <-ctx.Done():
				return
			case <-d.solicitCh:
			case <-time.After(3 * time.Second):
				continue
			}
		}

		serverAddr, err := rtc.DialSignalingWS(ctx, d.signaling, d.id, d.transport, d.node)
		if err != nil {
			log.Printf("[%s] signaling connection error (will retry): %v", d.id.Address()[:8], err)
		} else {
			log.Printf("[%s] connected to signaling gateway %s via WebRTC DataChannel", d.id.Address()[:8], serverAddr[:8])
			d.node.AddPeer(serverAddr)
			d.node.QueryPeers()
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
