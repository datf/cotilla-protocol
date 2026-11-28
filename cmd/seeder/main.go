package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/datf/cotilla-protocol/internal/buildinfo"
	"github.com/datf/cotilla-protocol/pkg/cotilla"
	"github.com/datf/cotilla-protocol/pkg/cotillartc"
)

type publisherKeyFile struct {
	PubKeyHex  string `json:"pub_hex"`
	PrivKeyHex string `json:"priv_hex"`
}

type SeederDaemon struct {
	signalingURL string
	id           *cotilla.Identity
	node         *cotilla.Node
	transport    *cotillartc.PionTransport
	bundlePath   string
	manifestPath string
	keyPath      string
	distRoomID   string
	distRoomKey  cotilla.RoomKey
	pinnedPub    string
	manifestMu   sync.RWMutex
	currentM     *cotilla.AppManifest
	bundleBytes  []byte
	solicitCh    chan struct{}
}

func main() {
	var (
		printVersion = flag.Bool("print-version", false, "Print seeder build version and exit")
		keygenMode   = flag.Bool("keygen", false, "Generate an Ed25519 publisher keypair and exit")
		keyOut       = flag.String("key-out", "publisher.json", "Output file for -keygen")

		signMode   = flag.Bool("sign", false, "Sign an application bundle and generate AppManifest JSON")
		bundleFlag = flag.String("bundle", "", "Path to the application bundle (e.g. dist/cotilla-chat.html)")
		keyFile    = flag.String("key-file", "publisher.json", "Path to publisher keypair JSON file")
		privHex    = flag.String("priv", "", "Raw hex private key for signing")
		manifestOut = flag.String("out", "", "Output path for signed manifest JSON (default: stdout)")
		appIDFlag  = flag.String("app-id", cotilla.DefaultAppID, "Application ID")
		channelFlag = flag.String("channel", cotilla.DefaultAppChannel, "Distribution channel (e.g. stable)")
		versionFlag = flag.String("version", "1.0.0", "Application version")
		seqFlag    = flag.Uint64("seq", 1, "Monotonic sequence number for rolling updates")
		ttlFlag    = flag.Duration("ttl", 24*time.Hour, "Manifest validity duration")

		// Daemon flags
		signalingFlag = flag.String("url", "ws://127.0.0.1:8080/ws", "WebSocket signaling server URL")
		manifestFlag  = flag.String("manifest", "", "Path to signed AppManifest JSON (optional if -key-file is provided)")
		distRoomFlag  = flag.String("dist-room", cotilla.DefaultAppDistRoomID, "Overlay distribution room ID")
		distKeyFlag   = flag.String("dist-key", "", "256-bit base64 room key for distribution channel (default: derived)")
		seedFlag      = flag.String("seed", "", "Deterministic hex seed for seeder node identity")
		healthFlag    = flag.String("health", "", "Optional HTTP health check address (e.g. :8081)")
		pprofFlag     = flag.String("pprof", "", "Optional pprof HTTP listen address (e.g. 127.0.0.1:6061)")
	)
	flag.Parse()

	if *printVersion {
		fmt.Printf("cotilla-seeder %s\n", buildinfo.String())
		return
	}

	if *pprofFlag != "" {
		go func() {
			mux := http.NewServeMux()
			mux.HandleFunc("/debug/pprof/", pprof.Index)
			mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
			mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
			mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
			mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
			log.Printf("[Seeder] pprof listening on %s", *pprofFlag)
			_ = http.ListenAndServe(*pprofFlag, mux)
		}()
	}

	// 1. Keygen Mode
	if *keygenMode {
		pub, priv, err := cotilla.GeneratePublisherKeypair()
		if err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		data, _ := json.MarshalIndent(publisherKeyFile{PubKeyHex: pub, PrivKeyHex: priv}, "", "  ")
		if *keyOut == "" || *keyOut == "-" {
			fmt.Println(string(data))
			return
		}
		if err := os.WriteFile(*keyOut, append(data, '\n'), 0600); err != nil {
			log.Fatalf("write key file %s: %v", *keyOut, err)
		}
		log.Printf("Generated publisher keypair saved to %s (pub: %s)", *keyOut, pub)
		return
	}

	// 2. Sign Mode
	if *signMode {
		if *bundleFlag == "" {
			log.Fatal("-bundle is required for -sign mode")
		}
		bundleData, err := os.ReadFile(*bundleFlag)
		if err != nil {
			log.Fatalf("read bundle file %s: %v", *bundleFlag, err)
		}
		actualPriv := *privHex
		if actualPriv == "" {
			keyData, err := os.ReadFile(*keyFile)
			if err != nil {
				log.Fatalf("read key file %s: %v", *keyFile, err)
			}
			var kf publisherKeyFile
			if err := json.Unmarshal(keyData, &kf); err != nil {
				log.Fatalf("parse key file %s: %v", *keyFile, err)
			}
			actualPriv = kf.PrivKeyHex
		}
		manifest, err := cotilla.SignAppBundle(actualPriv, *appIDFlag, *channelFlag, *versionFlag, *seqFlag, bundleData, "text/html; charset=utf-8", cotilla.FormatSingleHTMLV1, *ttlFlag)
		if err != nil {
			log.Fatalf("sign app bundle: %v", err)
		}
		outJSON, _ := json.MarshalIndent(manifest, "", "  ")
		if *manifestOut == "" || *manifestOut == "-" {
			fmt.Println(string(outJSON))
			return
		}
		if err := os.WriteFile(*manifestOut, append(outJSON, '\n'), 0644); err != nil {
			log.Fatalf("write manifest to %s: %v", *manifestOut, err)
		}
		log.Printf("Signed manifest saved to %s (app: %s, seq: %d, sha256: %s)", *manifestOut, manifest.AppID, manifest.Seq, manifest.SHA256[:16])
		return
	}

	// 3. Seeder Daemon Mode
	if *bundleFlag == "" {
		log.Fatal("seeder daemon requires -bundle <path> (or run with -keygen or -sign)")
	}

	distRoomKey := cotilla.AppDistRoomKeyFor(*distRoomFlag)
	if *distKeyFlag != "" {
		parsedKey, err := cotilla.ParseRoomKey(*distKeyFlag)
		if err != nil {
			log.Fatalf("invalid -dist-key: %v", err)
		}
		distRoomKey = parsedKey
	}

	d, err := NewSeederDaemon(SeederOptions{
		SignalingURL: *signalingFlag,
		Seed:         *seedFlag,
		BundlePath:   *bundleFlag,
		ManifestPath: *manifestFlag,
		KeyPath:      *keyFile,
		DistRoomID:   *distRoomFlag,
		DistRoomKey:  distRoomKey,
	})
	if err != nil {
		log.Fatalf("NewSeederDaemon failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d.Start(ctx)

	// Health check server if requested
	if *healthFlag != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			d.manifestMu.RLock()
			defer d.manifestMu.RUnlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":          "seeding",
				"address":         d.id.Address(),
				"app_id":          d.currentM.AppID,
				"version":         d.currentM.Version,
				"seq":             d.currentM.Seq,
				"file_id":         d.currentM.FileID,
				"sha256":          d.currentM.SHA256,
				"connected_peers": d.transport.Peers(),
			})
		})
		srv := &http.Server{Addr: *healthFlag, Handler: mux}
		go func() {
			log.Printf("[Seeder] Health server listening on %s", *healthFlag)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("health server: %v", err)
			}
		}()
		defer func() { _ = srv.Shutdown(context.Background()) }()
	}

	log.Printf("[Seeder %s] Seeding bundle %s (App: %s, Seq: %d, SHA: %s) on %s",
		d.id.Address()[:8], filepath.Base(d.bundlePath), d.currentM.AppID, d.currentM.Seq, d.currentM.SHA256[:16], d.distRoomID)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			log.Println("[Seeder] SIGHUP received: reloading bundle and manifest...")
			if err := d.loadBundleAndManifest(); err != nil {
				log.Printf("[Seeder] reload failed: %v", err)
				continue
			}
			d.manifestMu.RLock()
			_ = d.node.RegisterAppBundle(d.distRoomID, d.distRoomKey, d.currentM, d.bundleBytes, d.pinnedPub)
			d.manifestMu.RUnlock()
			log.Printf("[Seeder] reloaded bundle Seq %d", d.currentM.Seq)
			continue
		}
		break
	}

	log.Println("[Seeder] Shutting down seeder daemon...")
	d.Close()
}

type SeederOptions struct {
	SignalingURL string
	Seed         string
	BundlePath   string
	ManifestPath string
	KeyPath      string
	DistRoomID   string
	DistRoomKey  cotilla.RoomKey
}

func NewSeederDaemon(opts SeederOptions) (*SeederDaemon, error) {
	var seederID *cotilla.Identity
	var err error
	if opts.Seed != "" {
		seedBytes, err := hex.DecodeString(opts.Seed)
		if err != nil {
			return nil, fmt.Errorf("invalid hex seed: %w", err)
		}
		seederID, err = cotilla.NewIdentityFromSeed(seedBytes)
		if err != nil {
			return nil, fmt.Errorf("NewIdentityFromSeed: %w", err)
		}
	} else {
		seederID, err = cotilla.NewIdentity()
		if err != nil {
			return nil, fmt.Errorf("NewIdentity: %w", err)
		}
	}

	distRoomID := opts.DistRoomID
	if distRoomID == "" {
		distRoomID = cotilla.DefaultAppDistRoomID
	}
	distRoomKey := opts.DistRoomKey
	if distRoomKey == (cotilla.RoomKey{}) {
		distRoomKey = cotilla.AppDistRoomKeyFor(distRoomID)
	}

	d := &SeederDaemon{
		signalingURL: opts.SignalingURL,
		id:           seederID,
		bundlePath:   opts.BundlePath,
		manifestPath: opts.ManifestPath,
		keyPath:      opts.KeyPath,
		distRoomID:   distRoomID,
		distRoomKey:  distRoomKey,
		solicitCh:    make(chan struct{}, 1),
	}

	if err := d.loadBundleAndManifest(); err != nil {
		return nil, fmt.Errorf("initial bundle load: %w", err)
	}

	d.transport = cotillartc.New(seederID.Address(), nil, func(from string, data []byte) {
		if d.node != nil {
			d.node.HandleWire(from, data)
		}
	})

	cfg := cotilla.DefaultConfig()
	d.node = cotilla.NewNode(seederID, d.distRoomID, d.distRoomKey, cfg, d.transport, cotilla.Hooks{
		OnPeerJoined: func(addr string) {
			log.Printf("[Seeder %s] Peer connected: %s", seederID.Address()[:8], addr[:8])
		},
		OnPeerLeft: func(addr string) {
			log.Printf("[Seeder %s] Peer left: %s", seederID.Address()[:8], addr[:8])
		},
		OnAnchorSolicit: func(needed int) {
			select {
			case d.solicitCh <- struct{}{}:
			default:
			}
		},
		OnAnchorDeficit: func(currentAnchors, activePeers int) {
			select {
			case d.solicitCh <- struct{}{}:
			default:
			}
		},
		Log: func(msg string) {
			log.Printf("[Seeder Core] %s", msg)
		},
	})

	d.transport.OnOpen(func(peerAddr string) {
		d.node.AddPeer(peerAddr)
		_ = d.node.RequestCatchUp()
		go d.node.BroadcastPeerInfo()
	})
	d.transport.OnClose(func(peerAddr string) {
		d.node.RemovePeer(peerAddr)
	})

	d.manifestMu.RLock()
	err = d.node.RegisterAppBundle(d.distRoomID, d.distRoomKey, d.currentM, d.bundleBytes, d.pinnedPub)
	d.manifestMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("RegisterAppBundle: %w", err)
	}

	return d, nil
}

func (d *SeederDaemon) Start(ctx context.Context) {
	go d.bootstrapLoop(ctx)
	d.node.StartMeshSupervisor(ctx, 3*time.Second)
}

func (d *SeederDaemon) Close() {
	d.node.StopMeshSupervisor()
	d.transport.Close()
}

func (d *SeederDaemon) loadBundleAndManifest() error {
	bundleData, err := os.ReadFile(d.bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle %s: %w", d.bundlePath, err)
	}

	var manifest *cotilla.AppManifest
	if d.manifestPath != "" {
		mBytes, err := os.ReadFile(d.manifestPath)
		if err != nil {
			return fmt.Errorf("read manifest %s: %w", d.manifestPath, err)
		}
		var parsed cotilla.AppManifest
		if err := json.Unmarshal(mBytes, &parsed); err != nil {
			return fmt.Errorf("parse manifest %s: %w", d.manifestPath, err)
		}
		manifest = &parsed
	} else if d.keyPath != "" {
		keyBytes, err := os.ReadFile(d.keyPath)
		if err != nil {
			return fmt.Errorf("read key file %s: %w", d.keyPath, err)
		}
		var kf publisherKeyFile
		if err := json.Unmarshal(keyBytes, &kf); err != nil {
			return fmt.Errorf("parse key file %s: %w", d.keyPath, err)
		}
		m, err := cotilla.SignAppBundle(kf.PrivKeyHex, cotilla.DefaultAppID, cotilla.DefaultAppChannel, "1.0.0", 1, bundleData, "text/html; charset=utf-8", cotilla.FormatSingleHTMLV1, 24*time.Hour)
		if err != nil {
			return fmt.Errorf("sign bundle: %w", err)
		}
		manifest = m
	} else {
		return errors.New("either -manifest or -key-file is required to seed a bundle")
	}

	if err := cotilla.VerifyAppBundle(manifest, bundleData, manifest.PubKey, manifest.AppID, manifest.Channel, manifest.Seq, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("verify bundle against manifest: %w", err)
	}

	d.manifestMu.Lock()
	d.currentM = manifest
	d.bundleBytes = bundleData
	d.pinnedPub = manifest.PubKey
	d.manifestMu.Unlock()
	return nil
}

func (d *SeederDaemon) hasGatewayConn() bool {
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

func (d *SeederDaemon) bootstrapLoop(ctx context.Context) {
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

		if len(d.transport.Peers()) > 0 {
			select {
			case <-ctx.Done():
				return
			case <-d.solicitCh:
			case <-time.After(3 * time.Second):
				continue
			}
		}

		serverAddr, err := cotillartc.DialSignalingWS(ctx, d.signalingURL, d.id, d.transport, d.node)
		if err != nil {
			log.Printf("[Seeder] signaling connection error: %v (retrying...)", err)
		} else {
			log.Printf("[Seeder] connected to signaling gateway %s via WebRTC DataChannel", serverAddr[:8])
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
