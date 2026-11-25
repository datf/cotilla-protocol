# Testing Cotilla

Cotilla uses a multi-layered testing strategy combining Go unit/protocol tests, race detection, Go 1.27 `goroutineleak` and capacity/topology performance suites (`make perf`), Svelte frontend/live-server tests, and a Podman containerized multi-client E2E test bench (`make testbench`).

---

## 1. Quick Start Commands

```bash
# 1. Fast Go unit & protocol tests (build bootstrap/ first so cmd/server bootstrap tests pass)
make bootstrap && go test -short -count=1 ./...

# 2. Race detector across protocol, signaling server, seeder, and node daemon
go test -race -short -count=1 ./internal/perfcheck ./pkg/cotilla ./cmd/server ./cmd/seeder ./cmd/node

# 3. Full performance, capacity, hop-limit, HyParView island-prevention & Go 1.27 goroutineleak suite
make perf

# 4. WASM build & forbidden-dependency verification (must print CLEAN)
make wasm && (GOOS=js GOARCH=wasm go list -deps ./wasm | grep -E "pion|websocket|net/http|crypto/tls" || echo "CLEAN: 0 forbidden WASM deps")

# 5. Svelte 5 typecheck, store/platform unit tests, and live signaling server test
make server && pnpm --prefix svelte check && pnpm --prefix svelte test

# 6. Full containerized Podman E2E test bench (native + Svelte bootstrap/seeder + browser interop)
make testbench
```

---

## 2. Performance, Capacity, Topology & Go 1.27 Leak Suite (`make perf`)

Cotilla targets **Go 1.27+** to use the GA `goroutineleak` runtime profile (`pprof.Lookup("goroutineleak")`) via [`internal/perfcheck/perfcheck.go`](internal/perfcheck/perfcheck.go).

Run the full suite:

```bash
make perf
```

Environment overrides let you scale sweeps up or down:
- `COTILLA_PERF_MSGS`: Override MLS high-volume message count (default: `2000` short / `5000` full).
- `COTILLA_PERF_NODES`: Override mesh capacity node ladder.
- `COTILLA_PERF_CLIENTS`: Override concurrent real WebRTC signaling client count (default: `10/20` short / `25/50` full).

### Perf & Leak Suites Covered

| Test | Package | What It Verifies |
| :--- | :--- | :--- |
| `TestPerf_MLSPrivateGroup_ThousandsOfMessages` | `pkg/cotilla` | Exchanges 5,000 encrypted MLS messages across 5 peers with `RingBufferCapacity=200`, verifying throughput (~3,000 msg/s), bounded `SyncRequest.KnownIDs` (~14 KB), bounded heap, and 0 `goroutineleak`s. |
| `TestPerf_HyParView_NoIslandsAndSignalingReconnect` | `pkg/cotilla` | Simulates a 160-node overlay under heavy churn and random-walk `PortHyParViewShuffle`, verifying `components=1` (zero islands) via BFS (`perfcheck.AnalyzeGraph`) and signaling reconnection when active peers hit 0. |
| `TestPerf_MaxHopsAndScaleCapacity` | `pkg/cotilla` | Verifies exact hop bounds (`PrivateGroupTTL=3`, `PublicGroupTTL=6`, `MaxGossipTTL=20` across an 11-hop chain) and measures per-node heap (~12.6 KB/node), delivery rate (100%), and p95 latency across 50, 150, and 300 nodes. |
| `TestPerf_SignalingServer_MaxClientsChurnAndLeaks` | `cmd/server` | Connects 25 and 50 concurrent real Pion WebRTC clients via `/ws` + DataChannel churn + aborted `/ws` handshakes, asserting heap/client (~430 KB/client), full Pion goroutine settlement, and 0 `goroutineleak`s. |
| `TestPerf_SignalingServer_ReconnectOnZeroPeers` | `cmd/server` | Verifies a client whose peers all disconnect triggers `OnAnchorDeficit` and reconnects cleanly to the signaling gateway. |
| `TestPerf_Seeder_ConcurrentWavesAndLeaks` | `cmd/seeder` | Runs 3 waves x 4 concurrent WebRTC peers downloading a 320 KB signed app bundle (~8.8 MB/s) and asserts 0 `goroutineleak`s. |
| `TestPerf_NodeDaemon_PeerExhaustionReconnectAndLeaks` | `cmd/node` | Runs native `cmd/node` daemons against a real signaling server, severs peers to zero, and verifies automatic reconnect and 0 `goroutineleak`s. |

### Live Runtime Profiling (`-pprof`)
`cmd/server`, `cmd/seeder`, and `cmd/node` accept an opt-in `-pprof <addr>` flag (disabled by default):

```bash
./bin/cotilla-server -addr :8080 -web cotilla-bootstrap/dist -pprof 127.0.0.1:6060
curl http://127.0.0.1:6060/debug/pprof/goroutineleak?debug=2
go tool pprof http://127.0.0.1:6060/debug/pprof/heap
```

---

## 3. Unit, Cryptography & Transport Suites (`pkg/`, `cmd/`)

Run with `go test -short -count=1 ./...` or with `-race`:

- **Core Protocol & Routing (`pkg/cotilla/cotilla_test.go`, `packet_test.go`, `hyparview_test.go`):** Single-node isolation, 3–5 peer messaging, routed `Packet` signing/encryption, `ExpandingBroadcaster`, HyParView active/passive view management, NAT relaying, on-demand chunked transfers, sliding-window flow control (`chunkPipelineWindow = 16`), and multi-peer swarm seeding.
- **Cryptographic Hardening (`pkg/cotilla/crypto_hardening_test.go`, `invite_test.go`):** Signed `PeerInfo`, context-bound AEAD AAD, constant-time chunk verification, Noise_IK forward-secret 1:1 DMs (`cotilla-invite-v2`), 5-minute `ReplayWindow`, and length-prefixed `EncodeCanonical`.
- **MLS TreeKEM & Scaling (`pkg/cotilla/treekem_test.go`, `phase3_scaling_test.go`):** LBBT structure, Merkle `TreeHash`, Ed25519 KeyPackages, single-shot HPKE roundtrips, PFS/PCS strict epoch isolation, 20+ peer scaling, expanding-ring sync ($1 \to 2 \to 4 \to 8$), 15-minute `MessageTTL` catch-up, signed `ChannelInvite` lineage, and eviction lockout.
- **Secondary WebRTC SFrame Calls (`pkg/cotilla/calls_test.go`, `pkg/cotilla/sframe_test.go`, `pkg/cotillartc/call_media_test.go`):** RFC 9605 SFrame `AES_128_GCM_SHA256_128` keying via `MLS-Exporter`, multi-peer call isolation vs. 1:1 DMs, eviction revocation, and native Pion loopback media tests.
- **Signaling, Bootstrap & Seeder (`cmd/server/*_test.go`, `cmd/seeder/*_test.go`, `cmd/node/*_test.go`):** Strict 1:1 `/ws` handshake, anchor pool retention/promotion, strictly 2-file `bootstrap/` verification, HTTP gzip `/cotilla.wasm`, and end-to-end app bundle seeding.

---

## 4. Svelte 5 Frontend & Live Server Tests (`svelte/`)

```bash
make server
pnpm --prefix svelte check
pnpm --prefix svelte test
```

Runs:
1. `test_call_views.mjs`: Stage/carousel layout, FIFO screen share priority, active speaker ordering, and pinning.
2. `test_format_and_platform.mjs`: Formatting, attachment normalization, invite parsing, notifications, UI store, RMS audio meters, gain mixer, and audio processing prefs.
3. `test_store.mjs`: 3+ peer `CotillaStore` + real `CotillaClient` tests (hash auto-join, signed invites, group chat, 1:1 DM isolation, secondary WebRTC calls, eviction).
4. `test_live_server.mjs`: Spawns `bin/cotilla-server -web build`, verifies `/` and `/cotilla.wasm`, and connects 3 peers over `/ws`.

---

## 5. Containerized Multi-Client Test Bench (`testbench/`)

The Podman test bench builds static Go binaries, compiles the single-file Svelte bundle and Gzip-WASM bootstrap, and runs isolated containers (`cotilla-signaling`, `cotilla-seeder`, `cotilla-alice`, `cotilla-bob`, `cotilla-charlie`, and headless Chromium `cotilla-browser`) on a private bridge network.

```bash
# Full build, up, native runner + Svelte E2E + browser interop E2E, and teardown
make testbench

# Granular targets
make testbench-up                 # Build & start containers
make testbench-test               # Run 8 native Go containerized scenarios
make -C testbench test-svelte     # Run 5 Bootstrap -> Seeder -> Svelte Chromium E2E scenarios
make -C testbench test-browser    # Run test-svelte + 19 classic Browser & Interop scenarios
make testbench-down               # Stop containers and remove network
```

### Containerized Suites Verified
1. **Native Go Runner (`testbench/runner`, 8 scenarios):** 3-peer direct mesh formation, E2EE chat, on-demand 150 KB chunked transfer, transient disconnect + ring-buffer catch-up, peer-assisted NAT relay, 1:1 DM Noise_IK invite & formation, DM vs. group chat + SFrame secondary A/V isolation, and relayed DM chat.
2. **Bootstrap → Seeder → Svelte E2E (`testbench/browser/test_svelte.js`, 5 scenarios):**
   - 3-peer single-file bootstrap → P2P seeder download → Svelte launch & `#room`/`#key` hash preservation (0 extra HTTP requests, 0 JS/WASM errors).
   - 3-peer Svelte chat, on-demand attachment transfer, 1:1 DM isolation, MLS key rotation & eviction lockout.
   - 3-peer Svelte SFrame Audio + Video call (0 `pipeErrors`, 0 rejected frames).
   - 6-client mixed mesh (3 Svelte Chromium + 3 Native Go containers) bidirectional chat & SFrame A/V call.
   - Insecure non-localhost HTTP origin (`isSecureContext === false`): clean bootstrap, 3-peer text chat, and graceful HTTPS/localhost error toasts for call/mic actions.
3. **Classic Browser & Interop E2E (`testbench/browser/test.js`, 19 scenarios):** Covers burner room creation, mic/VAD, link joining, direct DataChannels, E2EE chat, voice/video streaming, 100 MB large file streaming, 4-client swarm seeding, 6-client mixed mesh (3 web + 3 native), channel invite lineage, spectator lockout, eviction & rogue partition rejection, and multi-room anchor churn survival.
