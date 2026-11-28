# Cotilla — Ephemeral E2EE WebRTC Burner Rooms

Cotilla ("gossip" in Spanish) is a lightweight, zero-knowledge, end-to-end encrypted peer-to-peer protocol and application suite built on WebRTC DataChannels and media streams.

It is designed for **ephemeral burner rooms** and **P2P-seeded web apps**: temporary, highly private spaces for 2 to 300+ peers to chat, exchange files, share encrypted audio/video, and bootstrap signed single-file web apps over the mesh with zero server persistence.

---

## 1. Quick Start: Launching Server, Bootstrap, Seeder & Svelte App

### Prerequisites
- **Go 1.27+** (module pinned to `go 1.27.0` for GA `goroutineleak` runtime profiles)
- **Node.js & pnpm** (for `svelte/` and `cotilla-bootstrap/` git submodules)
- **Podman & podman-compose** (optional, for `make testbench`)

### Initial Setup (Git Submodules & JS Dependencies)

`svelte/` and `cotilla-bootstrap/` are git submodules. After cloning (or if you cloned without `--recurse-submodules`), initialize submodules and install JS dependencies once:

```bash
# Initialize submodules and install pnpm/npm dependencies in svelte/ and cotilla-bootstrap/
make init

# Or initialize git submodules only (without running npm/pnpm install)
make submodules
```

> [!NOTE]
> JS build targets (`make svelte-bundle`, `make bootstrap-singlefile`, `make bootstrap-svelte`, `make all`) also lazily initialize missing submodules and re-run `pnpm install --frozen-lockfile` / `npm ci` only when `node_modules` is missing or a lockfile changes. Pure Go targets (`make test`, `make server`, `make seeder`, `make bootstrap`) never invoke `npm`/`pnpm`.

### Option A: Seed the Single-File Svelte App via Bootstrap + Seeder (Recommended)

```bash
# 1. Build cotilla-server, cotilla-seeder, signed Svelte single-file bundle,
#    and single-file gzip-WASM bootstrap (cotilla-bootstrap/dist/index.html + dist/apps/)
make server bootstrap-svelte

# 2. Terminal 1 — Start the zero-knowledge signaling gateway serving the bootstrap page
./dist/bin/cotilla-server -addr :8080 -web cotilla-bootstrap/dist

# 3. Terminal 2 — Start the headless P2P app seeder
./dist/bin/cotilla-seeder \
  -url ws://127.0.0.1:8080/ws \
  -bundle dist/apps/cotilla-svelte.html \
  -manifest dist/apps/cotilla-svelte.manifest.json \
  -health :8081
```

Open `http://localhost:8080/` in your browser. The minimalistic single-file bootstrap decompresses `cotilla.wasm` with the browser's built-in `DecompressionStream('gzip')`, opens a 1:1 WebRTC DataChannel to the signaling gateway, discovers the app seeder over the Cotilla mesh, verifies the Ed25519 manifest signature (`name`, `version`, `validSignatures`), downloads the Svelte bundle P2P, and launches the app while preserving `#room=...&key=...` URL hashes.

### Option B: Run the Svelte App Standalone (No Seeder Required)

Apps remain fully functional without a seeder by design:

```bash
make server svelte-build
./dist/bin/cotilla-server -addr :8080 -web svelte/build
```

### Option C: Classic Static Web Client or 2-File Bootstrap

```bash
# Serve the classic web client staged into dist/web/ (serves /cotilla.wasm gzipped automatically)
make run

# Or build and serve the strictly 2-file dist/bootstrap/ directory (index.html + cotilla.wasm)
make server bootstrap
./dist/bin/cotilla-server -addr :8080 -web dist/bootstrap
./dist/bin/cotilla-seeder \
  -url ws://127.0.0.1:8080/ws \
  -bundle dist/apps/cotilla-chat.html \
  -manifest dist/apps/cotilla-chat.manifest.json
```

### Optional: Native Overlay Node, Build Artifacts & Live Go 1.27 `pprof` Diagnostics

All generated outputs live under `dist/` (`dist/bin/`, `dist/wasm/`, `dist/web/`, `dist/bootstrap/`, `dist/apps/`, `dist/clib/`, `dist/dev/`, `dist/release/`):

```bash
# Run a standalone native overlay node
make node && ./dist/bin/cotilla-node -signaling ws://127.0.0.1:8080/ws -port 8082

# Print embedded version metadata on any binary
./dist/bin/cotilla-server -version
./dist/bin/cotilla-seeder -print-version
./dist/bin/cotilla-node -version

# Build the publishable @datf/cotilla-wasm package (cotilla.wasm, wasm_exec.js, package.json)
make release-wasm VERSION=v0.1.0

# Cross-compile multi-arch release binaries (pure Go, CGO_ENABLED=0)
make release-bin VERSION=v0.1.0 TARGET_GOOS=linux TARGET_GOARCH=arm64

# Enable opt-in pprof (/debug/pprof/goroutineleak and /debug/pprof/heap) on any binary:
./dist/bin/cotilla-server -addr :8080 -web cotilla-bootstrap/dist -pprof 127.0.0.1:6060
./dist/bin/cotilla-seeder -url ws://127.0.0.1:8080/ws -bundle dist/apps/cotilla-svelte.html -manifest dist/apps/cotilla-svelte.manifest.json -pprof 127.0.0.1:6061
```

---

## 2. Core Protocol Architecture (Meshtastic-Inspired Gossip + HyParView + MLS)

1. **Strict 1:1 `/ws` Gateway & Normal Overlay Peer:**
   - The signaling server's `/ws` endpoint (`coder/websocket`) is used **solely** to establish a single 1:1 WebRTC DataChannel between an arriving node and the gateway (`register → offer → answer → ok`), then `/ws` closes.
   - Once the DataChannel is open, `cmd/server` participates as a normal overlay peer, retaining an anchor pool (`-min-anchors`, `-intro-anchors`) and forwarding overlay broadcasts with zero knowledge of rooms, keys, or payloads.
2. **Unified Routed `Packet` & `Port` Dispatch (`pkg/cotilla/packet.go`):**
   - All overlay, channel, transfer, app-seeding, DM, and call-signaling traffic flows as signed/encrypted routed `Packet` frames with explicit `Port` numbers:
     - **Overlay & HyParView:** `PortPeerRequest`, `PortPeerResponse`, `PortWebRTCSignal`, `PortRootIntro`, `PortAnchorSolicit`, `PortHyParViewShuffle`, `PortGroupDiscover`, `PortLeave`.
     - **Channel & MLS:** `PortChat`, `PortGroupPeerInfo`, `PortEpochCommit`, `PortSyncReq`, `PortSyncRes`.
     - **Attachments & App Seeding:** `PortAttachMeta`, `PortChunkReq`, `PortChunkRes`, `PortAppInviteReq`, `PortAppManifestReq`, `PortAppManifestRes`.
     - **1:1 DMs & Secondary A/V Calls:** `PortDirectInvite`, `PortDirectInviteRes`, `PortDM`, `PortCallCtrl`, `PortCallSig`.
   - Outer packets currently use JSON for readability; binary Protobuf migration is tracked in [`TODO.md`](TODO.md).
3. **Expanding-Ring Broadcasts & HyParView Self-Repair (`broadcast.go`, `hyparview.go`):**
   - Broadcasts (`ExpandingBroadcaster`) start with a short TTL and small fanout, doubling TTL and fanout every `2 * TTL` if unanswered.
   - **Public Groups** (including PSK-encrypted app seeder groups addressed by `ChannelHash`) target **2 connected peers** with a longer TTL (`PublicGroupTTL = 6`).
   - **Private MLS Groups** target **6 connected peers** with a shorter TTL (`PrivateGroupTTL = 3`) and periodic HyParView random-walk shuffling (`RemainingHops`) to prevent network islands.
   - If a node loses all active peers (`len(live) == 0`), `OnAnchorDeficit` automatically triggers signaling reconnection—even in `fallbackMode`.
4. **URL Hash Keying, RFC 9420 TreeKEM MLS & Signed Invites:**
   - Room IDs and 256-bit keys live exclusively in the URL hash fragment (`#room=<uuid>&key=<base64>`).
   - Private rooms use RFC 9420 TreeKEM (Left-Balanced Binary Trees + single-shot HPKE `DHKEM(X25519, HKDF-SHA256)` + `XChaCha20-Poly1305`) for continuous asymmetric ratcheting (PFS + PCS), `GroupContext` binding, signed `ChannelInvite` delegation chains with 15-minute `InviteTTL`, and cryptographic lockout on eviction (`EvictPeer`).
   - Retained epoch keys and commit history are bounded (`maxRetainedEpochs = 256`), and evicted ring-buffer pointers are zeroed for GC.
5. **Bounded Ring-Buffer Catch-Up (`sync.go`, `ringbuffer.go`):**
   - Each peer retains the last 200 messages (or 15 minutes `MessageTTL`) in an in-memory `RingBuffer`.
   - Reconnecting peers run an expanding-ring targeted sync ($1 \to 2 \to 4 \to 8 \dots$ peers every 1.5s) with `SyncRequest.KnownIDs` bounded to `max(RingBufferCapacity*2, 400)`, keeping sync payloads compact even after thousands of messages.
6. **On-Demand Attachments & Swarm Seeding (`transfer.go`):**
   - Senders announce only `PortAttachMeta`; chunks (64 KB) are downloaded strictly on demand using a sliding window (`chunkPipelineWindow = 16`, ~1 MB in flight) and zero-copy `Uint8Array` WASM transfers.
   - Every downloading peer immediately acts as a swarm seeder.
7. **MLS-Scoped Secondary WebRTC A/V & Inner SFrame (RFC 9605):**
   - Primary overlay `RTCPeerConnection`s are **DataChannel-only**.
   - Audio, camera, and screen calls use dedicated direct secondary `RTCPeerConnection`s scoped per `(scopeID, peerAddr)` and double-encrypted with **RFC 9605 SFrame (`AES_128_GCM_SHA256_128`)** keyed from RFC 9420 `MLS-Exporter("cotilla sframe v1", ...)` inside DTLS-SRTP (`web/sframe-worker.js` + `pkg/cotillartc.CallMediaTransport`).
8. **1:1 Direct Messages:**
   - Modeled as isolated 2-peer burner rooms established via Noise_IK forward-secret `PortDirectInvite` (`cotilla-invite-v2`), unaffected by group channel evictions.

---

## 3. Portability & Repository Layout

| Target | Host Environment | WebRTC Transport |
| :--- | :--- | :--- |
| **Native** | Go CLI, servers, daemons (`cmd/`) | `pion/webrtc/v4` (`pkg/cotillartc`) |
| **Browser (WASM)** | Browsers (`web/`, `svelte/`, `cotilla-bootstrap/`) | Native JS `RTCPeerConnection`; lightweight `cotilla.wasm` (zero Pion/HTTP/TLS deps, gzip-compressed) |
| **Foreign Native** | iOS, Android, C/C++ (`clib/`) | `-buildmode=c-shared` (`libcotilla.so`) |

- `pkg/cotilla/`: Core protocol library (crypto, routed `Packet`, `ExpandingBroadcaster`, HyParView overlay, MLS TreeKEM, SFrame keyring, ring buffer, attachments, app manifests).
- `pkg/cotillartc/`: Native Pion WebRTC overlay (`PionTransport`) and secondary SFrame media transport (`CallMediaTransport`).
- `wasm/`: Pure-protocol Go/WASM bridge (`GOOS=js GOARCH=wasm`).
- `cmd/server/`: Zero-knowledge 1:1 `/ws` signaling gateway, overlay anchor peer, and gzip-aware static file server.
- `cmd/seeder/`: Headless Ed25519 manifest signer (`-keygen`, `-sign`) and P2P app bundle seeder.
- `cmd/node/`: Standalone native Cotilla overlay daemon.
- `cmd/bootstrapgen/`: Generates the strictly 2-file `bootstrap/` (`index.html` + `cotilla.wasm`) and default signed chat bundle.
- `cotilla-bootstrap/`: Single-file Vite bootstrap (`dist/index.html`) with Gzip-inlined `cotilla.wasm` (`DecompressionStream('gzip')`) and offline SFrame worker.
- `svelte/`: Svelte 5 / Tailwind v4 web client (standalone SPA & single-file P2P bundle).
- `internal/perfcheck/`: Go 1.27 `goroutineleak` assertions, heap snapshots, and BFS graph topology analyzer.
- `testbench/`: Podman containerized multi-client native + Chromium E2E test bench.

---

## 4. Testing & Performance Verification

See [`TESTING.md`](TESTING.md) for the complete testing guide.

```bash
# Go unit & protocol tests (automatically builds bootstrap/ prerequisites)
make test
# Or fast short run:
make bootstrap && go test -short -count=1 ./...

# Race detector across core, server, seeder, and node
go test -race -short -count=1 ./internal/perfcheck ./pkg/cotilla ./cmd/server ./cmd/seeder ./cmd/node

# Full performance, capacity, hop-limit, HyParView island-prevention & Go 1.27 goroutineleak suite
make perf

# Svelte typecheck & unit/store/live-server tests
make server && pnpm --prefix svelte check && pnpm --prefix svelte test

# Full containerized multi-client Podman E2E test bench (native + Svelte seeder + browser interop)
make testbench
```
