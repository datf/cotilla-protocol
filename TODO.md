# Cotilla Roadmap & Protocol TODOs

This document tracks unresolved architectural design work, MLS (RFC 9420) protocol gaps, and real-time media encryption work intentionally deferred from the current alpha implementation.

---

## 1. Concurrent MLS Commit Ordering / Consensus Algorithm

### Problem Statement
In a decentralized P2P mesh without a central delivery server, two or more active group members can concurrently propose commits advancing the same MLS epoch $E \to E+1$:
- Example: Peer A emits `CreateAddCommit(Dave)` at epoch $E \to E+1$, while Peer B concurrently emits `CreateRemoveCommit(Charlie)` or `CreateUpdateCommit()` at epoch $E \to E+1$.
- Today, whichever commit arrives first at a peer mutates `MLSGroup.Epoch` to $E+1$, causing the concurrent sibling commit (`Epoch == E+1`) to be rejected (`ErrTreeKEMEpochMismatch`), partitioning the group's ratchet tree and epoch application keys (split-brain).
- Naive wall-clock contention windows (`CommitContentionWindow`), subjective "online peer" percentages, or `<= 50%` thresholds also break in an asynchronous overlay mesh: clocks drift, `Commit.Timestamp` can be backdated up to `ReplayWindow` (5m) to hijack ordering, partial peer views (`MinActivePeers = 6`) disagree on who is online, and `<= 50%` quorums do not guarantee intersection.

### Planned Consensus Design (Witness Co-Signing + Optimistic Rollback)

- **Deterministic Witness-Committee Co-Signing (Quorum Certificates):**
  - **Committee Selection:** For `(epoch, view)`, deterministically rank active (non-blank) `RatchetTree` leaves (excluding any eviction target) by `SHA256(ConfirmedTranscriptHash || view || leafIndex)` and select up to `WitnessCommitteeMaxSize` (default `7`) witnesses.
  - **Uniform Strict-Majority Quorum (`> 50%`):** Use a uniform simple-majority threshold across `Add`, `Update`, and `Remove` commits (relying on optimistic apply + rollback rather than a `Remove` supermajority):
    - $M \le 2$ active leaves: quorum = `1` (1-peer genesis / 2-peer room).
    - $M = 3$ active leaves: quorum = `2` (proposer + 1 other, keeping eviction of a 3rd peer possible).
    - $M \ge 4$ active leaves: quorum = `len(committee)/2 + 1`.
  - **Single-Vote Endorsement Rule & Total Order:** Witnesses sign at most one `CommitEndorsement` (`cotilla-commit-endorse-v1` over `(RoomID, EpochID, View, CommitDigest, Endorser)`) per `(epoch, view)`. If multiple candidates contend before signing, witnesses prefer:
    1. Operation class: `Remove > Update > Add` (evictions always supersede admissions).
    2. Deterministic tie-breaker: lexicographically lowest `CommitDigest` (`SHA256(CommitterSignPub || CanonicalBytesWithConfirmation())`). *Self-reported `Commit.Timestamp` is excluded from ordering to prevent backdating attacks and clock-skew boundary splits.*
  - **Gossiped Quorum Certificate:** Once `>= quorum` endorsements accumulate (`FrameCommitPropose` / `FrameCommitEndorse`), attach `Endorsements []CommitEndorsement` to `EpochCommit` (`View uint64`) and gossip the certified commit (`SyncResponse` also serves QC-certified `commitHistory`).

- **Optimistic Apply + Snapshot Rollback (0-RTT Fast Path):**
  - **Speculative Fast Path:** Nodes optimistically apply the first valid candidate `MLSCommit` immediately against epoch $E$ (keeping 0-RTT chat encryption for uncontended transitions) while collecting witness endorsements asynchronously in the background.
  - **Defer Irreversible Side Effects Until QC Finality:** Transport disconnection (`Transport.ClosePeer`), secondary WebRTC call revocation (`notifyCallEpochTransition` peer close), and destructive UI/session teardown (`OnMemberEvicted` / `wasm.leaveRoom()` / peer map deletion) MUST wait until the `Remove` commit achieves QC finality (nodes may immediately stop encrypting *new* outbound messages to the target locally while pending).
  - **Checkpoint Rollback & Re-Proposal:** Retain deep `MLSGroup.Clone()` + `ChannelState` snapshots over `MaxForkReorgEpochs` (default `2`). If a competing fork achieves QC finality—or higher `(hasQC, EndorsementCount, OpClass, CommitDigest)` priority—within the reorg horizon, nodes roll back to the epoch $E$ checkpoint, apply and forward the winning branch, and re-queue displaced `Add` proposals (issuing fresh `MLSWelcome` messages) for epoch $E+2$.
  - **SFrame `KID` Key-Replacement Fix:** Update `SFrameKeyring.InstallBundle` (`pkg/cotilla/sframe.go`) and `handleInstallBundle` (`web/sframe-worker.js`) so cached `tx` / `rxKeys` entries keyed by `KID = (epoch << 16) | leafIndex` compare actual key/salt material and replace stale branch keys + reset replay windows on rollback/replacement.

- **View-Rotation Dead-Tab Liveness:**
  - If a selected witness committee stalls due to silent disconnects (peers closing tabs without `FrameLeave`), nodes deterministically advance to `(epoch, view + 1)` after `CommitViewTimeout` (default `1500ms`), rotating to a fresh witness subset while preserving strict quorum intersection as long as a majority of `RatchetTree` leaves remain live.

- **Byzantine Safety Guards & Equivocation Auto-Eviction:**
  - **Equivocation Detection:** If any peer's signature appears on two distinct `CommitDigest`s for the same `(EpochID, View)`, nodes package the pair as an `EquivocationProof` and automatically propose an eviction commit against the double-signer.
  - **Chain Weight & Bounded Reorg (`MaxForkReorgEpochs`):** Fork choice prioritizes deeper QC-finalized chain depth before per-epoch tie-breakers so partitioned subgraphs converge cleanly without deadlocking against `MaxForkReorgEpochs`.

- **Implementation Scope & Verification Targets:**
  - Wire & Crypto (`pkg/cotilla/envelope.go`, `crypto.go`, `config.go`): `FrameCommitPropose`, `FrameCommitEndorse`, `CommitEndorsement`, `EquivocationProof`, `CanonicalCommitEndorsement`, and config defaults.
  - TreeKEM & Node (`pkg/cotilla/treekem.go`, `node.go`): `MLSGroup.Clone()`, `WitnessCommittee()`, `WitnessQuorum()`, optimistic apply + rollback checkpoints, endorsement aggregation, view rotation, and `SyncReq`/`SyncRes` QC validation.
  - Media & UI (`pkg/cotilla/sframe.go`, `calls.go`, `web/sframe-worker.js`, `wasm/main.go`, `web/cotilla.js`, `web/app.js`): SFrame key-mismatch replacement, deferred `ClosePeer`/`OnMemberEvicted`, and pending/finalized/rollback UI hooks.
  - Multi-Peer Verification: 3+ and 5+ peer tests covering concurrent `Add` vs. `Remove`, `Remove` vs. `Remove` rollback, small-room thresholds ($M = 2, 3$), equivocation eviction, view rotation under silent witness loss, and full mixed-mesh `make testbench`.

---

## 2. Missing RFC 9420 (MLS 1.0) Specifications

Currently, Cotilla implements a simplified TreeKEM core (`RatchetTree`, `MLSCommit`, `MLSWelcome`). The following RFC 9420 mechanisms should be added for full protocol security and scalability:

1. **Per-Sender `SecretTree` Symmetric Ratchets (RFC 9420 §9):**
   - Today, all members within an epoch encrypt `Envelope` and `Attachment` payloads directly under a shared epoch `ApplicationSecret` with random XChaCha20-Poly1305 nonces.
   - Implement the RFC 9420 `SecretTree` derived from `encryption_secret` with per-leaf symmetric `handshake_ratchet` and `application_ratchet` chains (`sender_data_secret` + per-message generation counters) so compromise of a peer's state at generation $g_2$ does not leak earlier messages from generation $g_1 < g_2$ within the same epoch.
   - Enforce bounded out-of-order generation window storage and strict nonce/generation single-use rejection.

2. **Decoupled `Proposal` & `Commit` Framing (RFC 9420 §12.1–12.4):**
   - Separate standalone signed `Proposal` messages (`Add`, `Remove`, `Update`, `PreSharedKey`) from `Commit` frames so multiple pending proposals can be batched into a single $O(\log N)$ TreeKEM path commit rather than executing one commit per member join/departure.

3. **Full RFC 9420 Key Schedule & Signed `GroupInfo` in `Welcome` (RFC 9420 §8, §12.4.3.1):**
   - Replace the custom `(EpochSecret, InitSecret, ApplicationSecret)` tuple inside `MLSWelcome.EncryptedGroupSecret` with standard:
     - `EncryptedGroupSecrets` (per-newcomer `KeyPackageRef` + HPKE-encrypted `{joiner_secret, path_secret}`), and
     - HPKE-encrypted signed `GroupInfo` containing `GroupContext`, extensions (ratchet tree / member roster), `confirmation_tag`, `signer` leaf index, and Ed25519 signature.
   - Have joiners derive `member_secret -> welcome_secret -> epoch_secret -> confirmation_key` independently from `joiner_secret` and verify `confirmation_tag` against `GroupContext` and `confirmed_transcript_hash`.
   - Use RFC 9420 `ExpandWithLabel` framing (`uint16 length || "MLS 1.0 " + label || context`) and explicitly track `exporter_secret`, `epoch_authenticator`, `membership_key`, and `resumption_psk`.

4. **`KeyPackage` Lifetimes, Capabilities, Extension Pinning, & Single-Use Enforcement (RFC 9420 §10, §16.8):**
   - Add `Capabilities` (supported cipher suites, protocol versions, extensions), `Lifetime` (`not_before`, `not_after`), and `KeyPackageRef` hashing.
   - Track consumed `KeyPackageRef`s locally and reject replayed `KeyPackage` init keys across epochs or multiple welcomes to prevent cross-session key reuse.

5. **`UpdatePath` Diffs & Parent Hash Validation (RFC 9420 §7.5, §7.9):**
   - Replace full serialized `TreeNodes` snapshots on `MLSCommit` with compact `UpdatePath` (`leaf_node` + `UpdatePathNode[]` with `EncryptedPathSecret` per co-path resolution) so commits scale as $O(\log N)$ instead of $O(N)$.
   - Compute and verify RFC 9420 `parent_hash` links down internal tree paths to guarantee unmerged-leaf consistency and prevent tree-tampering by malicious committers.

6. **External Commits / External Joins & PSK Resumption (RFC 9420 §12.4.3.2):**
   - Support authorized external commits (`external_pub` in `GroupInfo`) paired with signed `ChannelInvite` provenance so authorized newcomers can join cleanly if existing committers are temporarily offline or overloaded.

---

## 3. End-to-End Encrypted Real-Time Audio & Video

### Implemented Foundation (ADR 0015)
- Legacy unencrypted DataChannel media (`FrameAudio`, `FrameVideo`, PCM `createScriptProcessor`, JPEG `canvas.toBlob`) has been removed in favor of dedicated direct secondary WebRTC `RTCPeerConnection`s paired with RFC 9605 SFrame (`AES_128_GCM_SHA256_128`).
- Group call keys are derived via RFC 9420 `MLS-Exporter("cotilla sframe v1", ...)` (`kid = (epoch << 16) | leafIndex`), enforced inside `web/sframe-worker.js` (`RTCRtpScriptTransform`) and `pkg/cotillartc.CallMediaTransport`, with Noise_IK pairwise call signaling (`FrameCallSignal`), Ed25519-signed scope presence (`FrameCallControl`), and immediate secondary connection teardown + SFrame revocation on eviction.

### Remaining Media Hardening & Deferred Fallbacks
- **Audio-Only DataChannel Relay Fallback (When Direct Secondary ICE Fails):**
  - Direct secondary WebRTC A/V communications are supported today. When future NAT/ICE hardening introduces media relaying across intermediate root/anchor DataChannels after `iceConnectionState === "failed"`, fallback MUST be **audio-only** (no low-bitrate video fallback).
  - Browser fallback path: capture Opus encoded audio via **WebCodecs** (`AudioEncoder`/`AudioDecoder` + `MediaStreamTrackProcessor`) -> SFrame encrypt with existing `web/sframe-worker.js` keys -> relay over DataChannel (`FrameCallMedia`), keeping relay anchors cryptographically blind.
- **Large Call Scaling (>4 Video Peers) & Simulcast:**
  - Add Opus FEC/DTX tuning, adaptive VP8/H264/AV1 simulcast layers, and SFrame-compatible selective relay forwarding for large multi-party video calls.

---

## 4. Protobuf Wire Encoding for Routed Mesh Packets

- **Switch Outer `Packet` & `SealedData` from JSON to Protocol Buffers (Protobuf):**
  - Currently, the Meshtastic-inspired routed `Packet` (`pkg/cotilla/packet.go`) and inner encrypted `SealedData` payloads are serialized with `encoding/json` for readability and rapid iteration while the protocol stabilizes.
  - Once the base mesh + HyParView + MLS protocol is fully completed, define a `.proto` schema (`proto/cotilla/v1/packet.proto`) and migrate `MarshalPacket` / `UnmarshalPacket` and inner `SealedData` payloads to binary Protobuf encoding (`google.golang.org/protobuf` or compact `vtprotobuf`) to eliminate base64 expansion of binary fields (`Payload`, `Signature`, chunk bytes, HPKE ciphertexts) and reduce wire overhead and WASM CPU cost.
