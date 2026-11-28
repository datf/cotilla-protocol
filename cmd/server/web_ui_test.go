package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	cot "github.com/datf/cotilla-protocol/pkg/cotilla"
)

func TestWebAppJS_DOMSelectorsExist(t *testing.T) {
	htmlBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "index.html"))
	if err != nil {
		t.Fatalf("read web/index.html: %v", err)
	}
	appBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "app.js"))
	if err != nil {
		t.Fatalf("read web/app.js: %v", err)
	}

	idRe := regexp.MustCompile(`id="([^"]+)"`)
	htmlIDs := make(map[string]bool)
	for _, m := range idRe.FindAllSubmatch(htmlBytes, -1) {
		htmlIDs[string(m[1])] = true
	}

	dollarRe := regexp.MustCompile(`\$\("([^"]+)"\)`)
	for _, m := range dollarRe.FindAllSubmatch(appBytes, -1) {
		id := string(m[1])
		if !htmlIDs[id] {
			t.Errorf("web/app.js references missing DOM id %q not present in web/index.html", id)
		}
	}
}

func TestWebAppJS_CreateRoomAndChannelPeerIsolation(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node binary not available for browser UI harness")
	}

	htmlBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "index.html"))
	if err != nil {
		t.Fatalf("read web/index.html: %v", err)
	}
	appPath, err := filepath.Abs(filepath.Join("..", "..", "web", "app.js"))
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	cotillaJSPath, err := filepath.Abs(filepath.Join("..", "..", "web", "cotilla.js"))
	if err != nil {
		t.Fatalf("abs path cotilla.js: %v", err)
	}

	idRe := regexp.MustCompile(`id="([^"]+)"`)
	var ids []string
	seen := make(map[string]bool)
	for _, m := range idRe.FindAllSubmatch(htmlBytes, -1) {
		id := string(m[1])
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	idsJSON, _ := json.Marshal(ids)

	script := `
const fs = require("fs");
const vm = require("vm");
const { webcrypto } = require("crypto");

const cotillaCode = fs.readFileSync(process.env.COTILLA_LIB_JS, "utf8");
const appCode = fs.readFileSync(process.env.COTILLA_APP_JS, "utf8");
const knownIDs = JSON.parse(process.env.COTILLA_HTML_IDS);

function runScenario(hashValue) {
  const alerts = [];
  const errors = [];
  const elements = new Map();
  const makeClassList = () => {
    const classes = new Set();
    return {
      add: (...cs) => cs.forEach((c) => classes.add(c)),
      remove: (...cs) => cs.forEach((c) => classes.delete(c)),
      toggle: (c, force) => {
        if (force === undefined) {
          if (classes.has(c)) { classes.delete(c); return false; }
          classes.add(c); return true;
        }
        if (force) classes.add(c); else classes.delete(c);
        return !!force;
      },
      contains: (c) => classes.has(c),
    };
  };
  const makeEl = (tag) => {
    const attrs = {};
    const children = [];
    const el = {
      tagName: (tag || "div").toUpperCase(),
      style: {},
      dataset: {},
      className: "",
      classList: makeClassList(),
      textContent: "",
      value: "",
      children,
      disabled: false,
      scrollHeight: 0,
      scrollTop: 0,
      setAttribute: (k, v) => { attrs[k] = String(v); },
      getAttribute: (k) => attrs[k] ?? null,
      appendChild: (c) => { children.push(c); c.parentNode = el; return c; },
      removeChild: (c) => {
        const i = children.indexOf(c);
        if (i >= 0) children.splice(i, 1);
        c.parentNode = null;
        return c;
      },
      addEventListener: () => {},
      getContext: () => ({ drawImage: () => {} }),
      showModal: () => {},
      close: () => {},
      click: () => { if (typeof el.onclick === "function") return el.onclick({}); },
    };
    return el;
  };
  for (const id of knownIDs) {
    const el = makeEl("div");
    el.id = id;
    elements.set(id, el);
  }

  const hooks = {};
  const workerMsgs = [];
  const callPCs = [];
  const sentCallSignals = [];

  class MockWorker {
    constructor(url) {
      this.url = url;
      this.onmessage = null;
    }
    postMessage(msg) {
      workerMsgs.push(msg);
      if (msg && msg.type === "installBundle" && msg.requestId && this.onmessage) {
        setTimeout(() => this.onmessage({ data: { type: "ack", requestId: msg.requestId } }), 0);
      } else if (msg && msg.type === "getStats" && msg.requestId && this.onmessage) {
        setTimeout(() => this.onmessage({ data: { type: "stats", requestId: msg.requestId, stats: { encryptedAudio: 0, encryptedVideo: 0, decryptedAudio: 0, decryptedVideo: 0, rejected: 0 } } }), 0);
      }
    }
  }
  class MockRTCRtpScriptTransform {
    constructor(worker, options) {
      this.worker = worker;
      this.options = options;
    }
  }
  class MockRTCPeerConnection {
    constructor(cfg) {
      this.cfg = cfg;
      this.transceivers = [];
      this.signalingState = "stable";
      this.connectionState = "connected";
      this.remoteDescription = null;
      this.localDescription = null;
      this.closed = false;
      callPCs.push(this);
    }
    addTransceiver(kindOrTrack, opts) {
      const kind = typeof kindOrTrack === "string" ? kindOrTrack : (kindOrTrack.kind || "audio");
      const sender = { track: typeof kindOrTrack === "string" ? null : kindOrTrack, transform: null, replaceTrack: async () => {} };
      const receiver = { track: { kind, id: kind + "-rx" }, transform: null };
      const tr = { sender, receiver, direction: (opts && opts.direction) || "sendrecv", setCodecPreferences: () => {} };
      this.transceivers.push(tr);
      return tr;
    }
    getTransceivers() { return this.transceivers; }
    async createOffer() { return { type: "offer", sdp: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n" }; }
    async createAnswer() { return { type: "answer", sdp: "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n" }; }
    async setLocalDescription(d) { this.localDescription = d; }
    async setRemoteDescription(d) {
      this.remoteDescription = d;
      if (d && d.type === "offer" && this.transceivers.length === 0) {
        this.addTransceiver("audio", { direction: "sendrecv" });
        this.addTransceiver("video", { direction: "sendrecv" });
      }
    }
    async addIceCandidate() {}
    async getStats() { return new Map(); }
    close() { this.closed = true; this.connectionState = "closed"; }
  }
  class MockMediaStream {
    constructor(tracks) { this._tracks = Array.isArray(tracks) ? [...tracks] : []; }
    getTracks() { return this._tracks; }
    addTrack(t) { this._tracks.push(t); }
  }

  const ctx = {
    console,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Uint8Array,
    ArrayBuffer,
    Int16Array,
    Float32Array,
    Set,
    Map,
    WeakSet,
    URL: { createObjectURL: () => "blob:mock", revokeObjectURL: () => {} },
    Blob: function () {},
    crypto: webcrypto,
    sessionStorage: (() => {
      const m = new Map();
      return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)) };
    })(),
    alert: (msg) => alerts.push(String(msg)),
    prompt: () => null,
    navigator: {},
    addEventListener: () => {},
    Worker: MockWorker,
    RTCRtpScriptTransform: MockRTCRtpScriptTransform,
    RTCPeerConnection: MockRTCPeerConnection,
    MediaStream: MockMediaStream,
    Go: class {
      constructor() { this.importObject = {}; }
      run() {}
    },
    fetch: async () => ({}),
    WebAssembly: { instantiateStreaming: async () => ({ instance: {} }) },
    WebSocket: class {
      constructor() { this.readyState = 1; }
      send() {}
      close() {}
    },
    document: {
      getElementById: (id) => elements.get(id) || null,
      createElement: (tag) => makeEl(tag),
      querySelectorAll: () => [],
      addEventListener: () => {},
      execCommand: () => true,
      body: makeEl("body"),
    },
  };
  ctx.location = {
    protocol: "http:",
    host: "localhost:8080",
    origin: "http://localhost:8080",
    pathname: "/",
    hash: hashValue || "",
  };
  ctx.history = {
    pushState: (_s, _t, url) => {
      const idx = String(url).indexOf("#");
      ctx.location.hash = idx >= 0 ? String(url).slice(idx) : "";
    },
  };
  ctx.window = ctx;
  ctx.cotilla = {
    createRoom: () => JSON.stringify({ roomID: "room-ephemeral-1", roomKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY" }),
    init: (seed) => JSON.stringify({ address: "alice-addr-" + seed.slice(0, 6), signPub: "alice-addr-" + seed.slice(0, 6) }),
    joinRoom: (roomID) => JSON.stringify({ status: "ok", roomID }),
    leaveRoom: () => JSON.stringify({ status: "left" }),
    createChannelInvite: () => JSON.stringify({
      room_id: "room-ephemeral-1",
      inviter_pub: "alice-addr",
      room_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
      epoch_id: 1,
      expires_at: Date.now() + 60000,
      signature: "00".repeat(64),
    }),
    setChannelInvite: () => JSON.stringify({ status: "ok" }),
    joinChannel: () => JSON.stringify({ status: "query_broadcast" }),
    requestCatchUp: () => JSON.stringify({ status: "ok" }),
    addPeer: () => {},
    addAnchorPeer: () => {},
    setFallbackMode: () => {},
    solicitAnchors: () => {},
    registerDMSession: () => JSON.stringify({ status: "ok" }),
    joinCall: (scopeID, isDM) => ({
      status: "ok",
      scopeID,
      isDM: !!isDM,
      bundle: {
        scopeID,
        epoch: 1,
        leafIndex: 0,
        sender: { kidBE: new Uint8Array([0, 0, 0, 0, 0, 1, 0, 0]), epoch: 1, leafIndex: 0, address: "alice-addr", key: new Uint8Array(16).fill(1), salt: new Uint8Array(12).fill(2) },
        receivers: [
          { kidBE: new Uint8Array([0, 0, 0, 0, 0, 1, 0, 1]), epoch: 1, leafIndex: 1, address: "zzz-browser-bob", key: new Uint8Array(16).fill(3), salt: new Uint8Array(12).fill(4) },
        ],
      },
    }),
    updateCallOptions: () => JSON.stringify({ status: "ok" }),
    leaveCall: () => JSON.stringify({ status: "ok" }),
    sendCallSignal: (scopeID, target, kind, payload) => {
      sentCallSignals.push({ scopeID, target, kind, payload });
      return JSON.stringify({ status: "ok" });
    },
    activeCallPeers: () => JSON.stringify([]),
    isInCall: () => true,
    signSignaling: (t) => JSON.stringify({ type: t }),
    verifySignaling: () => true,
    createOffer: async () => "mock-offer-sdp",
    acceptOffer: async () => "mock-answer-sdp",
    acceptAnswer: async () => {},
    setOnMessage: (fn) => { hooks.onMessage = fn; },
    setOnAttachmentOffer: (fn) => { hooks.onAttachmentOffer = fn; },
    setOnAttachmentProgress: (fn) => { hooks.onAttachmentProgress = fn; },
    setOnAttachment: (fn) => { hooks.onAttachment = fn; },
    setOnCallPresence: (fn) => { hooks.onCallPresence = fn; },
    setOnCallSignal: (fn) => { hooks.onCallSignal = fn; },
    setOnSFrameKeysUpdated: (fn) => { hooks.onSFrameKeysUpdated = fn; },
    setOnCallPeerClosed: (fn) => { hooks.onCallPeerClosed = fn; },
    setOnDirectInvite: (fn) => { hooks.onDirectInvite = fn; },
    setOnInviteResponse: (fn) => { hooks.onInviteResponse = fn; },
    setOnDMMessage: (fn) => { hooks.onDMMessage = fn; },
    setOnPeerJoined: (fn) => { hooks.onPeerJoined = fn; },
    setOnPeerLeft: (fn) => { hooks.onPeerLeft = fn; },
    setOnMemberEvicted: (fn) => { hooks.onMemberEvicted = fn; },
    setOnEpochCommit: (fn) => { hooks.onEpochCommit = fn; },
    setOnAnchorIntro: (fn) => { hooks.onAnchorIntro = fn; },
    setOnAnchorDeficit: (fn) => { hooks.onAnchorDeficit = fn; },
    setOnAnchorSolicit: (fn) => { hooks.onAnchorSolicit = fn; },
    setOnChannelDiscovered: (fn) => { hooks.onChannelDiscovered = fn; },
    setOnOpen: (fn) => { hooks.onOpen = fn; },
  };

  const sandbox = vm.createContext(ctx);
  try {
    vm.runInContext(cotillaCode, sandbox, { filename: "cotilla.js" });
    vm.runInContext(appCode, sandbox, { filename: "app.js" });
  } catch (e) {
    errors.push(e.stack || e.message || String(e));
  }
  return { sandbox, elements, hooks, alerts, errors, workerMsgs, callPCs, sentCallSignals };
}

(async () => {
  // Scenario 1: Create room click & peer isolation between overlay anchors and room members
  const s1 = runScenario("");
  await new Promise((r) => setTimeout(r, 30));
  const createBtn = s1.elements.get("btn-create-room");
  await createBtn.onclick();

  if (s1.alerts.length > 0 || s1.errors.length > 0) {
    console.error("SCENARIO_1_ALERT_OR_ERR:", JSON.stringify({ alerts: s1.alerts, errors: s1.errors }));
    process.exit(1);
  }
  if (!s1.sandbox.location.hash.includes("#room=room-ephemeral-1")) {
    console.error("SCENARIO_1_MISSING_HASH:", s1.sandbox.location.hash);
    process.exit(1);
  }
  if (s1.elements.get("landing").style.display !== "none") {
    console.error("SCENARIO_1_LANDING_VISIBLE");
    process.exit(1);
  }

  // Native anchor opens DataChannel, but is NOT in room-ephemeral-1
  s1.hooks.onPeerJoined("native-anchor-1");
  s1.hooks.onOpen("native-anchor-1");
  // Discovery in another channel must also be ignored
  s1.hooks.onChannelDiscovered("other-channel-xyz", "stranger-1");

  const st = s1.sandbox.state;
  if (st.peers.size !== 0 || st.directPeers.size !== 0) {
    console.error("SCENARIO_1_LEAKED_OVERLAY_PEERS:", JSON.stringify({
      peers: Array.from(st.peers),
      directPeers: Array.from(st.directPeers),
    }));
    process.exit(1);
  }

  // Browser Bob is discovered in the active room and has an open WebRTC channel
  s1.hooks.onOpen("browser-bob");
  s1.hooks.onChannelDiscovered("room-ephemeral-1", "browser-bob");
  if (st.peers.size !== 1 || !st.peers.has("browser-bob") || st.directPeers.size !== 1 || !st.directPeers.has("browser-bob")) {
    console.error("SCENARIO_1_MISSING_ROOM_PEER:", JSON.stringify({
      peers: Array.from(st.peers),
      directPeers: Array.from(st.directPeers),
    }));
    process.exit(1);
  }

  // Scenario 1b: Mixed Mesh where native-anchor-1 IS in the same room -> promoted to peers & directPeers
  s1.hooks.onChannelDiscovered("room-ephemeral-1", "native-anchor-1");
  if (!st.peers.has("native-anchor-1") || !st.directPeers.has("native-anchor-1")) {
    console.error("SCENARIO_1B_SAME_ROOM_ANCHOR_NOT_PROMOTED");
    process.exit(1);
  }

  // Scenario 1c: Strictly scoped secondary WebRTC call isolation & eviction teardown
  // Unjoined calls or non-member offers MUST create 0 secondary PCs.
  s1.hooks.onCallSignal(JSON.stringify({ scope_id: "room-ephemeral-1", from: "zzz-browser-bob", kind: "offer", payload: "v=0\r\n" }));
  await new Promise((r) => setTimeout(r, 15));
  if (s1.callPCs.length !== 0) {
    console.error("SCENARIO_1C_UNJOINED_CREATED_PC");
    process.exit(1);
  }

  // Join voice in listen-only mode -> installs SFrame bundle in worker, then handles peer join
  await s1.elements.get("btn-voice").onclick();
  s1.hooks.onCallPresence("room-ephemeral-1", false, "zzz-browser-bob", JSON.stringify({ action: "join", scope_id: "room-ephemeral-1", is_dm: false }));
  await new Promise((r) => setTimeout(r, 25));
  if (s1.callPCs.length !== 1 || !s1.callPCs[0].transceivers[0].sender.transform || !s1.callPCs[0].transceivers[0].receiver.transform) {
    console.error("SCENARIO_1C_MISSING_SECONDARY_PC_OR_TRANSFORM");
    process.exit(1);
  }
  if (!s1.workerMsgs.some((m) => m.type === "installBundle" && m.scopeID === "room-ephemeral-1")) {
    console.error("SCENARIO_1C_MISSING_WORKER_BUNDLE");
    process.exit(1);
  }
  if (!s1.sentCallSignals.some((sig) => sig.scopeID === "room-ephemeral-1" && sig.target === "zzz-browser-bob" && sig.kind === "offer")) {
    console.error("SCENARIO_1C_MISSING_OUTBOUND_CALL_OFFER");
    process.exit(1);
  }

  // Evicting zzz-browser-bob must revoke SFrame key & close its secondary PC immediately
  s1.hooks.onMemberEvicted("zzz-browser-bob", "alice", "removed", 2);
  if (!s1.callPCs[0].closed || !s1.workerMsgs.some((m) => m.type === "revokePeer" && m.peerAddr === "zzz-browser-bob")) {
    console.error("SCENARIO_1C_EVICTION_DID_NOT_REVOKE_OR_CLOSE");
    process.exit(1);
  }

  // Scenario 2: Join room from #join-room-input
  const s2 = runScenario("");
  await new Promise((r) => setTimeout(r, 30));
  s2.elements.get("join-room-input").value = "http://localhost:8080/#room=room-join-2&key=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
  await s2.elements.get("btn-join-room").onclick();
  if (s2.alerts.length > 0 || s2.errors.length > 0 || s2.sandbox.state.roomID !== "room-join-2") {
    console.error("SCENARIO_2_JOIN_FAILED:", JSON.stringify({ alerts: s2.alerts, errors: s2.errors, roomID: s2.sandbox.state.roomID }));
    process.exit(1);
  }
  console.log("WEB_UI_HARNESS_OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
`

	cmd := exec.Command(nodeBin, "-e", script)
	cmd.Env = append(os.Environ(),
		"COTILLA_LIB_JS="+cotillaJSPath,
		"COTILLA_APP_JS="+appPath,
		"COTILLA_HTML_IDS="+string(idsJSON),
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("web/app.js + web/cotilla.js browser UI harness failed: %v\nOutput:\n%s", err, out.String())
	}
}

func TestWebCotillaJS_SeparationAndLifecycle(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node binary not available for cotilla.js test")
	}

	cotillaBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "cotilla.js"))
	if err != nil {
		t.Fatalf("read web/cotilla.js failed: %v", err)
	}
	appBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "app.js"))
	if err != nil {
		t.Fatalf("read web/app.js failed: %v", err)
	}
	htmlBytes, err := os.ReadFile(filepath.Join("..", "..", "web", "index.html"))
	if err != nil {
		t.Fatalf("read web/index.html failed: %v", err)
	}

	cotillaSrc := string(cotillaBytes)
	appSrc := string(appBytes)
	if !strings.Contains(string(htmlBytes), `src="cotilla.js"`) {
		t.Fatalf("web/index.html does not load cotilla.js before app.js")
	}
	if strings.Contains(cotillaSrc, "document.") {
		t.Fatalf("web/cotilla.js must not reference DOM (document.*)")
	}
	if strings.Contains(appSrc, "new WebSocket(") || strings.Contains(appSrc, "WebAssembly.instantiate") {
		t.Fatalf("web/app.js must delegate WebSocket signaling and WASM loading to web/cotilla.js")
	}

	cotillaPath, _ := filepath.Abs(filepath.Join("..", "..", "web", "cotilla.js"))
	script := `
const fs = require("fs");
const vm = require("vm");
const { webcrypto } = require("crypto");
const code = fs.readFileSync(process.env.COTILLA_LIB_JS, "utf8");

const wsDials = [];
const wsInstances = [];
const hooks = {};
const calls = {
  hasGateway: false,
  addGatewayPeer: [],
  queryPeers: 0,
  addAnchorPeer: [],
  setFallbackMode: [],
  solicitAnchors: [],
  fetchedWasm: [],
};

class MockWebSocket {
  constructor(url) {
    this.url = url;
    this.readyState = 1;
    this.sent = [];
    this.closed = false;
    wsDials.push(url);
    wsInstances.push(this);
    setTimeout(() => { if (this.onopen) this.onopen(); }, 5);
  }
  send(d) { this.sent.push(JSON.parse(d)); }
  close() { this.closed = true; this.readyState = 3; if (this.onclose) this.onclose(); }
}
MockWebSocket.OPEN = 1;
MockWebSocket.CONNECTING = 0;

const workerMsgs = [];
const callPCs = [];
const sentSignals = [];
class MockWorker {
  postMessage(m) {
    workerMsgs.push(m);
    if (m && m.type === "installBundle" && m.requestId && this.onmessage) {
      setTimeout(() => this.onmessage({ data: { type: "ack", requestId: m.requestId } }), 0);
    } else if (m && m.type === "getStats" && m.requestId && this.onmessage) {
      setTimeout(() => this.onmessage({ data: { type: "stats", requestId: m.requestId, stats: { encryptedAudio: 2, encryptedVideo: 1, decryptedAudio: 3, decryptedVideo: 4, rejected: 0 } } }), 0);
    }
  }
}
class MockTransform { constructor(w, o) { this.w = w; this.o = o; } }
class MockPC {
  constructor() { this.transceivers = []; this.addedCandidates = []; this.closed = false; this.connectionState = "connected"; this.signalingState = "stable"; callPCs.push(this); }
  addTransceiver(k) {
    const tr = { sender: { track: null, transform: null, replaceTrack: async () => {} }, receiver: { track: { kind: k, id: k }, transform: null }, setCodecPreferences: () => {} };
    this.transceivers.push(tr);
    return tr;
  }
  getTransceivers() { return this.transceivers; }
  async createOffer() { return { type: "offer", sdp: "sdp-offer" }; }
  async createAnswer() { return { type: "answer", sdp: "sdp-answer" }; }
  async setLocalDescription(d) { this.localDescription = d; }
  async setRemoteDescription(d) {
    this.remoteDescription = d;
    if (d && d.type === "offer" && this.transceivers.length === 0) {
      this.addTransceiver("audio");
      this.addTransceiver("video");
    }
  }
  async addIceCandidate(c) { this.addedCandidates.push({ cand: c, hadRemote: !!this.remoteDescription }); }
  async getStats() { return new Map(); }
  close() { this.closed = true; this.connectionState = "closed"; }
}

const ctx = {
  console,
  setTimeout,
  clearTimeout,
  Uint8Array,
  ArrayBuffer,
  Set,
  Map,
  WeakSet,
  crypto: webcrypto,
  WebSocket: MockWebSocket,
  Worker: MockWorker,
  RTCRtpScriptTransform: MockTransform,
  RTCPeerConnection: MockPC,
  Go: class {
    constructor() { this.importObject = {}; }
    run() {}
  },
  fetch: async (url) => { calls.fetchedWasm.push(url); return {}; },
  WebAssembly: { instantiateStreaming: async () => ({ instance: {} }) },
  cotilla: {
    init: (seed) => JSON.stringify({ address: "peer-self-" + seed.slice(0, 6), signPub: "peer-self", encPub: "enc-self" }),
    createRoom: () => JSON.stringify({ roomID: "room-lib-1", roomKey: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY" }),
    joinRoom: (roomID) => JSON.stringify({ status: "ok", roomID }),
    leaveRoom: () => JSON.stringify({ status: "left" }),
    setChannelInvite: () => JSON.stringify({ status: "ok" }),
    joinChannel: () => JSON.stringify({ status: "ok" }),
    requestCatchUp: () => JSON.stringify({ status: "ok" }),
    createChannelInvite: () => JSON.stringify({
      room_id: "room-lib-1",
      inviter_pub: "peer-self",
      room_key: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
      epoch_id: 2,
      expires_at: 9999999999999,
      signature: "ab".repeat(64),
    }),
    addPeer: () => {},
    isGatewayPeer: (addr) => addr === "server-1",
    hasGatewayConn: () => !!calls.hasGateway,
    addGatewayPeer: (addr) => calls.addGatewayPeer.push(addr),
    queryPeers: () => { calls.queryPeers++; },
    addAnchorPeer: (a) => calls.addAnchorPeer.push(a),
    setFallbackMode: (fb) => calls.setFallbackMode.push(fb),
    solicitAnchors: (need, anchorsJSON) => calls.solicitAnchors.push({ need, anchors: JSON.parse(anchorsJSON) }),
    registerDMSession: () => JSON.stringify({ status: "ok" }),
    joinCall: (scopeID, isDM) => ({
      status: "ok",
      scopeID,
      isDM: !!isDM,
      bundle: {
        scopeID,
        epoch: 1,
        leafIndex: 0,
        sender: { kidBE: new Uint8Array([0, 0, 0, 0, 0, 1, 0, 0]), epoch: 1, leafIndex: 0, address: "peer-self", key: new Uint8Array(16).fill(5), salt: new Uint8Array(12).fill(6) },
        receivers: [],
      },
    }),
    updateCallOptions: () => JSON.stringify({ status: "ok" }),
    leaveCall: () => JSON.stringify({ status: "ok" }),
    sendCallSignal: (scopeID, target, kind, payload) => {
      sentSignals.push({ scopeID, target, kind, payload });
      return JSON.stringify({ status: "ok" });
    },
    activeCallPeers: () => JSON.stringify([]),
    isInCall: () => false,
    signSignaling: (t, target, sdp) => JSON.stringify({ type: t, target, sdp }),
    verifySignaling: () => true,
    createOffer: async () => "offer-sdp",
    acceptOffer: async () => "answer-sdp",
    acceptAnswer: async () => {},
    setOnMessage: (fn) => { hooks.onMessage = fn; },
    setOnAttachmentOffer: (fn) => { hooks.onAttachmentOffer = fn; },
    setOnAttachmentProgress: (fn) => { hooks.onAttachmentProgress = fn; },
    setOnAttachment: (fn) => { hooks.onAttachment = fn; },
    setOnCallPresence: (fn) => { hooks.onCallPresence = fn; },
    setOnCallSignal: (fn) => { hooks.onCallSignal = fn; },
    setOnSFrameKeysUpdated: (fn) => { hooks.onSFrameKeysUpdated = fn; },
    setOnCallPeerClosed: (fn) => { hooks.onCallPeerClosed = fn; },
    setOnDirectInvite: (fn) => { hooks.onDirectInvite = fn; },
    setOnInviteResponse: (fn) => { hooks.onInviteResponse = fn; },
    setOnDMMessage: (fn) => { hooks.onDMMessage = fn; },
    setOnPeerJoined: (fn) => { hooks.onPeerJoined = fn; },
    setOnPeerLeft: (fn) => { hooks.onPeerLeft = fn; },
    setOnMemberEvicted: (fn) => { hooks.onMemberEvicted = fn; },
    setOnEpochCommit: (fn) => { hooks.onEpochCommit = fn; },
    setOnAnchorIntro: (fn) => { hooks.onAnchorIntro = fn; },
    setOnAnchorDeficit: (fn) => { hooks.onAnchorDeficit = fn; },
    setOnAnchorSolicit: (fn) => { hooks.onAnchorSolicit = fn; },
    setOnChannelDiscovered: (fn) => { hooks.onChannelDiscovered = fn; },
    setOnOpen: (fn) => { hooks.onOpen = fn; },
  },
};
ctx.globalThis = ctx;
ctx.window = ctx;

const sandbox = vm.createContext(ctx);
vm.runInContext(code, sandbox, { filename: "cotilla.js" });

(async () => {
  const CotillaClient = sandbox.CotillaClient;
  if (typeof CotillaClient !== "function") {
    throw new Error("CotillaClient not exported by cotilla.js");
  }

  // Test standalone instantiation with explicit signalingUrl & no DOM
  const client = new CotillaClient({
    signalingUrl: "wss://custom-signaling.example/ws",
    wasmUrl: "/assets/cotilla.wasm",
    getBaseUrl: () => "https://chat.example/",
  });

  await client.loadWasm();
  if (calls.fetchedWasm[0] !== "/assets/cotilla.wasm") {
    throw new Error("expected wasmUrl fetched, got " + JSON.stringify(calls.fetchedWasm));
  }

  const created = await client.createRoom();
  if (!created || created.roomID !== "room-lib-1" || !created.url.includes("https://chat.example/#room=room-lib-1")) {
    throw new Error("unexpected createRoom link result: " + JSON.stringify(created));
  }

  // Invite data helpers preserve '+' signs in base64 keys/signatures cleanly
  const parsed = CotillaClient.parseLink("https://chat.example/#room=room+1&key=abc+def==&inviter=inv1&epoch=3&exp=123456&sig=sigsig");
  if (!parsed || parsed.room !== "room+1" || parsed.key !== "abc+def==" || !parsed.invite || parsed.invite.epoch_id !== 3) {
    throw new Error("parseLink corrupted '+' or invite fields: " + JSON.stringify(parsed));
  }

  await new Promise((r) => setTimeout(r, 20));
  if (wsDials[0] !== "wss://custom-signaling.example/ws") {
    throw new Error("expected configured signalingUrl dial, got " + JSON.stringify(wsDials));
  }

  // Deliver server offer -> verifies addGatewayPeer
  const ws0 = wsInstances[0];
  await ws0.onmessage({ data: JSON.stringify({ type: "offer", peer: "server-1", target: "peer-self", sdp: "server-sdp", timestamp: Date.now(), sig: "server-sig" }) });
  if (!calls.addGatewayPeer.includes("server-1")) {
    throw new Error("cotilla.js did not mark gateway peer via addGatewayPeer");
  }
  const answerSent = ws0.sent.find((m) => m.type === "answer");
  if (!answerSent || answerSent.target !== "server-1") {
    throw new Error("cotilla.js did not set target to server-1 on answer: " + JSON.stringify(answerSent));
  }

  // Receive ok -> client closes WS
  await ws0.onmessage({ data: JSON.stringify({ type: "ok" }) });
  if (!ws0.closed) {
    throw new Error("expected client to close WS after receiving ok");
  }

  // Gateway WebRTC DataChannel opens -> cotilla.js calls queryPeers()
  hooks.onOpen("server-1");
  if (calls.queryPeers !== 1) {
    throw new Error("expected cotilla.js to call queryPeers on gateway OnOpen");
  }

  // Anchor deficit hook fires: when gateway DataChannel is active, cotilla.js must queryPeers and NOT dial /ws!
  if (typeof hooks.onAnchorDeficit !== "function" || typeof hooks.onAnchorSolicit !== "function") {
    throw new Error("cotilla.js did not wire setOnAnchorDeficit and setOnAnchorSolicit");
  }
  calls.hasGateway = true;
  const queriesBefore = calls.queryPeers;
  const dialsBefore = wsDials.length;
  hooks.onAnchorDeficit(0, 2);
  await new Promise((r) => setTimeout(r, 20));
  if (calls.queryPeers <= queriesBefore || wsDials.length !== dialsBefore) {
    throw new Error("expected onAnchorDeficit to call queryPeers and NOT dial /ws when hasGatewayConn is true");
  }
  calls.hasGateway = false;

  // When gateway DataChannel is disconnected, anchor deficit hook MUST dial signalingUrl again!
  hooks.onAnchorDeficit(0, 2);
  await new Promise((r) => setTimeout(r, 20));
  if (wsDials.length !== dialsBefore + 1) {
    throw new Error("expected onAnchorDeficit to reconnect /ws when hasGatewayConn is false, wsDials=" + JSON.stringify(wsDials));
  }

  // Disconnect and verify onAnchorSolicit dials WS cleanly
  wsInstances[1].close();
  client.leaveRoom();
  await client.createRoom();
  await new Promise((r) => setTimeout(r, 20));
  const ws2 = wsInstances[wsInstances.length - 1];
  ws2.close();
  await new Promise((r) => setTimeout(r, 20));
  const dialsBeforeSolicit = wsDials.length;
  hooks.onAnchorSolicit(2);
  await new Promise((r) => setTimeout(r, 20));
  if (wsDials.length <= dialsBeforeSolicit) {
    throw new Error("expected onAnchorSolicit to connect signaling WS when closed");
  }

  // Test createSFrameWorker factory from __COTILLA_BOOTSTRAP__
  let customWorkerCreated = false;
  sandbox.window.__COTILLA_BOOTSTRAP__ = {
    createSFrameWorker: () => {
      customWorkerCreated = true;
      return new MockWorker();
    },
  };
  const customClient = new CotillaClient({ signalingUrl: "wss://custom.example/ws" });
  customClient._ensureSFrameWorker();
  if (!customWorkerCreated) {
    throw new Error("expected CotillaClient to use __COTILLA_BOOTSTRAP__.createSFrameWorker when provided");
  }
  sandbox.window.__COTILLA_BOOTSTRAP__ = null;

  // Secondary call lifecycle: group + DM isolation across channel eviction
  await client.joinCall("room-lib-1", false, { listenOnly: true });
  await client.joinCall("dm-room-1", true, { audio: true });
  await hooks.onCallSignal(JSON.stringify({ scope_id: "dm-room-1", from: "zzz-dm-peer", kind: "offer", payload: "v=0\r\n" }));
  await hooks.onCallSignal(JSON.stringify({ scope_id: "room-lib-1", from: "zzz-evict-peer", kind: "offer", payload: "v=0\r\n" }));
  if (callPCs.length !== 2) {
    throw new Error("expected 2 isolated secondary PCs (group + DM), got " + callPCs.length);
  }
  const stBefore = await client.getCallStats();
  if (stBefore.secondaryPeerCount !== 2 || stBefore.sframe.decryptedVideo !== 4) {
    throw new Error("unexpected getCallStats result: " + JSON.stringify(stBefore));
  }
  // Evict zzz-evict-peer from group channel: group PC closes, DM PC with zzz-dm-peer remains open!
  hooks.onMemberEvicted("zzz-evict-peer", "peer-self", "test", 3);
  if (!callPCs[1].closed || callPCs[0].closed) {
    throw new Error("eviction closed wrong call PC or failed to isolate DM call");
  }

  // Regression test: inbound offer + trickle candidate arriving BEFORE joinCall finishes
  // awaiting installBundleAck must NOT be dropped and must serialize offer->answer->candidate.
  const beforeRacePCs = callPCs.length;
  const raceJoinP = client.joinCall("room-race-1", false, { audio: true });
  hooks.onCallSignal(JSON.stringify({ scope_id: "room-race-1", from: "aaa-early-native", kind: "offer", payload: "v=0\r\n" }));
  hooks.onCallSignal(JSON.stringify({ scope_id: "room-race-1", from: "aaa-early-native", kind: "candidate", payload: JSON.stringify({ candidate: "candidate:1 1 UDP 1 127.0.0.1 9999 typ host" }) }));
  await raceJoinP;
  await new Promise((r) => setTimeout(r, 20));
  if (callPCs.length !== beforeRacePCs + 1) {
    throw new Error("expected early offer during installBundle to create answerer PC, got delta " + (callPCs.length - beforeRacePCs));
  }
  const racePC = callPCs[callPCs.length - 1];
  if (racePC.addedCandidates.length !== 1 || !racePC.addedCandidates[0].hadRemote) {
    throw new Error("expected serialized candidate after remote offer: " + JSON.stringify(racePC.addedCandidates));
  }
  if (!sentSignals.some((s) => s.scopeID === "room-race-1" && s.target === "aaa-early-native" && s.kind === "answer")) {
    throw new Error("expected answer signal for early native offer during joinCall");
  }

  console.log("COTILLA_LIB_OK");
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
`
	cmd := exec.Command(nodeBin, "-e", script)
	cmd.Env = append(os.Environ(), "COTILLA_LIB_JS="+cotillaPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("web/cotilla.js standalone lifecycle test failed: %v\nOutput:\n%s", err, out.String())
	}
}

func TestWebSFrameWorker_RFC9605_WireCompatibilityAndReplay(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node binary not available for sframe-worker test")
	}

	workerPath, _ := filepath.Abs(filepath.Join("..", "..", "web", "sframe-worker.js"))

	// Derive both an MLS-epoch KID entry and an Open/DM 64-bit KID entry (bit 63 set!) from Go.
	idA, _ := cot.NewIdentityFromSeed([]byte("worker-interop-alice-00000000001"))
	idB, _ := cot.NewIdentityFromSeed([]byte("worker-interop-bob-0000000000002"))
	grp, err := cot.NewMLSGroup("worker-room", idA)
	if err != nil {
		t.Fatal(err)
	}
	kpB, _ := cot.NewKeyPackage(idB)
	if _, _, err := grp.CreateAddCommit(kpB); err != nil {
		t.Fatal(err)
	}
	ep, leafA, _, base, err := grp.SnapshotForSFrame("cotilla sframe v1", []byte("worker-room"))
	if err != nil {
		t.Fatal(err)
	}
	mlsAlice, err := cot.DeriveLeafSFrameKey(base, ep, leafA, idA.Address())
	if err != nil {
		t.Fatal(err)
	}
	rk, _ := cot.GenerateRoomKey()
	dmBundle, err := cot.BuildDMSFrameBundle("dm-worker-1", rk, idA.Address(), idB.Address())
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt frames in Go for both MLS (epoch<<16|leaf) and DM (bit 63 Open KID) at ctr=0 and ctr=9 (exercises minimal BE header paths).
	mlsCT0, err := cot.SFrameEncryptFrame(mlsAlice, 0, []byte("go-mls-frame-0"))
	if err != nil {
		t.Fatal(err)
	}
	mlsCT9, err := cot.SFrameEncryptFrame(mlsAlice, 9, []byte("go-mls-frame-9"))
	if err != nil {
		t.Fatal(err)
	}
	dmCT0, err := cot.SFrameEncryptFrame(dmBundle.Receivers[0], 0, []byte("go-dm-frame-0"))
	if err != nil {
		t.Fatal(err)
	}

	var kidMLSBuf, kidDMBuf [8]byte
	binary.BigEndian.PutUint64(kidMLSBuf[:], mlsAlice.KID)
	binary.BigEndian.PutUint64(kidDMBuf[:], dmBundle.Receivers[0].KID)

	fixture, _ := json.Marshal(map[string]any{
		"aliceAddr": idA.Address(),
		"bobAddr":   idB.Address(),
		"mlsKID":    hex.EncodeToString(kidMLSBuf[:]),
		"mlsKey":    hex.EncodeToString(mlsAlice.Key[:]),
		"mlsSalt":   hex.EncodeToString(mlsAlice.Salt[:]),
		"mlsCT0":    hex.EncodeToString(mlsCT0),
		"mlsCT9":    hex.EncodeToString(mlsCT9),
		"dmKID":     hex.EncodeToString(kidDMBuf[:]),
		"dmKey":     hex.EncodeToString(dmBundle.Receivers[0].Key[:]),
		"dmSalt":    hex.EncodeToString(dmBundle.Receivers[0].Salt[:]),
		"dmCT0":     hex.EncodeToString(dmCT0),
	})

	script := `
const fs = require("fs");
const vm = require("vm");
const assert = require("assert");
const { webcrypto } = require("crypto");
const { ReadableStream, WritableStream, TransformStream } = require("stream/web");

const workerCode = fs.readFileSync(process.env.SFRAME_WORKER_JS, "utf8");
const fx = JSON.parse(process.env.SFRAME_FIXTURE);
const hexToU8 = (h) => new Uint8Array(Buffer.from(h, "hex"));

const selfCtx = {
  console,
  setTimeout,
  clearTimeout,
  Uint8Array,
  ArrayBuffer,
  DataView,
  Set,
  Map,
  BigInt,
  Promise,
  crypto: webcrypto,
  TransformStream,
  onmessage: null,
  onrtctransform: null,
  posted: [],
  postMessage(m) { this.posted.push(m); },
};
selfCtx.self = selfCtx;
selfCtx.globalThis = selfCtx;

vm.runInContext(workerCode, vm.createContext(selfCtx), { filename: "sframe-worker.js" });

(async () => {
  // Install MLS + DM bundles with 64-bit KIDs (including bit-63 Open KID!)
  await selfCtx.onmessage({
    data: {
      type: "installBundle",
      requestId: 1,
      scopeID: "worker-room",
      graceMs: 3000,
      bundle: {
        epoch: 1,
        sender: { kidBE: hexToU8(fx.mlsKID), epoch: 1, leafIndex: 0, address: fx.aliceAddr, key: hexToU8(fx.mlsKey), salt: hexToU8(fx.mlsSalt) },
        receivers: [{ kidBE: hexToU8(fx.mlsKID), epoch: 1, leafIndex: 0, address: fx.aliceAddr, key: hexToU8(fx.mlsKey), salt: hexToU8(fx.mlsSalt) }],
      },
    },
  });
  await selfCtx.onmessage({
    data: {
      type: "installBundle",
      requestId: 2,
      scopeID: "dm-worker-1",
      graceMs: 3000,
      bundle: {
        epoch: 0,
        sender: { kidBE: hexToU8(fx.dmKID), epoch: 0, leafIndex: -1, address: fx.bobAddr, key: hexToU8(fx.dmKey), salt: hexToU8(fx.dmSalt) },
        receivers: [{ kidBE: hexToU8(fx.dmKID), epoch: 0, leafIndex: -1, address: fx.bobAddr, key: hexToU8(fx.dmKey), salt: hexToU8(fx.dmSalt) }],
      },
    },
  });

  // Helper to run frames through onrtctransform
  async function runFrames(options, inputFrames) {
    const out = [];
    let writableResolve;
    const done = new Promise((r) => { writableResolve = r; });
    const readable = new ReadableStream({
      start(ctrl) {
        for (const f of inputFrames) ctrl.enqueue({ data: f.buffer.slice(f.byteOffset, f.byteOffset + f.byteLength) });
        ctrl.close();
      },
    });
    const writable = new WritableStream({
      write(chunk) { out.push(new Uint8Array(chunk.data)); },
      close() { writableResolve(); },
    });
    selfCtx.onrtctransform({ transformer: { readable, writable, options } });
    await done;
    return out;
  }

  // 1. Decrypt Go-encrypted MLS frames (ctr=0, ctr=9) + reject replayed ctr=9
  const decMLS = await runFrames(
    { scopeID: "worker-room", peerAddr: fx.aliceAddr, direction: "decrypt", mediaKind: "audio" },
    [hexToU8(fx.mlsCT0), hexToU8(fx.mlsCT9), hexToU8(fx.mlsCT9)]
  );
  assert.strictEqual(decMLS.length, 2, "replay frame must be rejected");
  assert.strictEqual(Buffer.from(decMLS[0]).toString(), "go-mls-frame-0");
  assert.strictEqual(Buffer.from(decMLS[1]).toString(), "go-mls-frame-9");

  // 2. Decrypt Go-encrypted DM Open-KID frame (bit 63 set -> tests lossless 64-bit KID!)
  const decDM = await runFrames(
    { scopeID: "dm-worker-1", peerAddr: fx.bobAddr, direction: "decrypt", mediaKind: "video" },
    [hexToU8(fx.dmCT0)]
  );
  assert.strictEqual(decDM.length, 1);
  assert.strictEqual(Buffer.from(decDM[0]).toString(), "go-dm-frame-0");

  // 3. Peer spoofing must fail closed even with valid MLS key
  const spoofAttempt = await runFrames(
    { scopeID: "worker-room", peerAddr: "wrong-peer", direction: "decrypt", mediaKind: "audio" },
    [hexToU8(fx.mlsCT0)]
  );
  assert.strictEqual(spoofAttempt.length, 0);

  // 4. Encrypt in JS worker and verify decryptable with Go-encrypted receiver key
  const encFrames = await runFrames(
    { scopeID: "worker-room", peerAddr: fx.aliceAddr, direction: "encrypt", mediaKind: "video" },
    [new TextEncoder().encode("js-vp8-frame-0")]
  );
  assert.strictEqual(encFrames.length, 1);
  process.stdout.write(Buffer.from(encFrames[0]).toString("hex"));
})();
`
	cmd := exec.Command(nodeBin, "-e", script)
	cmd.Env = append(os.Environ(), "SFRAME_WORKER_JS="+workerPath, "SFRAME_FIXTURE="+string(fixture))
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sframe-worker test failed: %v\nstderr:\n%s", err, stderr.String())
	}

	// Verify Go's SFrameKeyring decrypts the frame produced by WebCrypto sframe-worker.js!
	workerCT, err := hex.DecodeString(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatalf("invalid hex ciphertext from sframe-worker: %v", err)
	}
	kr := cot.NewSFrameKeyring()
	if err := kr.InstallBundle(&cot.SFrameKeyBundle{
		ScopeID:   "worker-room",
		Epoch:     ep,
		LeafIndex: leafA,
		Sender:    mlsAlice,
		Receivers: []cot.SFrameKeyEntry{mlsAlice},
	}, 0); err != nil {
		t.Fatal(err)
	}
	pt, kid, err := kr.Decrypt(workerCT, idA.Address())
	if err != nil {
		t.Fatalf("Go SFrameKeyring failed to decrypt JS WebCrypto SFrame frame: %v", err)
	}
	if kid != mlsAlice.KID || string(pt) != "js-vp8-frame-0" {
		t.Fatalf("unexpected decrypted output from JS worker: kid=%x pt=%q", kid, string(pt))
	}
}

func TestBootstrap_StrictlyTwoFilesAndInlinedWasmExec(t *testing.T) {
	// Verify dist/bootstrap directory structure
	entries, err := os.ReadDir(filepath.Join("..", "..", "dist", "bootstrap"))
	if err != nil {
		t.Fatalf("read dist/bootstrap dir: %v", err)
	}
	if len(entries) != 2 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dist/bootstrap must contain strictly 2 files, got %d: %v", len(entries), names)
	}
	names := map[string]bool{entries[0].Name(): true, entries[1].Name(): true}
	if !names["cotilla.wasm"] || !names["index.html"] {
		t.Fatalf("dist/bootstrap must contain strictly cotilla.wasm and index.html, got: %v", names)
	}

	// Verify index.html content
	htmlBytes, err := os.ReadFile(filepath.Join("..", "..", "dist", "bootstrap", "index.html"))
	if err != nil {
		t.Fatalf("read dist/bootstrap/index.html: %v", err)
	}
	htmlStr := string(htmlBytes)
	if strings.Contains(htmlStr, "/* __WASM_EXEC_JS__ */") {
		t.Errorf("dist/bootstrap/index.html contains un-substituted __WASM_EXEC_JS__")
	}
	if strings.Contains(htmlStr, "__PINNED_PUB_KEY__") {
		t.Errorf("dist/bootstrap/index.html contains un-substituted __PINNED_PUB_KEY__")
	}
	if !strings.Contains(htmlStr, "class Go {") && !strings.Contains(htmlStr, "globalThis.Go = class") {
		t.Errorf("dist/bootstrap/index.html does not contain inlined Go wasm_exec runtime")
	}

	// Verify dist/apps bundle and signed manifest
	bundleBytes, err := os.ReadFile(filepath.Join("..", "..", "dist", "apps", "cotilla-chat.html"))
	if err != nil {
		t.Fatalf("read dist/apps/cotilla-chat.html: %v", err)
	}
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "dist", "apps", "cotilla-chat.manifest.json"))
	if err != nil {
		t.Fatalf("read dist/apps/cotilla-chat.manifest.json: %v", err)
	}

	var manifest cot.AppManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	now := time.Now().UnixMilli()
	if err := cot.VerifyAppBundle(&manifest, bundleBytes, manifest.PubKey, manifest.AppID, manifest.Channel, 1, now); err != nil {
		t.Fatalf("VerifyAppBundle failed for built bundle: %v", err)
	}
}

func TestBootstrap_SignalingStaticServing(t *testing.T) {
	fs := http.FileServer(http.Dir(filepath.Join("..", "..", "dist", "bootstrap")))
	handler := withWasmMime(fs)

	// 1. GET / -> index.html
	req, _ := http.NewRequest("GET", "/", nil)
	rr := &testResponseWriter{header: make(http.Header)}
	handler.ServeHTTP(rr, req)
	if rr.code != 0 && rr.code != http.StatusOK {
		t.Errorf("expected 200 for /, got %d", rr.code)
	}
	if !strings.Contains(string(rr.body), "progress-bar") {
		t.Errorf("expected index.html content for /, got: %s", string(rr.body)[:min(100, len(rr.body))])
	}

	// 2. GET /cotilla.wasm -> application/wasm
	reqWasm, _ := http.NewRequest("GET", "/cotilla.wasm", nil)
	rrWasm := &testResponseWriter{header: make(http.Header)}
	handler.ServeHTTP(rrWasm, reqWasm)
	if ct := rrWasm.header.Get("Content-Type"); ct != "application/wasm" {
		t.Errorf("expected application/wasm Content-Type, got %q", ct)
	}

	// 3. GET /other.js -> 404
	reqOther, _ := http.NewRequest("GET", "/other.js", nil)
	rrOther := &testResponseWriter{header: make(http.Header)}
	handler.ServeHTTP(rrOther, reqOther)
	if rrOther.code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent file in 2-file bootstrap, got %d", rrOther.code)
	}
}

func TestBootstrap_NodeHarnessEndToEnd(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node binary not available for bootstrap browser harness")
	}

	bootstrapPath := filepath.Join("..", "..", "dist", "bootstrap", "index.html")
	manifestPath := filepath.Join("..", "..", "dist", "apps", "cotilla-chat.manifest.json")
	bundlePath := filepath.Join("..", "..", "dist", "apps", "cotilla-chat.html")

	bootstrapBytes, err := os.ReadFile(bootstrapPath)
	if err != nil {
		t.Fatalf("read dist/bootstrap/index.html: %v", err)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read dist/apps/cotilla-chat.manifest.json: %v", err)
	}
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read dist/apps/cotilla-chat.html: %v", err)
	}

	// Verify bootstrap UI contains only the minimalistic progress bar (no verbose logs or cards)
	requiredIDs := []string{"progress-bar"}
	for _, id := range requiredIDs {
		if !strings.Contains(string(bootstrapBytes), `id="`+id+`"`) {
			t.Errorf("bootstrap/index.html missing required DOM id %q", id)
		}
	}
	verboseElements := []string{"status-text", "diagnostics-log", "diagnostics-details", "error-box", "btn-retry"}
	for _, el := range verboseElements {
		if strings.Contains(string(bootstrapBytes), `id="`+el+`"`) {
			t.Errorf("bootstrap/index.html contains verbose element %q, expected minimalistic loading bar only", el)
		}
	}

	// Extract the main bootstrap script (the second <script> tag in bootstrap/index.html)
	scriptRe := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	matches := scriptRe.FindAllSubmatch(bootstrapBytes, -1)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 script tags in bootstrap/index.html (wasm_exec + bootstrap), found %d", len(matches))
	}
	bootstrapScript := string(matches[1][1])

	nodeHarness := `
const vm = require("vm");
const assert = require("assert");

const bootstrapScript = process.env.BOOTSTRAP_SCRIPT;
const manifestJSON = process.env.MANIFEST_JSON;
const bundleHTML = process.env.BUNDLE_HTML;

let writtenDocument = "";
let docOpened = false;
let docClosed = false;

const makeEl = (id) => {
  const listeners = {};
  return {
    id,
    style: {},
    classList: {
      add: () => {},
      remove: () => {},
      toggle: () => {},
      contains: () => false,
    },
    textContent: "",
    value: 0,
    max: 100,
    disabled: false,
    removeAttribute: () => {},
    addEventListener: (ev, fn) => { listeners[ev] = fn; },
    click: () => { if (listeners["click"]) listeners["click"](); },
  };
};

const elements = new Map();
const getEl = (id) => {
  if (!elements.has(id)) elements.set(id, makeEl(id));
  return elements.get(id);
};

let manifestCallback = null;
let bundleReadyCallback = null;
let attachmentProgressCallback = null;

const fakeWasmModule = { __isMockWasmModule: true };
const debugLogs = [];

const mockCotilla = {
  init: () => JSON.stringify({ address: "mock_peer_addr", signPub: "mock_sign_pub" }),
  signSignaling: (type, target, sdp) => JSON.stringify({
    type,
    peer: "mock_peer_addr",
    timestamp: Date.now(),
    signature: "mock_sig_hex",
    target: target || "",
    sdp: sdp || "",
  }),
  verifySignaling: () => true,
  bootstrapApp: (cfg) => {
    const parsed = typeof cfg === "string" ? JSON.parse(cfg) : cfg;
    assert.strictEqual(parsed.seederGroup.name, "cotilla-app-dist-v1");
    assert.strictEqual(parsed.appName, "cotilla-chat");
    assert.strictEqual(parsed.seederGroup.channel, "stable");
    return JSON.stringify({ room_key: "mock_dist_key" });
  },
  joinBootstrap: (distRoomID, roomKey, appID, channel, pinnedPubKey, minSeq) => {
    assert.strictEqual(distRoomID, "cotilla-app-dist-v1");
    assert.strictEqual(appID, "cotilla-chat");
    assert.strictEqual(channel, "stable");
    return JSON.stringify({ room_key: "mock_dist_key" });
  },
  verifyAppBundle: (mStr, bBytes, pinnedPub, appID, channel, minSeq) => {
    const m = JSON.parse(mStr);
    assert.strictEqual(m.app_id, "cotilla-chat");
    assert(bBytes.length > 0);
    return JSON.stringify({ valid: true });
  },
  shutdown: () => {},
  addAnchorPeer: (peer) => {},
  isGatewayPeer: (addr) => true,
  addGatewayPeer: (addr) => {},
  queryPeers: () => {},
  createOffer: async (peer) => "v=0\r\no=mock 0 0 IN IP4 127.0.0.1\r\ns=-\r\n",
  acceptOffer: async (peer, sdp) => "v=0\r\no=mock 0 0 IN IP4 127.0.0.1\r\ns=-\r\n",
  acceptAnswer: async (peer, sdp) => {},
  requestAppManifest: () => {},
  setOnOpen: (fn) => {},
  setOnPeerLeft: (fn) => {},
  setOnAttachmentProgress: (fn) => { attachmentProgressCallback = fn; },
  setOnAppManifest: (fn) => { manifestCallback = fn; },
  setOnAppBundleReady: (fn) => {
    bundleReadyCallback = fn;
    // Trigger bundle delivery shortly after registration
    setTimeout(() => {
      if (manifestCallback) {
        manifestCallback(manifestJSON, "mock_seeder_addr");
      }
      if (attachmentProgressCallback) {
        attachmentProgressCallback("mock_file_id", 1, 2);
        attachmentProgressCallback("mock_file_id", 2, 2);
      }
      setTimeout(() => {
        const enc = new TextEncoder();
        const bundleBytes = enc.encode(bundleHTML);
        bundleReadyCallback(manifestJSON, bundleBytes);
      }, 20);
    }, 20);
  },
};

class MockWebSocket {
  constructor(url) {
    this.url = url;
    setTimeout(() => {
      if (this.onopen) this.onopen();
    }, 10);
  }
  send(data) {
    const msg = JSON.parse(data);
    if (msg.type === "register") {
      setTimeout(() => {
        if (this.onmessage) {
          this.onmessage({
            data: JSON.stringify({
              type: "offer",
              peer: "mock_server_addr",
              target: "mock_addr_0000000000000000000000000000000000000000000000000000000000000000",
              sdp: "v=0\r\no=mock 0 0 IN IP4 127.0.0.1\r\ns=-\r\n",
              timestamp: Date.now(),
              sig: "00".repeat(64),
            }),
          });
        }
      }, 10);
    } else if (msg.type === "answer") {
      assert.strictEqual(msg.target, "mock_server_addr", "bootstrap answer message must include non-empty server target");
      setTimeout(() => {
        if (this.onmessage) {
          this.onmessage({
            data: JSON.stringify({ type: "ok" }),
          });
        }
      }, 10);
    }
  }
  close() {}
}

class MockGo {
  constructor() {
    this.importObject = {};
  }
  async run() {}
}

const sandbox = {
  console: {
    ...console,
    debug: (...args) => {
      debugLogs.push(args.join(" "));
    },
  },
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  TextDecoder,
  TextEncoder,
  Uint8Array,
  Promise,
  WebAssembly: {
    compileStreaming: async () => fakeWasmModule,
    compile: async () => fakeWasmModule,
    instantiate: async () => ({ exports: {} }),
  },
  fetch: async (url) => {
    if (url === "cotilla.wasm") {
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => new ArrayBuffer(1024),
      };
    }
    throw new Error("404: " + url);
  },
  Go: MockGo,
  WebSocket: MockWebSocket,
  window: {},
  document: {
    getElementById: (id) => getEl(id),
    querySelector: (sel) => getEl(sel.replace("#", "")),
    open: () => { docOpened = true; writtenDocument = ""; },
    write: (content) => { writtenDocument += content; },
    close: () => { docClosed = true; },
  },
  location: {
    protocol: "http:",
    host: "127.0.0.1:8080",
    origin: "http://127.0.0.1:8080",
    pathname: "/",
    search: "",
    hash: "#room=test-room-777&key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  },
  navigator: {},
};

sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.cotilla = mockCotilla;

const context = vm.createContext(sandbox);

vm.runInContext(bootstrapScript, context);

// Poll for document replacement
const startTime = Date.now();
const interval = setInterval(() => {
  if (docOpened && docClosed && writtenDocument.length > 0) {
    clearInterval(interval);

    // Assertions
    assert(writtenDocument.includes("<!DOCTYPE html>"), "writtenDocument must be valid HTML");
    assert(writtenDocument.includes("Cotilla P2P Burner Chat") || writtenDocument.includes("cotilla-chat"), "writtenDocument must contain chat app HTML");
    assert(sandbox.window.__COTILLA_BOOTSTRAP__, "window.__COTILLA_BOOTSTRAP__ must be set");
    assert.strictEqual(sandbox.window.__COTILLA_BOOTSTRAP__.wasmModule, fakeWasmModule, "precompiled wasm module must be preserved");
    assert.strictEqual(sandbox.window.__COTILLA_BOOTSTRAP__.manifest.app_id, "cotilla-chat", "manifest app_id must match");
    assert.strictEqual(sandbox.location.hash, "#room=test-room-777&key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "URL hash must be preserved");

    // Simulate browser parsing and executing the written document's scripts
    sandbox.document.createElement = (tag) => makeEl(tag);
    sandbox.cotilla = mockCotilla;
    const scriptMatches = writtenDocument.matchAll(/<script>([\s\S]*?)<\/script>/g);
    for (const match of scriptMatches) {
      const code = match[1].trim();
      if (code) {
        vm.runInContext(code, context);
      }
    }

    // Verify chat app booted using precompiled bootstrap runtime
    assert(sandbox.window.CotillaClient, "CotillaClient must be defined in written document");
    assert(sandbox.window.cotillaClient, "cotillaClient instance must be initialized in written document");
    assert.strictEqual(getEl("app-version").textContent, "cotilla-chat v1.0.0 (seq 1)", "app-version element must reflect verified manifest");
    assert(debugLogs.length > 0, "bootstrap must emit debug messages to console.debug");

    process.stdout.write("SUCCESS_BOOTSTRAP_LAUNCH");
    process.exit(0);
  }

  if (Date.now() - startTime > 3000) {
    clearInterval(interval);
    console.error("Timeout waiting for bootstrap execution. Debug logs: " + JSON.stringify(debugLogs));
    process.exit(1);
  }
}, 20);
`

	cmd := exec.Command(nodeBin, "-e", nodeHarness)
	cmd.Env = append(os.Environ(),
		"BOOTSTRAP_SCRIPT="+bootstrapScript,
		"MANIFEST_JSON="+string(manifestBytes),
		"BUNDLE_HTML="+string(bundleBytes),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node bootstrap harness failed: %v\nOutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "SUCCESS_BOOTSTRAP_LAUNCH") {
		t.Fatalf("expected SUCCESS_BOOTSTRAP_LAUNCH, got: %s", string(out))
	}
}

type testResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (w *testResponseWriter) Header() http.Header { return w.header }
func (w *testResponseWriter) Write(b []byte) (int, error) {
	w.body = append(w.body, b...)
	return len(b), nil
}
func (w *testResponseWriter) WriteHeader(statusCode int) {
	w.code = statusCode
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestCotillaBootstrap_SourceAndSingleFileBuild(t *testing.T) {
	cbDir := filepath.Join("..", "..", "cotilla-bootstrap")
	if _, err := os.Stat(cbDir); err != nil {
		t.Skip("cotilla-bootstrap directory not present")
	}

	// 1. Check index.html source
	indexHTML, err := os.ReadFile(filepath.Join(cbDir, "index.html"))
	if err != nil {
		t.Fatalf("read cotilla-bootstrap/index.html: %v", err)
	}
	if !strings.Contains(string(indexHTML), `id="progress-bar"`) {
		t.Errorf("cotilla-bootstrap/index.html missing progress-bar element")
	}

	// 2. Check src/style.css source
	styleCSS, err := os.ReadFile(filepath.Join(cbDir, "src", "style.css"))
	if err != nil {
		t.Fatalf("read cotilla-bootstrap/src/style.css: %v", err)
	}
	if !strings.Contains(string(styleCSS), "progress") || !strings.Contains(string(styleCSS), "--fill") {
		t.Errorf("cotilla-bootstrap/src/style.css missing progress styling")
	}

	// 3. Check src/worker.js matches web/sframe-worker.js
	workerJS, err := os.ReadFile(filepath.Join(cbDir, "src", "worker.js"))
	if err != nil {
		t.Fatalf("read cotilla-bootstrap/src/worker.js: %v", err)
	}
	webWorkerJS, err := os.ReadFile(filepath.Join("..", "..", "web", "sframe-worker.js"))
	if err != nil {
		t.Fatalf("read web/sframe-worker.js: %v", err)
	}
	if !bytes.Equal(workerJS, webWorkerJS) {
		t.Errorf("cotilla-bootstrap/src/worker.js differs from web/sframe-worker.js")
	}

	// 4. Check src/main.js source
	mainJS, err := os.ReadFile(filepath.Join(cbDir, "src", "main.js"))
	if err != nil {
		t.Fatalf("read cotilla-bootstrap/src/main.js: %v", err)
	}
	mainStr := string(mainJS)
	for _, expected := range []string{
		"wasm_exec.js",
		"cotilla.wasm?inline",
		"worker.js?worker&inline",
		"createSFrameWorker",
		"verifyAppBundle",
		"bootstrapApp",
		"queryPeers",
		"document.write",
	} {
		if !strings.Contains(mainStr, expected) {
			t.Errorf("cotilla-bootstrap/src/main.js missing expected pattern %q", expected)
		}
	}

	// 5. Check compiled single-file bundle in cotilla-bootstrap/dist/
	distIndex := filepath.Join(cbDir, "dist", "index.html")
	if distBytes, err := os.ReadFile(distIndex); err == nil {
		distStr := string(distBytes)
		if !strings.Contains(distStr, "data:application/wasm") {
			t.Errorf("cotilla-bootstrap/dist/index.html missing inlined wasm")
		}
		if !strings.Contains(distStr, "class Go") && !strings.Contains(distStr, "globalThis.Go") {
			t.Errorf("cotilla-bootstrap/dist/index.html missing Go runtime")
		}
		if !strings.Contains(distStr, "progress-bar") {
			t.Errorf("cotilla-bootstrap/dist/index.html missing progress-bar")
		}
		if !strings.Contains(distStr, "createSFrameWorker") {
			t.Errorf("cotilla-bootstrap/dist/index.html missing createSFrameWorker")
		}
	}
}
