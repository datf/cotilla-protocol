// cotilla.js — Reusable Ephemeral Zero-Knowledge Cotilla P2P Client Library
//
// Responsibilities:
//   - Loading the Go WebAssembly module (cotilla.wasm) and identity seed management
//   - Parsing and constructing zero-knowledge invite links (#room=...&key=...)
//   - Managing the configured signaling WebSocket (/ws) for root discovery & WebRTC SDP negotiation
//   - Handling anchor pool resilience (anchor tracking, fallback mode, anchor deficit & solicitation reconnects)
//   - Exposing room messaging, DMs, attachments (zero-copy Uint8Array), and media frame APIs
//
// Contains zero DOM/UI dependencies so any UI layer (e.g. app.js) can configure and bind to it.

(function (rootScope) {
  "use strict";

  function parseCotillaJSON(raw) {
    if (typeof raw !== "string" || raw === "") return null;
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && parsed.error) {
      throw new Error(parsed.error);
    }
    return parsed;
  }

  function createMemoryStorage() {
    const store = new Map();
    return {
      getItem(k) {
        return store.has(k) ? store.get(k) : null;
      },
      setItem(k, v) {
        store.set(k, String(v));
      },
    };
  }

  function encodeBase64JSON(obj) {
    const jsonStr = JSON.stringify(obj);
    if (typeof btoa === "function") {
      return btoa(jsonStr);
    }
    if (typeof Buffer !== "undefined") {
      return Buffer.from(jsonStr, "utf8").toString("base64");
    }
    return "";
  }

  function decodeBase64JSON(b64) {
    let jsonStr = "";
    if (typeof atob === "function") {
      jsonStr = atob(b64);
    } else if (typeof Buffer !== "undefined") {
      jsonStr = Buffer.from(b64, "base64").toString("utf8");
    } else {
      return null;
    }
    return JSON.parse(jsonStr);
  }

  class CotillaClient {
    constructor(config = {}) {
      this.config = {
        signalingUrl: config.signalingUrl || "",
        wasmUrl: config.wasmUrl || "cotilla.wasm",
        sframeWorkerUrl: config.sframeWorkerUrl || "sframe-worker.js",
        getBaseUrl: typeof config.getBaseUrl === "function" ? config.getBaseUrl : () => "",
        storage: config.storage || createMemoryStorage(),
        Go: config.Go || null,
        WebSocket: config.WebSocket || null,
        RTCPeerConnection: config.RTCPeerConnection || null,
        RTCRtpScriptTransform: config.RTCRtpScriptTransform || null,
        Worker: config.Worker || null,
        iceServers: Array.isArray(config.iceServers) ? config.iceServers : [],
        fetch: config.fetch || null,
        WebAssembly: config.WebAssembly || null,
        crypto: config.crypto || null,
      };

      this.wasm = null;
      this._wasmLoadingPromise = null;

      // Session / protocol state
      this.me = null;
      this.roomID = null;
      this.roomKey = null;
      this.isCreator = false;
      this.isEvicted = false;

      // Signaling / WebRTC peer tracking
      this.ws = null;
      this.wsRole = null;
      this.wsIntentionalClose = false;
      this.reconnectTimer = null;
      this._lastSolicitAttemptAt = 0;

      // Keep Set references stable across resets so UI layers can observe live membership cleanly
      this.offeredRoots = new Set();
      this.answeredRoots = new Set();
      this.overlayPeers = new Set();
      this.peers = new Set();
      this.directPeers = new Set();

      // Dedicated secondary WebRTC call state (strictly scoped to active calls + SFrame worker)
      this.activeCalls = new Map(); // scopeID -> { scopeID, isDM, opts, peers: Map, bundleReady }
      this.callPCs = new Map(); // `${scopeID}::${peerAddr}` -> call peer entry
      this._callSignalQueues = new Map(); // `${scopeID}::${peerAddr}` -> sequential promise chain
      this.sframeWorker = null;
      this._workerReqSeq = 0;
      this._workerAcks = new Map();
      this._workerStatsResolvers = new Map();
      this._localAudioTrack = null;
      this._localVideoTrack = null;
      this._localVideoKind = null;

      this._listeners = new Map();
    }

    // ---- Link & Hash Utilities (Static) ----

    static parseLink(hashOrUrl) {
      if (!hashOrUrl || typeof hashOrUrl !== "string") return null;
      const hashIdx = hashOrUrl.indexOf("#");
      const content = hashIdx !== -1 ? hashOrUrl.slice(hashIdx + 1) : hashOrUrl;
      if (!content) return null;

      let room = null;
      let key = null;
      let inviter = null;
      let epoch = 0;
      let exp = null;
      let sig = null;
      let parentB64 = null;

      // Manual query parsing to preserve '+' characters in base64 keys/signatures
      const pairs = content.split("&");
      for (const pair of pairs) {
        const eq = pair.indexOf("=");
        if (eq === -1) continue;
        const k = decodeURIComponent(pair.slice(0, eq).trim());
        const v = decodeURIComponent(pair.slice(eq + 1).trim());
        if (k === "room") room = v;
        if (k === "key") key = v;
        if (k === "inviter") inviter = v;
        if (k === "epoch") epoch = parseInt(v, 10);
        if (k === "exp") exp = parseInt(v, 10);
        if (k === "sig") sig = v;
        if (k === "parent") parentB64 = v;
      }

      if (room && key) {
        const out = { room, key };
        if (inviter && exp && sig) {
          out.invite = {
            room_id: room,
            room_key: key,
            inviter_pub: inviter,
            epoch_id: Number.isNaN(epoch) ? 0 : epoch,
            expires_at: exp,
            signature: sig,
          };
          if (parentB64) {
            try {
              const parentObj = decodeBase64JSON(parentB64);
              if (parentObj) out.invite.parent_invite = parentObj;
            } catch {}
          }
        }
        return out;
      }
      return null;
    }

    static buildHash(roomID, roomKey, invite) {
      let hash = `#room=${encodeURIComponent(roomID)}&key=${encodeURIComponent(roomKey)}`;
      if (invite && invite.inviter_pub && invite.expires_at && invite.signature) {
        hash += `&inviter=${encodeURIComponent(invite.inviter_pub)}&epoch=${invite.epoch_id || 0}&exp=${invite.expires_at}&sig=${encodeURIComponent(invite.signature)}`;
        if (invite.parent_invite) {
          try {
            const b64 = encodeBase64JSON(invite.parent_invite);
            if (b64) hash += `&parent=${encodeURIComponent(b64)}`;
          } catch {}
        }
      }
      return hash;
    }

    static buildLink(baseUrl, roomID, roomKey, invite) {
      return `${baseUrl || ""}${CotillaClient.buildHash(roomID, roomKey, invite)}`;
    }

    // ---- Event Subscriptions ----

    on(eventName, handler) {
      if (typeof handler !== "function") return () => {};
      let set = this._listeners.get(eventName);
      if (!set) {
        set = new Set();
        this._listeners.set(eventName, set);
      }
      set.add(handler);
      return () => this.off(eventName, handler);
    }

    off(eventName, handler) {
      const set = this._listeners.get(eventName);
      if (set) {
        set.delete(handler);
      }
    }

    _emit(eventName, payload) {
      const set = this._listeners.get(eventName);
      if (!set) return;
      for (const fn of Array.from(set)) {
        try {
          fn(payload);
        } catch (err) {
          console.error(`[CotillaClient] listener error for ${eventName}:`, err);
        }
      }
    }

    // ---- WASM Bootstrap & Identity ----

    _wasm() {
      const w = this.wasm || rootScope.cotilla;
      if (!w) {
        throw new Error("Cotilla WASM module not initialized");
      }
      return w;
    }

    async loadWasm() {
      if (this.wasm) return this.wasm;
      if (this._wasmLoadingPromise) return this._wasmLoadingPromise;

      this._wasmLoadingPromise = (async () => {
        const GoCtor = this.config.Go || rootScope.Go;
        const fetchFn = this.config.fetch || rootScope.fetch;
        const wasmAPI = this.config.WebAssembly || rootScope.WebAssembly;
        if (!GoCtor || !wasmAPI) {
          throw new Error("WebAssembly runtime or Go constructor unavailable");
        }
        const go = new GoCtor();
        let instance;
        const bootstrap = rootScope.__COTILLA_BOOTSTRAP__;
        if (bootstrap && bootstrap.wasmModule) {
          instance = await wasmAPI.instantiate(bootstrap.wasmModule, go.importObject);
        } else if (bootstrap && bootstrap.wasmBytes) {
          const res = await wasmAPI.instantiate(bootstrap.wasmBytes, go.importObject);
          instance = res.instance;
        } else if (this.config.wasmBytes) {
          const res = await wasmAPI.instantiate(this.config.wasmBytes, go.importObject);
          instance = res.instance;
        } else {
          if (!fetchFn) throw new Error("fetch API unavailable to load wasmUrl");
          const resp = await fetchFn(this.config.wasmUrl);
          const res = await wasmAPI.instantiateStreaming(resp, go.importObject);
          instance = res.instance;
        }
        go.run(instance);
        while (!rootScope.cotilla) {
          await new Promise((r) => setTimeout(r, 20));
        }
        this.wasm = rootScope.cotilla;
        return this.wasm;
      })();

      try {
        return await this._wasmLoadingPromise;
      } catch (err) {
        this._wasmLoadingPromise = null;
        throw err;
      }
    }

    _getOrCreateIdentitySeed() {
      const storage = this.config.storage;
      let seed = storage ? storage.getItem("cotilla.seed") : null;
      if (!seed) {
        const cryptoAPI = this.config.crypto || rootScope.crypto;
        const buf = new Uint8Array(32);
        cryptoAPI.getRandomValues(buf);
        seed = [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
        if (storage) storage.setItem("cotilla.seed", seed);
      }
      return seed;
    }

    _resolveSignalingUrl() {
      const url = typeof this.config.signalingUrl === "function"
        ? this.config.signalingUrl()
        : this.config.signalingUrl;
      if (!url) {
        throw new Error("CotillaClient missing required configuration: signalingUrl");
      }
      return url;
    }

    // ---- Room & Invite Lifecycle ----

    async createRoom(ttlMs = 15 * 60 * 1000) {
      const wasm = await this.loadWasm();
      const res = parseCotillaJSON(wasm.createRoom());
      await this.startSession(res.roomID, res.roomKey, null, true);
      const data = this.getInviteData(ttlMs);
      return {
        roomID: res.roomID,
        roomKey: res.roomKey,
        invite: data.invite,
        hash: data.hash,
        url: data.url,
      };
    }

    async joinRoomFromLink(linkOrHash) {
      const parsed = CotillaClient.parseLink(linkOrHash);
      if (!parsed) {
        throw new Error("Invalid room link or parameters. Expected format: #room=<uuid>&key=<key>");
      }
      await this.startSession(parsed.room, parsed.key, parsed.invite || null, false);
      const hash = CotillaClient.buildHash(parsed.room, parsed.key, parsed.invite);
      const base = this.config.getBaseUrl ? this.config.getBaseUrl() : "";
      return {
        roomID: parsed.room,
        roomKey: parsed.key,
        invite: parsed.invite || null,
        hash,
        url: `${base}${hash}`,
      };
    }

    getInviteData(ttlMs = 15 * 60 * 1000) {
      if (!this.roomID || !this.roomKey) {
        throw new Error("No active room session");
      }
      const wasm = this._wasm();
      const base = this.config.getBaseUrl ? this.config.getBaseUrl() : "";
      let invite = null;
      let hash = CotillaClient.buildHash(this.roomID, this.roomKey, null);
      if (wasm.createChannelInvite) {
        try {
          let inv = parseCotillaJSON(wasm.createChannelInvite(ttlMs));
          if (typeof inv === "string") inv = JSON.parse(inv);
          invite = inv;
          hash = CotillaClient.buildHash(inv.room_id || this.roomID, inv.room_key || this.roomKey, inv);
        } catch {}
      }
      return {
        invite,
        hash,
        url: `${base}${hash}`,
      };
    }

    _emitPeersChanged() {
      this._emit("peersChanged", {
        overlayPeers: this.overlayPeers,
        peers: this.peers,
        directPeers: this.directPeers,
      });
    }

    disconnectSignaling() {
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
      if (this.ws) {
        this.wsIntentionalClose = true;
        try { this.ws.close(); } catch {}
        this.ws = null;
      }
      this.wsRole = null;
      this.offeredRoots.clear();
      this.answeredRoots.clear();
    }

    leaveRoom() {
      const hadRoom = !!this.roomID;
      this._closeAllCalls();
      this.disconnectSignaling();
      this.overlayPeers.clear();
      this.peers.clear();
      this.directPeers.clear();
      this.roomID = null;
      this.roomKey = null;
      this.isCreator = false;
      this.isEvicted = false;
      this._lastSolicitAttemptAt = 0;

      const wasm = this.wasm || rootScope.cotilla;
      if (wasm && wasm.leaveRoom) {
        try { wasm.leaveRoom(); } catch {}
      }
      if (hadRoom) {
        this._emit("sessionLeft", {});
      }
    }

    async startSession(roomID, roomKey, invite = null, isCreator = false) {
      const wasm = await this.loadWasm();
      this.leaveRoom();

      this.roomID = roomID;
      this.roomKey = roomKey;
      this.isCreator = !!isCreator;
      this.isEvicted = false;

      const seed = this._getOrCreateIdentitySeed();
      this.me = parseCotillaJSON(wasm.init(seed));

      parseCotillaJSON(wasm.joinRoom(roomID, roomKey, !!isCreator));
      if (invite && wasm.setChannelInvite) {
        wasm.setChannelInvite(JSON.stringify(invite));
      }

      const boot = rootScope.__COTILLA_BOOTSTRAP__;
      if (boot && boot.manifest && boot.bundleBytes && wasm.registerAppBundle) {
        try {
          const manifestStr = typeof boot.manifest === "string" ? boot.manifest : JSON.stringify(boot.manifest);
          wasm.registerAppBundle(manifestStr, boot.bundleBytes, boot.distRoomID || "", boot.distRoomKey || "", boot.pinnedPubKeyHex || "");
          this._emit("appSeedingActive", { appID: boot.manifest.app_id, version: boot.manifest.version, seq: boot.manifest.seq });
        } catch (err) {
          console.warn("failed to register bootstrap bundle for swarm seeding:", err);
        }
      }

      this._bindWasmHooks(wasm);
      this._emit("sessionStarted", {
        roomID: this.roomID,
        roomKey: this.roomKey,
        me: this.me,
        isCreator: this.isCreator,
        invite: invite || null,
      });
      this._emitPeersChanged();

      this.connectSignaling();
    }

    _bindWasmHooks(wasm) {
      wasm.setOnMessage((envJSON, plaintext) => {
        try {
          const env = JSON.parse(envJSON);
          const data = JSON.parse(plaintext);
          this._emit("message", {
            author: env.author_pub_key,
            text: data.text || plaintext,
            ts: env.timestamp || Date.now(),
            envelope: env,
          });
        } catch {
          this._emit("message", {
            author: "peer",
            text: plaintext,
            ts: Date.now(),
            envelope: null,
          });
        }
      });

      if (wasm.setOnAttachmentOffer) {
        wasm.setOnAttachmentOffer((metaJSON) => {
          try {
            const meta = JSON.parse(metaJSON);
            this._emit("attachmentOffer", { meta });
          } catch (err) {
            console.error("attachment offer error", err);
          }
        });
      }

      if (wasm.setOnAttachmentProgress) {
        wasm.setOnAttachmentProgress((fileID, received, total) => {
          this._emit("attachmentProgress", { fileID, received, total });
        });
      }

      wasm.setOnAttachment((metaJSON) => {
        try {
          const meta = JSON.parse(metaJSON);
          this._emit("attachment", { meta });
        } catch (err) {
          console.error("attachment error", err);
        }
      });

      if (wasm.setOnCallPresence) {
        wasm.setOnCallPresence((scopeID, isDM, from, payJSON) => {
          try {
            const payload = JSON.parse(payJSON);
            this._handleCallPresence(scopeID, !!isDM, from, payload);
          } catch (err) {
            console.warn("callPresence parse error", err);
          }
        });
      }

      if (wasm.setOnCallSignal) {
        wasm.setOnCallSignal((sigJSON) => {
          try {
            const sig = JSON.parse(sigJSON);
            this._handleCallSignal(sig).catch((err) => {
              console.warn("callSignal error", err);
            });
          } catch (err) {
            console.warn("callSignal parse error", err);
          }
        });
      }

      if (wasm.setOnSFrameKeysUpdated) {
        wasm.setOnSFrameKeysUpdated((scopeID, isDM, bundle) => {
          if (bundle) {
            this._installBundleInWorker(scopeID, bundle).catch((err) => {
              console.warn("sframe key update failed", err);
            });
            this._emit("sframeKeysUpdated", { scopeID, isDM: !!isDM, epoch: bundle.epoch });
          }
        });
      }

      if (wasm.setOnCallPeerClosed) {
        wasm.setOnCallPeerClosed((scopeID, peerAddr) => {
          if (!peerAddr) {
            this._closeScopeCall(scopeID);
          } else {
            this._revokeAndCloseCallPeer(scopeID, peerAddr);
          }
          this._emit("callPeerClosed", { scopeID, peerAddr });
        });
      }

      if (wasm.setOnDirectInvite) {
        wasm.setOnDirectInvite((invJSON, payJSON) => {
          try {
            const inv = JSON.parse(invJSON);
            const pay = JSON.parse(payJSON);
            this._emit("directInvite", { raw: invJSON, inv, pay });
          } catch (err) {
            console.error("direct invite callback error", err);
          }
        });
      }

      if (wasm.setOnInviteResponse) {
        wasm.setOnInviteResponse((resJSON) => {
          try {
            const res = JSON.parse(resJSON);
            this._emit("inviteResponse", { res });
          } catch (err) {
            console.error("invite response callback error", err);
          }
        });
      }

      if (wasm.setOnDMMessage) {
        wasm.setOnDMMessage((author, roomID, text) => {
          this._emit("dmMessage", { author, roomID, text, ts: Date.now() });
        });
      }

      wasm.setOnPeerJoined((addr) => {
        if (addr && (!this.me || addr !== this.me.address)) {
          this.overlayPeers.add(addr);
          this._emit("peerJoined", { addr });
          this._emitPeersChanged();
        }
      });

      wasm.setOnPeerLeft((addr) => {
        this.overlayPeers.delete(addr);
        this.peers.delete(addr);
        this.directPeers.delete(addr);
        this._closePeerAcrossAllCalls(addr);
        this._emit("peerLeft", { addr });
        this._emitPeersChanged();
        if (this.overlayPeers.size === 0 && !this.ws && this.roomID && !this.isEvicted) {
          if (wasm.hasGatewayConn && wasm.hasGatewayConn()) {
            if (wasm.queryPeers) wasm.queryPeers();
            return;
          }
          this.connectSignaling();
        }
      });

      if (wasm.setOnMemberEvicted) {
        wasm.setOnMemberEvicted((evictedPeer, evictor, reason, epochID) => {
          const selfEvicted = !!(this.me && evictedPeer === this.me.address);
          if (selfEvicted) {
            this.isEvicted = true;
            // Self-eviction revokes group call access immediately, leaving unrelated 1:1 DM calls untouched.
            if (this.roomID) {
              this._closeScopeCall(this.roomID);
            }
            this.disconnectSignaling();
            this.overlayPeers.clear();
            this.peers.clear();
            this.directPeers.clear();
            if (wasm.leaveRoom) {
              try { wasm.leaveRoom(); } catch {}
            }
          } else {
            this.peers.delete(evictedPeer);
            this.directPeers.delete(evictedPeer);
            if (this.roomID) {
              this._revokeAndCloseCallPeer(this.roomID, evictedPeer);
            }
          }
          this._emit("memberEvicted", { evictedPeer, evictor, reason, epochID, selfEvicted });
          this._emitPeersChanged();
        });
      }

      if (wasm.setOnEpochCommit) {
        wasm.setOnEpochCommit((commitJSON) => {
          try {
            const commit = JSON.parse(commitJSON);
            this._emit("epochCommit", { commit });
          } catch {}
        });
      }

      if (wasm.setOnAnchorIntro) {
        wasm.setOnAnchorIntro((anchorsJSON, fallback) => {
          let anchors = [];
          try { anchors = JSON.parse(anchorsJSON); } catch {}
          this._emit("anchorIntro", { anchors, fallback });
          this._emit("status", {
            online: true,
            text: fallback ? "preservation fallback mode" : `mesh active (${anchors.length} anchors)`,
          });
        });
      }

      if (wasm.setOnAnchorDeficit) {
        wasm.setOnAnchorDeficit((currentAnchors, activePeers) => {
          if (this.isEvicted || !this.roomID) return;
          this._emit("anchorDeficit", { currentAnchors, activePeers });
          if (wasm.hasGatewayConn && wasm.hasGatewayConn()) {
            if (wasm.queryPeers) wasm.queryPeers();
            return;
          }
          this.connectSignaling();
        });
      }

      if (wasm.setOnAnchorSolicit) {
        wasm.setOnAnchorSolicit((needed) => {
          if (this.isEvicted || !this.roomID) return;
          if (wasm.hasGatewayConn && wasm.hasGatewayConn()) {
            if (wasm.queryPeers) wasm.queryPeers();
            return;
          }
          const WSCtor = this.config.WebSocket || rootScope.WebSocket;
          const wsOpen = this.ws && WSCtor && (this.ws.readyState === WSCtor.OPEN || this.ws.readyState === WSCtor.CONNECTING);
          if (wsOpen) return;
          const now = Date.now();
          if (now - this._lastSolicitAttemptAt < 1500) return;
          this._lastSolicitAttemptAt = now;
          this._emit("anchorSolicit", { needed });
          this.connectSignaling();
        });
      }

      if (wasm.setOnChannelDiscovered) {
        wasm.setOnChannelDiscovered((channelID, peer) => {
          if ((!channelID || channelID === this.roomID) && this.me && peer !== this.me.address) {
            this.peers.add(peer);
            if (this.overlayPeers.has(peer)) {
              this.directPeers.add(peer);
            }
            this._emit("channelDiscovered", { channelID, peer });
            this._emitPeersChanged();
          }
        });
      }

      wasm.setOnOpen((addr) => {
        if (this.isEvicted) return;
        if (this.reconnectTimer) {
          clearTimeout(this.reconnectTimer);
          this.reconnectTimer = null;
        }
        if (wasm.isGatewayPeer && wasm.isGatewayPeer(addr)) {
          if (wasm.addGatewayPeer) wasm.addGatewayPeer(addr);
          if (wasm.addPeer) wasm.addPeer(addr);
          if (wasm.queryPeers) wasm.queryPeers();
          this._emit("open", { addr });
          this._emitPeersChanged();
          if (this.overlayPeers.size === 0) {
            this._emit("status", { online: true, text: "connected to gateway (discovering peers)..." });
          }
          return;
        }
        this.overlayPeers.add(addr);
        if (this.peers.has(addr)) {
          this.directPeers.add(addr);
        }
        if (wasm.addPeer) wasm.addPeer(addr);
        if (wasm.requestCatchUp) wasm.requestCatchUp();
        if (wasm.joinChannel) wasm.joinChannel(this.roomID);
        this._emit("open", { addr });
        this._emitPeersChanged();
        const count = this.directPeers.size > 0 ? this.directPeers.size : this.overlayPeers.size;
        this._emit("status", { online: true, text: `connected (${count} peer${count === 1 ? "" : "s"})` });
      });
    }

    // ---- Signaling WebSocket (WebRTC Negotiation & Root Replenishment Only) ----

    connectSignaling() {
      if (this.isEvicted || !this.roomID) return;
      const wasm = this._wasm();
      if (wasm && wasm.hasGatewayConn && wasm.hasGatewayConn()) {
        if (wasm.queryPeers) wasm.queryPeers();
        return;
      }
      const WSCtor = this.config.WebSocket || rootScope.WebSocket;
      if (!WSCtor) {
        throw new Error("WebSocket implementation unavailable");
      }
      if (this.ws && (this.ws.readyState === WSCtor.OPEN || this.ws.readyState === WSCtor.CONNECTING)) {
        return;
      }
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }

      const signalingUrl = this._resolveSignalingUrl();
      const ws = new WSCtor(signalingUrl);
      this.ws = ws;
      this.wsIntentionalClose = false;

      ws.onopen = () => {
        this._emit("status", {
          online: this.overlayPeers.size > 0,
          text: "registering with signaling...",
        });
        try {
          const wasm = this._wasm();
          const regMsg = parseCotillaJSON(wasm.signSignaling("register", "", ""));
          this._wsSend(ws, regMsg);
        } catch (err) {
          console.error("failed to sign register message:", err);
        }
      };

      ws.onclose = () => {
        const intentional = this.wsIntentionalClose;
        if (this.ws === ws) {
          this.ws = null;
        }
        if (this.overlayPeers.size > 0) {
          const count = this.directPeers.size > 0 ? this.directPeers.size : this.overlayPeers.size;
          this._emit("status", { online: true, text: `mesh active (${count} peers)` });
          return;
        }
        if (intentional && this.roomID && !this.isEvicted) {
          this._emit("status", { online: true, text: "establishing WebRTC mesh..." });
          if (!this.reconnectTimer) {
            this.reconnectTimer = setTimeout(() => {
              this.reconnectTimer = null;
              const wasm = this._wasm();
              if (wasm && wasm.hasGatewayConn && wasm.hasGatewayConn()) {
                if (wasm.queryPeers) wasm.queryPeers();
                return;
              }
              if (this.overlayPeers.size === 0 && !this.ws && this.roomID && !this.isEvicted) {
                this.connectSignaling();
              }
            }, 5000);
          }
          return;
        }
        this._emit("status", { online: false, text: "reconnecting..." });
        if (!intentional && this.roomID && !this.isEvicted && !this.reconnectTimer) {
          this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            const wasm = this._wasm();
            if (wasm && wasm.hasGatewayConn && wasm.hasGatewayConn()) {
              if (wasm.queryPeers) wasm.queryPeers();
              return;
            }
            this.connectSignaling();
          }, 2000);
        }
      };

      ws.onmessage = async (ev) => {
        let msg;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          return;
        }
        if (msg.error) {
          console.warn("signaling server error:", msg.error);
          return;
        }

        const wasm = this._wasm();
        if (msg.type === "offer") {
          if (!wasm.verifySignaling || !wasm.verifySignaling(ev.data)) {
            console.warn("dropped unauthenticated or invalid signaling offer from", msg.peer);
            return;
          }
          if (wasm.addGatewayPeer) {
            wasm.addGatewayPeer(msg.peer);
          }
          const rawAnswerSDP = await wasm.acceptOffer(msg.peer, msg.sdp);
          const answerMsg = parseCotillaJSON(wasm.signSignaling("answer", msg.peer, rawAnswerSDP));
          this._wsSend(ws, answerMsg);
          return;
        }

        if (msg.type === "ok") {
          this.wsIntentionalClose = true;
          const activeWS = ws || this.ws;
          if (activeWS) {
            try { activeWS.close(); } catch {}
          }
          if (this.ws === activeWS) {
            this.ws = null;
          }
          return;
        }
      };
    }

    _wsSend(ws, obj) {
      const targetWS = ws || this.ws;
      const WSCtor = this.config.WebSocket || rootScope.WebSocket;
      if (targetWS && WSCtor && targetWS.readyState === WSCtor.OPEN) {
        targetWS.send(JSON.stringify(obj));
      }
    }

    // ---- Protocol Operations (Chat, DMs, Attachments, Media, Key/Member Control) ----

    sendMessage(text) {
      return parseCotillaJSON(this._wasm().sendMessage(text));
    }

    sendDirectInvite(peer, kind = "dm", title = "Private Chat") {
      return parseCotillaJSON(this._wasm().sendDirectInvite(peer, kind, title));
    }

    respondDirectInvite(rawInviteJSON, accept) {
      return parseCotillaJSON(this._wasm().respondDirectInvite(rawInviteJSON, !!accept));
    }

    registerDMSession(roomID, roomKey, peerAddr = "") {
      const wasm = this._wasm();
      if (wasm.registerDMSession) {
        return parseCotillaJSON(wasm.registerDMSession(roomID, roomKey, peerAddr || ""));
      }
      return null;
    }

    sendDMMessage(peer, roomID, roomKey, text) {
      const wasm = this._wasm();
      if (!wasm.sendDMMessage) {
        throw new Error("sendDMMessage unavailable in WASM runtime");
      }
      return parseCotillaJSON(wasm.sendDMMessage(peer, roomID, roomKey, text));
    }

    shareAttachment(name, mimeType, bytesUint8) {
      return parseCotillaJSON(this._wasm().shareAttachment(name, mimeType || "application/octet-stream", bytesUint8));
    }

    downloadAttachment(fileID) {
      const wasm = this._wasm();
      if (wasm.downloadAttachment) {
        return wasm.downloadAttachment(fileID);
      }
      return null;
    }

    getAttachmentData(fileID) {
      const wasm = this._wasm();
      if (wasm.getAttachmentData) {
        return wasm.getAttachmentData(fileID);
      }
      return null;
    }

    // ---- Scoped Secondary WebRTC A/V Calls (SFrame RFC 9605 + MLS-Exporter) ----

    _ensureSFrameWorker() {
      if (this.sframeWorker) {
        return this.sframeWorker;
      }
      let w = null;
      if (typeof this.config.createSFrameWorker === "function") {
        w = this.config.createSFrameWorker();
      } else if (rootScope.__COTILLA_BOOTSTRAP__ && typeof rootScope.__COTILLA_BOOTSTRAP__.createSFrameWorker === "function") {
        w = rootScope.__COTILLA_BOOTSTRAP__.createSFrameWorker();
      } else {
        const WorkerCtor = this.config.Worker || rootScope.Worker;
        if (!WorkerCtor) {
          return null;
        }
        let workerUrl = this.config.sframeWorkerUrl;
        const sframeSrc = this.config.sframeWorkerSource || (rootScope.__COTILLA_BOOTSTRAP__ && rootScope.__COTILLA_BOOTSTRAP__.sframeWorkerSource);
        if (sframeSrc && typeof Blob !== "undefined" && typeof URL !== "undefined" && typeof URL.createObjectURL === "function") {
          const blob = new Blob([sframeSrc], { type: "application/javascript" });
          workerUrl = URL.createObjectURL(blob);
        }
        w = new WorkerCtor(workerUrl);
      }
      if (!w) return null;
      w.onmessage = (ev) => {
        const msg = ev && ev.data;
        if (!msg || typeof msg !== "object") return;
        if (msg.type === "ack" && msg.requestId && this._workerAcks.has(msg.requestId)) {
          const handler = this._workerAcks.get(msg.requestId);
          this._workerAcks.delete(msg.requestId);
          handler(msg);
        } else if (msg.type === "stats" && msg.requestId && this._workerStatsResolvers.has(msg.requestId)) {
          const resolve = this._workerStatsResolvers.get(msg.requestId);
          this._workerStatsResolvers.delete(msg.requestId);
          resolve(msg.stats || {});
        }
      };
      this.sframeWorker = w;
      return w;
    }

    _installBundleInWorker(scopeID, bundle, graceMs = 3000) {
      const worker = this._ensureSFrameWorker();
      if (!worker || !bundle) {
        return Promise.resolve();
      }
      const requestId = ++this._workerReqSeq;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          this._workerAcks.delete(requestId);
          resolve();
        }, 2000);
        this._workerAcks.set(requestId, (msg) => {
          clearTimeout(timer);
          if (msg && msg.error) {
            reject(new Error(msg.error));
            return;
          }
          resolve();
        });
        worker.postMessage({ type: "installBundle", requestId, scopeID, bundle, graceMs });
      });
    }

    async joinCall(scopeID, isDM = false, opts = {}) {
      if (!scopeID) {
        throw new Error("joinCall requires scopeID");
      }
      if (rootScope.isSecureContext === false || (rootScope.crypto && !rootScope.crypto.subtle)) {
        throw new Error("Encrypted voice & video calls require HTTPS or localhost (WebCrypto SubtleCrypto is unavailable on insecure HTTP origins).");
      }
      const wasm = this._wasm();
      const normOpts = {
        listenOnly: !!opts.listenOnly,
        audio: !!opts.audio && !opts.listenOnly,
        video: !!opts.video && !opts.listenOnly,
        screen: !!opts.screen && !opts.listenOnly,
      };
      this._ensureSFrameWorker();
      const res = wasm.joinCall(scopeID, !!isDM, normOpts);
      if (res && res.error) {
        throw new Error(res.error);
      }

      // Register activeCalls synchronously right after wasm.joinCall returns (before awaiting
      // the worker installBundle round-trip) so immediate inbound offers from already-joined
      // native/browser peers are never dropped while SFrame keys finish installing.
      let call = this.activeCalls.get(scopeID);
      if (!call) {
        call = {
          scopeID,
          isDM: !!isDM,
          opts: normOpts,
          peers: new Map(),
          bundleDone: true,
          bundlePromise: null,
        };
        this.activeCalls.set(scopeID, call);
      } else {
        call.isDM = !!isDM;
        call.opts = normOpts;
      }

      if (res && res.bundle) {
        call.bundleDone = false;
        const bundlePromise = this._installBundleInWorker(scopeID, res.bundle).then(() => {
          call.bundleDone = true;
        });
        call.bundlePromise = bundlePromise;
        await bundlePromise;
      }
      if (this.activeCalls.get(scopeID) !== call) {
        return res;
      }

      if (wasm.activeCallPeers) {
        const roster = parseCotillaJSON(wasm.activeCallPeers(scopeID)) || [];
        for (const p of roster) {
          if (!p || !p.address || (this.me && p.address === this.me.address)) continue;
          call.peers.set(p.address, p);
          if (this.me && this.me.address < p.address && !this._hasCallPeer(scopeID, p.address)) {
            this._initiateCallOffer(scopeID, p.address).catch((err) => {
              console.warn("call offer init error", err);
            });
          }
        }
      }

      await this._syncLocalTracksForScope(scopeID);
      this._emit("callJoined", { scopeID, isDM: !!isDM, opts: { ...normOpts } });
      return res;
    }

    async updateCallOptions(scopeID, opts = {}) {
      const call = this.activeCalls.get(scopeID);
      if (!call) return null;
      const normOpts = {
        listenOnly: !!opts.listenOnly,
        audio: !!opts.audio && !opts.listenOnly,
        video: !!opts.video && !opts.listenOnly,
        screen: !!opts.screen && !opts.listenOnly,
      };
      call.opts = normOpts;
      const wasm = this._wasm();
      let res = null;
      if (wasm.updateCallOptions) {
        res = parseCotillaJSON(wasm.updateCallOptions(scopeID, JSON.stringify(normOpts)));
      }
      await this._syncLocalTracksForScope(scopeID);
      return res;
    }

    leaveCall(scopeID) {
      this._closeScopeCall(scopeID);
      const wasm = this.wasm || rootScope.cotilla;
      let res = null;
      if (wasm && wasm.leaveCall) {
        try {
          res = parseCotillaJSON(wasm.leaveCall(scopeID));
        } catch {}
      }
      this._emit("callLeft", { scopeID });
      return res;
    }

    async setLocalMediaTracks({ audioTrack, videoTrack, videoKind } = {}) {
      if (audioTrack !== undefined) {
        this._localAudioTrack = audioTrack || null;
      }
      if (videoTrack !== undefined) {
        this._localVideoTrack = videoTrack || null;
        this._localVideoKind = videoKind || null;
      }
      for (const scopeID of this.activeCalls.keys()) {
        await this._syncLocalTracksForScope(scopeID);
      }
    }

    async _syncLocalTracksForScope(scopeID) {
      const call = this.activeCalls.get(scopeID);
      if (!call) return;
      const wantAudio = !call.opts.listenOnly && !!call.opts.audio && this._localAudioTrack ? this._localAudioTrack : null;
      const wantVideo = !call.opts.listenOnly && (!!call.opts.video || !!call.opts.screen) && this._localVideoTrack ? this._localVideoTrack : null;

      for (const entry of this.callPCs.values()) {
        if (entry.scopeID !== scopeID || entry.closed) continue;
        if (entry.audioSender && typeof entry.audioSender.replaceTrack === "function") {
          try {
            await entry.audioSender.replaceTrack(wantAudio);
            await this._applyAudioSenderParameters(entry.audioSender);
          } catch {}
        }
        if (entry.videoSender && typeof entry.videoSender.replaceTrack === "function") {
          try { await entry.videoSender.replaceTrack(wantVideo); } catch {}
        }
      }
    }

    _callKey(scopeID, peerAddr) {
      return `${scopeID}::${peerAddr}`;
    }

    _hasCallPeer(scopeID, peerAddr) {
      const entry = this.callPCs.get(this._callKey(scopeID, peerAddr));
      return !!(entry && !entry.closed && entry.pc && entry.pc.connectionState !== "failed" && entry.pc.connectionState !== "closed");
    }

    _attachSFrameTransform(entry, rtpObject, direction, mediaKind) {
      if (!rtpObject || entry.attachedTransforms.has(rtpObject)) {
        return;
      }
      const worker = this._ensureSFrameWorker();
      if (!worker) {
        return;
      }
      entry.attachedTransforms.add(rtpObject);

      const TransformCtor = this.config.RTCRtpScriptTransform || rootScope.RTCRtpScriptTransform;
      const opts = {
        scopeID: entry.scopeID,
        peerAddr: entry.peerAddr,
        direction,
        mediaKind,
      };
      if (typeof TransformCtor === "function" && "transform" in rtpObject) {
        rtpObject.transform = new TransformCtor(worker, opts);
        return;
      }
      if (typeof rtpObject.createEncodedStreams === "function") {
        const { readable, writable } = rtpObject.createEncodedStreams();
        worker.postMessage(
          { type: "attachStreams", readable, writable, ...opts },
          [readable, writable]
        );
      }
    }

    _applyCodecPreferences(pc) {
      const SenderCtor = rootScope.RTCRtpSender;
      if (!SenderCtor || typeof SenderCtor.getCapabilities !== "function") {
        return;
      }
      const transceivers = pc.getTransceivers ? pc.getTransceivers() : [];
      for (const t of transceivers) {
        if (!t || typeof t.setCodecPreferences !== "function") continue;
        const kind = (t.sender && t.sender.track && t.sender.track.kind) ||
          (t.receiver && t.receiver.track && t.receiver.track.kind) || "";
        if (kind === "video") {
          const caps = SenderCtor.getCapabilities("video");
          if (caps && Array.isArray(caps.codecs)) {
            const vp8 = caps.codecs.filter((c) => {
              const m = (c.mimeType || "").toLowerCase();
              return m === "video/vp8" || (m === "video/rtx" && String(c.sdpFmtpLine || "").includes("apt="));
            });
            const vp8Only = caps.codecs.filter((c) => (c.mimeType || "").toLowerCase() === "video/vp8");
            const chosen = vp8Only.length > 0 ? vp8Only : vp8;
            if (chosen.length > 0) {
              try { t.setCodecPreferences(chosen); } catch {}
            }
          }
        } else if (kind === "audio") {
          const caps = SenderCtor.getCapabilities("audio");
          if (caps && Array.isArray(caps.codecs)) {
            const opus = caps.codecs.filter((c) => (c.mimeType || "").toLowerCase() === "audio/opus");
            if (opus.length > 0) {
              try { t.setCodecPreferences(opus); } catch {}
            }
          }
        }
      }
    }

    async _applyAudioSenderParameters(sender) {
      if (!sender || typeof sender.getParameters !== "function" || typeof sender.setParameters !== "function") return;
      try {
        const params = sender.getParameters();
        if (params && Array.isArray(params.encodings) && params.encodings.length > 0) {
          if (params.encodings[0].maxBitrate === 64000) return;
          params.encodings[0].maxBitrate = 64000;
          await sender.setParameters(params);
        }
      } catch {}
    }

    _getOrCreateCallPC(scopeID, peerAddr, initTransceivers) {
      const key = this._callKey(scopeID, peerAddr);
      const existing = this.callPCs.get(key);
      if (existing && !existing.closed) {
        return existing;
      }

      const PCCtor = this.config.RTCPeerConnection || rootScope.RTCPeerConnection;
      if (!PCCtor) {
        throw new Error("RTCPeerConnection unavailable");
      }
      const TransformCtor = this.config.RTCRtpScriptTransform || rootScope.RTCRtpScriptTransform;
      const pcOpts = {
        iceServers: this.config.iceServers,
        bundlePolicy: "max-bundle",
      };
      if (typeof TransformCtor !== "function") {
        pcOpts.encodedInsertableStreams = true;
      }

      const pc = new PCCtor(pcOpts);
      const entry = {
        scopeID,
        peerAddr,
        pc,
        audioSender: null,
        videoSender: null,
        remoteStream: typeof rootScope.MediaStream === "function" ? new rootScope.MediaStream() : null,
        pendingCandidates: [],
        makingOffer: false,
        closed: false,
        attachedTransforms: new WeakSet(),
      };
      this.callPCs.set(key, entry);

      pc.onicecandidate = (ev) => {
        if (entry.closed || !ev || !ev.candidate) return;
        const candPayload = typeof ev.candidate.toJSON === "function"
          ? JSON.stringify(ev.candidate.toJSON())
          : JSON.stringify(ev.candidate);
        try {
          const wasm = this._wasm();
          if (wasm.sendCallSignal) {
            wasm.sendCallSignal(scopeID, peerAddr, "candidate", candPayload);
          }
        } catch {}
      };

      pc.onconnectionstatechange = () => {
        if (entry.closed) return;
        const st = pc.connectionState;
        this._emit("callPeerState", { scopeID, peerAddr, state: st });
        if (st === "failed" || st === "closed") {
          this._closeCallPeer(scopeID, peerAddr);
        }
      };

      pc.ontrack = (ev) => {
        if (entry.closed || !ev || !ev.track) return;
        const kind = ev.track.kind === "video" ? "video" : "audio";
        if (ev.receiver) {
          this._attachSFrameTransform(entry, ev.receiver, "decrypt", kind);
        }
        if (ev.transceiver && ev.transceiver.sender) {
          if (kind === "audio" && !entry.audioSender) {
            entry.audioSender = ev.transceiver.sender;
          } else if (kind === "video" && !entry.videoSender) {
            entry.videoSender = ev.transceiver.sender;
          }
          this._attachSFrameTransform(entry, ev.transceiver.sender, "encrypt", kind);
        }
        if (entry.remoteStream) {
          const exists = entry.remoteStream.getTracks().some((t) => t.id === ev.track.id);
          if (!exists) {
            entry.remoteStream.addTrack(ev.track);
          }
        }
        this._emit("callRemoteTrack", {
          scopeID,
          peerAddr,
          kind,
          track: ev.track,
          stream: entry.remoteStream,
          streams: ev.streams || [],
        });
      };

      if (initTransceivers && typeof pc.addTransceiver === "function") {
        const call = this.activeCalls.get(scopeID);
        const sendAudio = call && !call.opts.listenOnly && call.opts.audio && this._localAudioTrack ? this._localAudioTrack : null;
        const sendVideo = call && !call.opts.listenOnly && (call.opts.video || call.opts.screen) && this._localVideoTrack ? this._localVideoTrack : null;

        const audioTr = pc.addTransceiver(sendAudio || "audio", {
          direction: "sendrecv",
          sendEncodings: [{ maxBitrate: 64000 }],
        });
        const videoTr = pc.addTransceiver(sendVideo || "video", { direction: "sendrecv" });
        entry.audioSender = audioTr.sender;
        entry.videoSender = videoTr.sender;
        this._attachSFrameTransform(entry, audioTr.sender, "encrypt", "audio");
        this._attachSFrameTransform(entry, audioTr.receiver, "decrypt", "audio");
        this._attachSFrameTransform(entry, videoTr.sender, "encrypt", "video");
        this._attachSFrameTransform(entry, videoTr.receiver, "decrypt", "video");
        this._applyCodecPreferences(pc);
      }

      return entry;
    }

    _wireAnswererTransceivers(entry) {
      const pc = entry.pc;
      const transceivers = pc.getTransceivers ? pc.getTransceivers() : [];
      const call = this.activeCalls.get(entry.scopeID);
      const sendAudio = call && !call.opts.listenOnly && call.opts.audio && this._localAudioTrack ? this._localAudioTrack : null;
      const sendVideo = call && !call.opts.listenOnly && (call.opts.video || call.opts.screen) && this._localVideoTrack ? this._localVideoTrack : null;

      for (const tr of transceivers) {
        if (!tr) continue;
        const kind = (tr.receiver && tr.receiver.track && tr.receiver.track.kind) ||
          (tr.sender && tr.sender.track && tr.sender.track.kind) ||
          (tr.mid && String(tr.mid).includes("1") ? "video" : "audio");
        tr.direction = "sendrecv";
        if (kind === "audio") {
          entry.audioSender = tr.sender;
          this._attachSFrameTransform(entry, tr.sender, "encrypt", "audio");
          this._attachSFrameTransform(entry, tr.receiver, "decrypt", "audio");
          if (tr.sender && typeof tr.sender.replaceTrack === "function") {
            tr.sender.replaceTrack(sendAudio).catch(() => {});
          }
        } else if (kind === "video") {
          entry.videoSender = tr.sender;
          this._attachSFrameTransform(entry, tr.sender, "encrypt", "video");
          this._attachSFrameTransform(entry, tr.receiver, "decrypt", "video");
          if (tr.sender && typeof tr.sender.replaceTrack === "function") {
            tr.sender.replaceTrack(sendVideo).catch(() => {});
          }
        }
      }
      this._applyCodecPreferences(pc);
    }

    async _initiateCallOffer(scopeID, peerAddr) {
      const call = this.activeCalls.get(scopeID);
      if (!call || this.isEvicted) return;
      if (call.bundlePromise && !call.bundleDone) {
        await call.bundlePromise;
      }
      if (!this.activeCalls.has(scopeID) || this.isEvicted || this._hasCallPeer(scopeID, peerAddr)) return;
      const entry = this._getOrCreateCallPC(scopeID, peerAddr, true);
      if (entry.closed) return;
      entry.makingOffer = true;
      try {
        const offer = await entry.pc.createOffer();
        if (entry.closed) return;
        await entry.pc.setLocalDescription(offer);
        const sdpStr = entry.pc.localDescription ? entry.pc.localDescription.sdp : offer.sdp;
        const wasm = this._wasm();
        if (wasm.sendCallSignal) {
          parseCotillaJSON(wasm.sendCallSignal(scopeID, peerAddr, "offer", sdpStr));
        }
      } finally {
        entry.makingOffer = false;
      }
    }

    _handleCallPresence(scopeID, isDM, from, payload) {
      this._emit("callPresence", { scopeID, isDM, from, payload });
      const call = this.activeCalls.get(scopeID);
      if (!call || !from || (this.me && from === this.me.address) || !payload) {
        return;
      }
      if (payload.action === "leave") {
        call.peers.delete(from);
        this._closeCallPeer(scopeID, from);
        this._emit("callPeerLeft", { scopeID, peerAddr: from });
        return;
      }
      call.peers.set(from, payload);
      if (this.me && this.me.address < from && !this._hasCallPeer(scopeID, from)) {
        this._initiateCallOffer(scopeID, from).catch((err) => {
          console.warn("call offer error for", from, err);
        });
      }
    }

    async _handleCallSignal(sig) {
      if (!sig || !sig.scope_id || !sig.from || (this.me && sig.from === this.me.address)) {
        return;
      }
      const scopeID = sig.scope_id;
      const from = sig.from;
      // Strict scoping: ignore call offers/signals for scopes where user has not joined a call.
      if (!this.activeCalls.has(scopeID)) {
        return;
      }
      const key = this._callKey(scopeID, from);
      const prev = this._callSignalQueues.get(key);
      const task = prev
        ? prev.catch(() => {}).then(() => this._processCallSignal(sig))
        : this._processCallSignal(sig);
      this._callSignalQueues.set(key, task);
      try {
        await task;
      } finally {
        if (this._callSignalQueues.get(key) === task) {
          this._callSignalQueues.delete(key);
        }
      }
    }

    async _processCallSignal(sig) {
      const scopeID = sig.scope_id;
      const from = sig.from;
      const call = this.activeCalls.get(scopeID);
      if (!call) {
        return;
      }
      if (call.bundlePromise && !call.bundleDone) {
        await call.bundlePromise;
      }
      if (!this.activeCalls.has(scopeID)) {
        return;
      }

      if (sig.kind === "bye") {
        this._closeCallPeer(scopeID, from);
        return;
      }

      if (sig.kind === "offer") {
        const polite = !this.me || this.me.address > from;
        let entry = this.callPCs.get(this._callKey(scopeID, from));
        if (entry && !entry.closed && (entry.makingOffer || entry.pc.signalingState !== "stable")) {
          if (!polite) {
            return;
          }
          this._closeCallPeer(scopeID, from);
          entry = null;
        }
        if (!entry || entry.closed) {
          entry = this._getOrCreateCallPC(scopeID, from, false);
        }
        await entry.pc.setRemoteDescription({ type: "offer", sdp: sig.payload });
        this._wireAnswererTransceivers(entry);
        await this._flushPendingCandidates(entry);
        const answer = await entry.pc.createAnswer();
        if (entry.closed) return;
        await entry.pc.setLocalDescription(answer);
        await this._applyAudioSenderParameters(entry.audioSender);
        const sdpStr = entry.pc.localDescription ? entry.pc.localDescription.sdp : answer.sdp;
        const wasm = this._wasm();
        if (wasm.sendCallSignal) {
          parseCotillaJSON(wasm.sendCallSignal(scopeID, from, "answer", sdpStr));
        }
        return;
      }

      const entry = this.callPCs.get(this._callKey(scopeID, from));
      if (!entry || entry.closed) return;

      if (sig.kind === "answer") {
        await entry.pc.setRemoteDescription({ type: "answer", sdp: sig.payload });
        await this._applyAudioSenderParameters(entry.audioSender);
        await this._flushPendingCandidates(entry);
      } else if (sig.kind === "candidate") {
        let cand;
        try {
          cand = JSON.parse(sig.payload);
        } catch {
          return;
        }
        if (!entry.pc.remoteDescription) {
          entry.pendingCandidates.push(cand);
        } else {
          try { await entry.pc.addIceCandidate(cand); } catch {}
        }
      }
    }

    async _flushPendingCandidates(entry) {
      if (!entry || entry.closed || !entry.pc.remoteDescription) return;
      const list = entry.pendingCandidates.splice(0, entry.pendingCandidates.length);
      for (const cand of list) {
        try { await entry.pc.addIceCandidate(cand); } catch {}
      }
    }

    _closeCallPeer(scopeID, peerAddr) {
      const key = this._callKey(scopeID, peerAddr);
      const entry = this.callPCs.get(key);
      if (!entry) return;
      entry.closed = true;
      this.callPCs.delete(key);
      if (entry.pc) {
        try { entry.pc.close(); } catch {}
      }
      this._emit("callPeerRemoved", { scopeID, peerAddr });
    }

    _revokeAndCloseCallPeer(scopeID, peerAddr) {
      if (this.sframeWorker && peerAddr) {
        this.sframeWorker.postMessage({ type: "revokePeer", scopeID, peerAddr });
      }
      const call = this.activeCalls.get(scopeID);
      if (call) {
        call.peers.delete(peerAddr);
      }
      this._closeCallPeer(scopeID, peerAddr);
    }

    _closePeerAcrossAllCalls(peerAddr) {
      for (const [key, entry] of Array.from(this.callPCs.entries())) {
        if (entry.peerAddr === peerAddr) {
          this._closeCallPeer(entry.scopeID, peerAddr);
        }
      }
      for (const call of this.activeCalls.values()) {
        call.peers.delete(peerAddr);
      }
    }

    _closeScopeCall(scopeID) {
      this.activeCalls.delete(scopeID);
      for (const entry of Array.from(this.callPCs.values())) {
        if (entry.scopeID === scopeID) {
          this._closeCallPeer(scopeID, entry.peerAddr);
        }
      }
      if (this.sframeWorker) {
        this.sframeWorker.postMessage({ type: "purgeScope", scopeID });
      }
    }

    _closeAllCalls() {
      for (const scopeID of Array.from(this.activeCalls.keys())) {
        this._closeScopeCall(scopeID);
      }
      for (const entry of Array.from(this.callPCs.values())) {
        this._closeCallPeer(entry.scopeID, entry.peerAddr);
      }
    }

    async getCallStats() {
      let workerStats = { encryptedAudio: 0, encryptedVideo: 0, decryptedAudio: 0, decryptedVideo: 0, rejected: 0 };
      if (this.sframeWorker) {
        workerStats = await new Promise((resolve) => {
          const requestId = ++this._workerReqSeq;
          const timer = setTimeout(() => {
            this._workerStatsResolvers.delete(requestId);
            resolve(workerStats);
          }, 500);
          this._workerStatsResolvers.set(requestId, (st) => {
            clearTimeout(timer);
            resolve(st || workerStats);
          });
          this.sframeWorker.postMessage({ type: "getStats", requestId });
        });
      }

      const peers = [];
      for (const entry of this.callPCs.values()) {
        if (entry.closed) continue;
        let framesDecoded = 0;
        let framesSent = 0;
        let inboundAudioBytes = 0;
        let inboundVideoBytes = 0;
        if (entry.pc && typeof entry.pc.getStats === "function") {
          try {
            const report = await entry.pc.getStats();
            report.forEach((stat) => {
              if (stat.type === "inbound-rtp") {
                if (stat.kind === "video") {
                  framesDecoded += stat.framesDecoded || 0;
                  inboundVideoBytes += stat.bytesReceived || 0;
                } else if (stat.kind === "audio") {
                  inboundAudioBytes += stat.bytesReceived || 0;
                }
              } else if (stat.type === "outbound-rtp") {
                framesSent += stat.framesSent || 0;
              }
            });
          } catch {}
        }
        peers.push({
          scopeID: entry.scopeID,
          peerAddr: entry.peerAddr,
          state: entry.pc ? entry.pc.connectionState : "unknown",
          framesDecoded,
          framesSent,
          inboundAudioBytes,
          inboundVideoBytes,
        });
      }

      return {
        activeCallScopes: Array.from(this.activeCalls.keys()),
        secondaryPeerCount: peers.length,
        sframe: workerStats,
        peers,
      };
    }

    rotateEpochKey() {
      const wasm = this._wasm();
      if (!wasm.rotateEpochKey) {
        throw new Error("rotateEpochKey unavailable in WASM runtime");
      }
      return parseCotillaJSON(wasm.rotateEpochKey());
    }

    evictPeer(peer, reason) {
      const wasm = this._wasm();
      if (!wasm.evictPeer) {
        throw new Error("evictPeer unavailable in WASM runtime");
      }
      return parseCotillaJSON(wasm.evictPeer(peer, reason));
    }

    invitedBy(peer) {
      const wasm = this._wasm();
      return wasm.invitedBy ? wasm.invitedBy(peer) : "";
    }
  }

  CotillaClient.parseCotillaJSON = parseCotillaJSON;
  rootScope.CotillaClient = CotillaClient;

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { CotillaClient };
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
