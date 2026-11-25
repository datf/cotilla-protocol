// sframe-worker.js — Dedicated WebRTC Encoded Transform Worker for RFC 9605 SFrame
//
// Cipher suite: AES_128_GCM_SHA256_128 (0x0001)
// Keys & 64-bit KIDs are derived inside Go/WASM (pkg/cotilla/sframe.go) via MLS-Exporter
// and pushed here over MessagePort / postMessage using zero-copy Uint8Arrays.

"use strict";

const REPLAY_WINDOW = 128n;
const MASK_128 = (1n << 128n) - 1n;

// scopeID -> ScopeKeyState
const scopes = new Map();

// Serialize async SubtleCrypto importKey operations per scope while keeping revocations immediate.
const scopeOpQueues = new Map();

const stats = {
  encryptedAudio: 0,
  encryptedVideo: 0,
  decryptedAudio: 0,
  decryptedVideo: 0,
  rejected: 0,
  attached: {
    encryptAudio: 0,
    encryptVideo: 0,
    decryptAudio: 0,
    decryptVideo: 0,
  },
  pipeErrors: 0,
  lastPipeError: "",
  rejectReasons: {
    noTx: 0,
    encryptError: 0,
    badHeader: 0,
    noScope: 0,
    unknownKid: 0,
    expired: 0,
    peerMismatch: 0,
    replay: 0,
    keyRotated: 0,
    decryptError: 0,
  },
};

function readBigUint64BE(u8) {
  if (!u8 || u8.byteLength < 8) {
    throw new Error("sframe-worker: expected 8-byte kidBE");
  }
  const dv = new DataView(u8.buffer, u8.byteOffset, 8);
  return dv.getBigUint64(0, false);
}

function appendMinimalBE(val) {
  const buf = new Uint8Array(8);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, val, false);
  let start = 0;
  while (start < 7 && buf[start] === 0) {
    start++;
  }
  return buf.subarray(start);
}

function readMinimalBE(slice) {
  if (slice.length === 0 || slice.length > 8) {
    return null;
  }
  if (slice.length > 1 && slice[0] === 0) {
    return null;
  }
  const buf = new Uint8Array(8);
  buf.set(slice, 8 - slice.length);
  const dv = new DataView(buf.buffer);
  return dv.getBigUint64(0, false);
}

// Mirrors pkg/cotilla/sframe.go EncodeSFrameHeader byte-for-byte.
function encodeSFrameHeader(kid, ctr) {
  let cfg = 0;
  let kidBytes = null;
  let ctrBytes = null;

  if (kid <= 7n) {
    cfg |= Number(kid) << 4;
  } else {
    kidBytes = appendMinimalBE(kid);
    cfg |= 0x80 | ((kidBytes.length - 1) << 4);
  }

  if (ctr <= 7n) {
    cfg |= Number(ctr);
  } else {
    ctrBytes = appendMinimalBE(ctr);
    cfg |= 0x08 | (ctrBytes.length - 1);
  }

  const total = 1 + (kidBytes ? kidBytes.length : 0) + (ctrBytes ? ctrBytes.length : 0);
  const out = new Uint8Array(total);
  let off = 0;
  out[off++] = cfg;
  if (kidBytes) {
    out.set(kidBytes, off);
    off += kidBytes.length;
  }
  if (ctrBytes) {
    out.set(ctrBytes, off);
  }
  return out;
}

// Mirrors pkg/cotilla/sframe.go DecodeSFrameHeader byte-for-byte.
function decodeSFrameHeader(frame) {
  if (!frame || frame.byteLength < 1) {
    return null;
  }
  const cfg = frame[0];
  let off = 1;
  let kid;
  let ctr;

  if ((cfg & 0x80) !== 0) {
    const kLen = ((cfg >> 4) & 0x07) + 1;
    if (frame.byteLength < off + kLen) return null;
    kid = readMinimalBE(frame.subarray(off, off + kLen));
    if (kid === null || kid <= 7n) return null;
    off += kLen;
  } else {
    kid = BigInt((cfg >> 4) & 0x07);
  }

  if ((cfg & 0x08) !== 0) {
    const cLen = (cfg & 0x07) + 1;
    if (frame.byteLength < off + cLen) return null;
    ctr = readMinimalBE(frame.subarray(off, off + cLen));
    if (ctr === null || ctr <= 7n) return null;
    off += cLen;
  } else {
    ctr = BigInt(cfg & 0x07);
  }

  return { kid, ctr, headerLen: off };
}

function computeNonce(salt, ctr) {
  const nonce = new Uint8Array(12);
  nonce.set(salt, 0);
  const ctrBuf = new Uint8Array(8);
  new DataView(ctrBuf.buffer).setBigUint64(0, ctr, false);
  for (let i = 0; i < 8; i++) {
    nonce[4 + i] ^= ctrBuf[i];
  }
  return nonce;
}

function checkReplay(rx, ctr) {
  if (rx.pending && rx.pending.has(ctr)) {
    return false;
  }
  if (!rx.hasSeen) {
    return true;
  }
  if (ctr > rx.maxCTR) {
    return true;
  }
  const delta = rx.maxCTR - ctr;
  if (delta >= REPLAY_WINDOW) {
    return false;
  }
  return (rx.bitmap & (1n << delta)) === 0n;
}

function recordReplay(rx, ctr) {
  if (!rx.hasSeen) {
    rx.hasSeen = true;
    rx.maxCTR = ctr;
    rx.bitmap = 1n;
    return;
  }
  if (ctr > rx.maxCTR) {
    const shift = ctr - rx.maxCTR;
    if (shift >= REPLAY_WINDOW) {
      rx.bitmap = 1n;
    } else {
      rx.bitmap = ((rx.bitmap << shift) | 1n) & MASK_128;
    }
    rx.maxCTR = ctr;
    return;
  }
  const delta = rx.maxCTR - ctr;
  if (delta < REPLAY_WINDOW) {
    rx.bitmap |= 1n << delta;
  }
}

function getOrCreateScope(scopeID) {
  let sc = scopes.get(scopeID);
  if (!sc) {
    sc = {
      scopeID,
      epoch: 0,
      revision: 0,
      tx: null,
      rxKeys: new Map(), // BigInt kid -> RxEntry
    };
    scopes.set(scopeID, sc);
  }
  return sc;
}

function enqueueScopeOp(scopeID, fn) {
  const prev = scopeOpQueues.get(scopeID) || Promise.resolve();
  const next = prev.then(fn, fn);
  scopeOpQueues.set(scopeID, next);
  return next;
}

function requireSubtleCrypto() {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("sframe-worker: WebCrypto SubtleCrypto unavailable (HTTPS or localhost required)");
  }
  return crypto.subtle;
}

async function importAESKey(rawKeyBytes, usage) {
  return requireSubtleCrypto().importKey("raw", rawKeyBytes, { name: "AES-GCM" }, false, [usage]);
}

async function handleInstallBundle(msg) {
  const scopeID = msg.scopeID;
  const bundle = msg.bundle;
  const graceMs = typeof msg.graceMs === "number" ? msg.graceMs : 3000;
  if (!scopeID || !bundle || !bundle.sender) return;

  const sc = getOrCreateScope(scopeID);
  const startRev = sc.revision;

  await enqueueScopeOp(scopeID, async () => {
    const currentScope = getOrCreateScope(scopeID);
    if (currentScope.revision !== startRev) {
      return;
    }

    const txKID = readBigUint64BE(bundle.sender.kidBE);
    const txKey = await importAESKey(bundle.sender.key, "encrypt");
    const txSalt = new Uint8Array(bundle.sender.salt);

    const newRxPrepared = [];
    const incomingKIDs = new Set();
    const receivers = Array.isArray(bundle.receivers) ? bundle.receivers : [];
    for (const r of receivers) {
      const kid = readBigUint64BE(r.kidBE);
      incomingKIDs.add(kid);
      const existing = currentScope.rxKeys.get(kid);
      if (existing) {
        newRxPrepared.push({ kid, reuse: existing });
      } else {
        const cryptoKey = await importAESKey(r.key, "decrypt");
        newRxPrepared.push({
          kid,
          entry: {
            kid,
            epoch: Number(r.epoch || 0),
            leafIndex: Number(r.leafIndex ?? -1),
            address: r.address || "",
            salt: new Uint8Array(r.salt),
            cryptoKey,
            hasSeen: false,
            maxCTR: 0n,
            bitmap: 0n,
            pending: new Set(),
            expiresAt: 0,
          },
        });
      }
    }

    // Re-check revision in case scope was purged/revoked while importing keys.
    if (currentScope.revision !== startRev) {
      return;
    }

    if (!currentScope.tx || currentScope.tx.kid !== txKID) {
      currentScope.tx = {
        kid: txKID,
        epoch: Number(bundle.sender.epoch || 0),
        salt: txSalt,
        cryptoKey: txKey,
        ctr: 0n,
      };
    }

    const now = Date.now();
    const newEpoch = Number(bundle.epoch || 0);
    currentScope.epoch = newEpoch;

    for (const [kid, existing] of currentScope.rxKeys.entries()) {
      if (!incomingKIDs.has(kid)) {
        if (graceMs > 0 && existing.epoch < newEpoch) {
          if (!existing.expiresAt) {
            existing.expiresAt = now + graceMs;
          }
          if (now < existing.expiresAt) {
            continue;
          }
        }
        currentScope.rxKeys.delete(kid);
      }
    }

    for (const item of newRxPrepared) {
      if (item.reuse) {
        item.reuse.expiresAt = 0;
      } else {
        currentScope.rxKeys.set(item.kid, item.entry);
      }
    }
  });
}

function handleRevokePeer(msg) {
  const sc = scopes.get(msg.scopeID);
  if (!sc || !msg.peerAddr) return;
  sc.revision++;
  for (const [kid, rx] of sc.rxKeys.entries()) {
    if (rx.address === msg.peerAddr) {
      sc.rxKeys.delete(kid);
    }
  }
}

function handlePurgeScope(msg) {
  const sc = scopes.get(msg.scopeID);
  if (sc) {
    sc.revision++;
    sc.tx = null;
    sc.rxKeys.clear();
    scopes.delete(msg.scopeID);
  }
}

async function encryptTransformFrame(scopeID, mediaKind, encodedFrame, controller) {
  if (!encodedFrame || !encodedFrame.data || encodedFrame.data.byteLength === 0) {
    return;
  }
  const sc = scopes.get(scopeID);
  const tx = sc && sc.tx;
  if (!tx || !tx.cryptoKey) {
    stats.rejected++;
    stats.rejectReasons.noTx++;
    return;
  }

  // Reserve counter synchronously before await so parallel audio/video senders never reuse a nonce.
  const ctr = tx.ctr;
  tx.ctr += 1n;
  const kid = tx.kid;
  const salt = tx.salt;
  const cryptoKey = tx.cryptoKey;

  try {
    const hdr = encodeSFrameHeader(kid, ctr);
    const nonce = computeNonce(salt, ctr);
    const plaintext = new Uint8Array(encodedFrame.data);
    const sealed = await requireSubtleCrypto().encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: hdr, tagLength: 128 },
      cryptoKey,
      plaintext
    );

    const out = new Uint8Array(hdr.length + sealed.byteLength);
    out.set(hdr, 0);
    out.set(new Uint8Array(sealed), hdr.length);
    encodedFrame.data = out.buffer;

    if (mediaKind === "audio") {
      stats.encryptedAudio++;
    } else {
      stats.encryptedVideo++;
    }
    controller.enqueue(encodedFrame);
  } catch {
    stats.rejected++;
    stats.rejectReasons.encryptError++;
  }
}

async function decryptTransformFrame(scopeID, peerAddr, mediaKind, encodedFrame, controller) {
  if (!encodedFrame || !encodedFrame.data || encodedFrame.data.byteLength === 0) {
    return;
  }
  const frameBytes = new Uint8Array(encodedFrame.data);
  const parsed = decodeSFrameHeader(frameBytes);
  if (!parsed) {
    stats.rejected++;
    stats.rejectReasons.badHeader++;
    return;
  }

  const sc = scopes.get(scopeID);
  if (!sc) {
    stats.rejected++;
    stats.rejectReasons.noScope++;
    return;
  }

  const rx = sc.rxKeys.get(parsed.kid);
  if (!rx) {
    stats.rejected++;
    stats.rejectReasons.unknownKid++;
    return;
  }
  if (rx.expiresAt && Date.now() >= rx.expiresAt) {
    sc.rxKeys.delete(parsed.kid);
    stats.rejected++;
    stats.rejectReasons.expired++;
    return;
  }
  if (peerAddr && rx.address && rx.address !== peerAddr) {
    stats.rejected++;
    stats.rejectReasons.peerMismatch++;
    return;
  }
  if (!checkReplay(rx, parsed.ctr)) {
    stats.rejected++;
    stats.rejectReasons.replay++;
    return;
  }

  rx.pending.add(parsed.ctr);
  try {
    const nonce = computeNonce(rx.salt, parsed.ctr);
    const hdr = frameBytes.subarray(0, parsed.headerLen);
    const ct = frameBytes.subarray(parsed.headerLen);
    const ptBuf = await requireSubtleCrypto().decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: hdr, tagLength: 128 },
      rx.cryptoKey,
      ct
    );

    rx.pending.delete(parsed.ctr);
    if (!sc.rxKeys.has(parsed.kid) || sc.rxKeys.get(parsed.kid) !== rx) {
      stats.rejected++;
      stats.rejectReasons.keyRotated++;
      return;
    }
    if (!checkReplay(rx, parsed.ctr)) {
      stats.rejected++;
      stats.rejectReasons.replay++;
      return;
    }
    recordReplay(rx, parsed.ctr);

    encodedFrame.data = ptBuf;
    if (mediaKind === "audio") {
      stats.decryptedAudio++;
    } else {
      stats.decryptedVideo++;
    }
    controller.enqueue(encodedFrame);
  } catch {
    stats.rejected++;
    stats.rejectReasons.decryptError++;
  } finally {
    rx.pending.delete(parsed.ctr);
  }
}

function attachEncodedPipeline(readable, writable, options) {
  const scopeID = options && options.scopeID;
  const peerAddr = options && options.peerAddr;
  const direction = options && options.direction;
  const mediaKind = (options && options.mediaKind) || "audio";

  const dirKey = direction === "encrypt" ? "encrypt" : "decrypt";
  const kindKey = mediaKind === "video" ? "Video" : "Audio";
  stats.attached[dirKey + kindKey] = (stats.attached[dirKey + kindKey] || 0) + 1;

  const transformStream = new TransformStream({
    transform(encodedFrame, controller) {
      if (direction === "encrypt") {
        return encryptTransformFrame(scopeID, mediaKind, encodedFrame, controller);
      }
      return decryptTransformFrame(scopeID, peerAddr, mediaKind, encodedFrame, controller);
    },
  });

  readable.pipeThrough(transformStream).pipeTo(writable).catch((err) => {
    stats.pipeErrors++;
    stats.lastPipeError = err && err.message ? err.message : String(err || "");
  });
}

if (typeof self !== "undefined") {
  self.onrtctransform = (event) => {
    const transformer = event && event.transformer;
    if (!transformer) return;
    attachEncodedPipeline(transformer.readable, transformer.writable, transformer.options || {});
  };

  self.onmessage = async (event) => {
    const msg = event && event.data;
    if (!msg || typeof msg !== "object") return;

    switch (msg.type) {
      case "installBundle":
        try {
          await handleInstallBundle(msg);
          if (msg.requestId) {
            self.postMessage({ type: "ack", requestId: msg.requestId });
          }
        } catch (err) {
          stats.pipeErrors++;
          stats.lastPipeError = err && err.message ? err.message : String(err || "");
          if (msg.requestId) {
            self.postMessage({
              type: "ack",
              requestId: msg.requestId,
              error: stats.lastPipeError,
            });
          }
        }
        break;
      case "revokePeer":
        handleRevokePeer(msg);
        break;
      case "purgeScope":
        handlePurgeScope(msg);
        break;
      case "attachStreams":
        if (msg.readable && msg.writable) {
          attachEncodedPipeline(msg.readable, msg.writable, msg);
        }
        break;
      case "getStats":
        self.postMessage({
          type: "stats",
          requestId: msg.requestId,
          stats: {
            ...stats,
            attached: { ...stats.attached },
            rejectReasons: { ...stats.rejectReasons },
          },
        });
        break;
    }
  };
}
