// Cotilla Web UI — Thin UI & Browser Media Bridge over CotillaClient (cotilla.js)
//
// In accordance with the Cotilla architecture:
//   - cotilla.js owns cotilla.wasm loading, signaling WebSocket lifecycle, anchor replenishment,
//     invite link parsing/building, and all protocol/mesh operations.
//   - app.js configures CotillaClient (passing the signaling server URL) and binds DOM elements,
//     chat sessions/tabs, attachment UI, and Web Audio / Canvas media streams.

const $ = (id) => document.getElementById(id);
const short = (s) => (s ? s.slice(0, 8) : "...");

function resolveSignalingUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/ws`;
}

const client = new window.CotillaClient({
  signalingUrl: resolveSignalingUrl,
  wasmUrl: "cotilla.wasm",
  getBaseUrl: () => window.location.origin + window.location.pathname,
  storage: (() => {
    try {
      return window.sessionStorage;
    } catch {
      return null;
    }
  })(),
});
window.cotillaClient = client;
window.parseHash = window.CotillaClient.parseLink;

const state = {
  me: null,
  roomID: null,
  roomKey: null,
  overlayPeers: client.overlayPeers,
  peers: client.peers,
  directPeers: client.directPeers,
  isEvicted: false,
  localStream: null,
  camStream: null,
  screenStream: null,
  voiceConnected: false,
  micEnabled: false,
  camEnabled: false,
  activeCallScope: null,    // { scopeID, isDM }
  audioCtx: null,
  audioAnalysers: new Map(), // peerAddr -> { timer, source, analyser }
  speakingPeers: new Map(), // peerAddr -> boolean
  remoteMedia: new Map(),   // peerAddr -> { audioStream, videoStream, audioTrack, videoTrack, hasAudio, hasVideo, container, audioEl, videoEl, avatarEl, labelEl }
  remoteCallPresence: new Map(), // `${scopeID}::${peerAddr}` -> CallControlPayload
  blobUrls: new Set(),      // object URLs created for attachments
  activeSession: "main",    // "main" or peerAddress
  sessions: {
    main: {
      id: "main",
      name: "📢 Group Room",
      messages: [],
    },
  },
  pendingInvite: null,
};
window.state = state;

const seenAttachments = new Set();
window.seenAttachments = seenAttachments;

function trackBlobUrl(url) {
  if (url && typeof url === "string" && url.startsWith("blob:")) {
    state.blobUrls.add(url);
  }
  return url;
}

function cleanupUIResources() {
  if (state.activeCallScope) {
    try { client.leaveCall(state.activeCallScope.scopeID); } catch {}
    state.activeCallScope = null;
  }

  if (state.localStream) {
    state.localStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.localStream = null;
  }
  if (state.camStream) {
    state.camStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.camStream = null;
  }
  if (state.screenStream) {
    state.screenStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.screenStream = null;
  }
  try { client.setLocalMediaTracks({ audioTrack: null, videoTrack: null, videoKind: null }); } catch {}

  if (state.audioAnalysers) {
    for (const item of state.audioAnalysers.values()) {
      clearInterval(item.timer);
      try { item.source.disconnect(); } catch {}
    }
    state.audioAnalysers.clear();
  }
  if (state.audioCtx) {
    try { state.audioCtx.close(); } catch {}
    state.audioCtx = null;
  }
  state.voiceConnected = false;
  state.micEnabled = false;
  state.camEnabled = false;
  updateCallBadge();

  if (state.speakingPeers) {
    state.speakingPeers.clear();
  }
  if (state.remoteMedia) {
    for (const peer of Array.from(state.remoteMedia.keys())) {
      removePeerMedia(peer);
    }
    state.remoteMedia.clear();
  }
  if (state.remoteCallPresence) {
    state.remoteCallPresence.clear();
  }

  for (const url of state.blobUrls) {
    try { URL.revokeObjectURL(url); } catch {}
  }
  state.blobUrls.clear();
  seenAttachments.clear();

  state.activeSession = "main";
  state.sessions = {
    main: {
      id: "main",
      name: "📢 Group Room",
      messages: [],
    },
  };
  state.pendingInvite = null;
}

function updateAddressHash(hash) {
  if (!hash) return;
  if (window.history && window.history.pushState) {
    window.history.pushState(null, "", hash);
  } else {
    window.location.hash = hash;
  }
}

function bindClientEvents() {
  client.on("status", ({ online, text }) => {
    setStatus(!!online, text || "");
  });

  client.on("sessionStarted", ({ roomID, roomKey, me }) => {
    state.roomID = roomID;
    state.roomKey = roomKey;
    state.me = me;
    state.isEvicted = false;
    $("landing").style.display = "none";
    $("room-display").textContent = short(roomID);
    $("my-addr").textContent = short(me ? me.address : "");
    renderPeers();
    renderSessionTabs();
    renderSessionMessages();
  });

  client.on("message", ({ author, text, ts }) => {
    console.log(`[Cotilla] received message from ${short(author)}: ${text}`);
    appendMessage(author, text, ts, false);
  });

  client.on("attachmentOffer", ({ meta }) => {
    appendAttachmentOffer(meta, false);
  });

  client.on("attachmentProgress", ({ fileID, received, total }) => {
    updateAttachmentProgress(fileID, received, total);
  });

  client.on("attachment", ({ meta }) => {
    handleAttachmentCompleted(meta);
  });

  client.on("callPresence", ({ scopeID, from, payload }) => {
    handleRemoteCallPresence(scopeID, from, payload);
  });

  client.on("callRemoteTrack", ({ scopeID, peerAddr, kind, track, stream }) => {
    handleRemoteCallTrack(scopeID, peerAddr, kind, track, stream);
  });

  client.on("callPeerLeft", ({ scopeID, peerAddr }) => {
    if (scopeID && peerAddr) {
      state.remoteCallPresence.delete(`${scopeID}::${peerAddr}`);
    }
    removePeerMedia(peerAddr);
  });

  client.on("callPeerRemoved", ({ scopeID, peerAddr }) => {
    if (scopeID && peerAddr) {
      state.remoteCallPresence.delete(`${scopeID}::${peerAddr}`);
    }
    removePeerMedia(peerAddr);
  });

  client.on("callPeerClosed", ({ scopeID, peerAddr }) => {
    if (!peerAddr) {
      if (state.activeCallScope && state.activeCallScope.scopeID === scopeID) {
        leaveVoiceCallUIOnly();
      }
      return;
    }
    if (scopeID) {
      state.remoteCallPresence.delete(`${scopeID}::${peerAddr}`);
    }
    removePeerMedia(peerAddr);
  });

  client.on("sframeKeysUpdated", ({ scopeID, epoch }) => {
    if (state.activeCallScope && state.activeCallScope.scopeID === scopeID) {
      updateCallBadge(epoch);
    }
  });

  client.on("directInvite", ({ raw, inv, pay }) => {
    state.pendingInvite = { raw, inv, pay };
    const modalTitle = $("dm-modal-title");
    const modalText = $("dm-modal-text");
    if (modalTitle) modalTitle.textContent = `💬 Direct Invite from ${short(inv.from_sign_pub)}`;
    if (modalText) modalText.textContent = `Peer ${short(inv.from_sign_pub)} invited you to a private 1:1 conversation.`;
    const modal = $("dm-invite-modal");
    if (modal) modal.showModal();
  });

  client.on("inviteResponse", ({ res }) => {
    if (res.accepted) {
      appendMessage("system", `Peer ${short(res.from_sign_pub)} accepted your DM invite!`, Date.now(), false);
    } else {
      appendMessage("system", `Peer ${short(res.from_sign_pub)} declined your DM invite.`, Date.now(), false);
    }
  });

  client.on("dmMessage", ({ author, text, ts }) => {
    appendMessage(author, text, ts || Date.now(), false, author);
  });

  client.on("peerLeft", ({ addr }) => {
    removePeerMedia(addr);
  });

  client.on("peersChanged", () => {
    renderPeers();
  });

  client.on("open", ({ addr }) => {
    console.log(`[Cotilla] direct WebRTC DataChannel opened with ${short(addr)}`);
  });

  client.on("epochCommit", ({ commit }) => {
    console.log("Room key ratcheted to epoch:", commit.epoch_id);
  });

  client.on("memberEvicted", ({ evictedPeer, evictor, reason, epochID, selfEvicted }) => {
    if (selfEvicted) {
      state.isEvicted = true;
      if (state.activeCallScope && !state.activeCallScope.isDM) {
        leaveVoiceCallUIOnly();
      }
      appendMessage(
        "system",
        `🚫 You have been evicted from this burner room by ${short(evictor)}. Reason: ${reason}. You are cryptographically locked out.`,
        Date.now(),
        false
      );
      const copyBtn = $("btn-copy-link");
      if (copyBtn) copyBtn.disabled = true;
      const rotateBtn = $("btn-rotate-key");
      if (rotateBtn) rotateBtn.disabled = true;
      const sendBtn = $("send-btn");
      if (sendBtn) sendBtn.disabled = true;
      const chatInput = $("chat-input");
      if (chatInput) {
        chatInput.disabled = true;
        chatInput.placeholder = "🚫 Evicted from room";
      }
      renderPeers();
      return;
    }
    removePeerMedia(evictedPeer);
    appendMessage(
      "system",
      `🚫 Member ${short(evictedPeer)} was evicted by ${short(evictor)} (${reason}). Rotated to Epoch ${epochID}.`,
      Date.now(),
      false
    );
    renderPeers();
  });
}

async function enterSessionFromLink(linkOrHash) {
  cleanupUIResources();
  const res = await client.joinRoomFromLink(linkOrHash);
  updateAddressHash(res.hash);
  return res;
}

// ---- UI Rendering ----

function setStatus(online, text) {
  $("status-text").textContent = text;
  $("status-dot").classList.toggle("on", online);
}

function renderPeers() {
  const ul = $("peers-list");
  ul.textContent = "";
  const actualPeers = Array.from(state.peers).filter((p) => !state.me || p !== state.me.address);
  $("peer-count").textContent = actualPeers.length;

  if (state.isEvicted) {
    return;
  }

  for (const peer of actualPeers) {
    const isDirect = state.directPeers.has(peer);
    const isSpeaking = state.speakingPeers.has(peer);
    const li = document.createElement("li");
    li.classList.add("peer-list-item");

    const dot = document.createElement("span");
    dot.className = `dot-legend ${isDirect ? "direct" : "relay"}`;
    dot.title = isDirect ? "Direct P2P Link" : "Relayed via Peer";
    li.appendChild(dot);

    const code = document.createElement("code");
    code.textContent = short(peer);
    li.appendChild(code);

    if (isSpeaking) {
      const speakSpan = document.createElement("span");
      speakSpan.className = "speaking-indicator";
      speakSpan.textContent = "🔊";
      li.appendChild(speakSpan);
    }

    const actions = document.createElement("div");
    actions.className = "peer-actions";

    const dmBtn = document.createElement("button");
    dmBtn.type = "button";
    dmBtn.className = "peer-dm-btn";
    dmBtn.title = "Start Private DM";
    dmBtn.dataset.peer = peer;
    dmBtn.textContent = "💬 DM";
    dmBtn.onclick = (e) => {
      e.stopPropagation();
      if (state.isEvicted) {
        alert("You have been evicted from this burner room.");
        return;
      }
      startDirectMessage(peer);
    };
    actions.appendChild(dmBtn);

    const menuBtn = document.createElement("button");
    menuBtn.type = "button";
    menuBtn.className = "peer-menu-btn";
    menuBtn.title = "More options";
    menuBtn.dataset.peer = peer;
    menuBtn.textContent = "⋮";
    actions.appendChild(menuBtn);
    li.appendChild(actions);

    const menu = document.createElement("div");
    menu.className = "peer-context-menu";
    menu.style.display = "none";

    const infoBtn = document.createElement("button");
    infoBtn.type = "button";
    infoBtn.className = "menu-item-info";
    infoBtn.textContent = "ℹ️ Peer Info";
    menu.appendChild(infoBtn);

    const evictBtn = document.createElement("button");
    evictBtn.type = "button";
    evictBtn.className = "menu-item-evict";
    evictBtn.textContent = "🚫 Evict Member";
    menu.appendChild(evictBtn);
    li.appendChild(menu);

    menuBtn.onclick = (e) => {
      e.stopPropagation();
      document.querySelectorAll(".peer-context-menu").forEach((m) => {
        if (m !== menu) m.style.display = "none";
      });
      menu.style.display = menu.style.display === "none" ? "block" : "none";
    };

    infoBtn.onclick = (e) => {
      e.stopPropagation();
      menu.style.display = "none";
      const inv = client.invitedBy(peer);
      const inviter = inv ? short(inv) : "Unknown (Room Creator or direct link)";
      alert(`Peer Address: ${peer}\nInvited by: ${inviter}\nConnection: ${isDirect ? "Direct WebRTC DataChannel" : "Relayed via Mesh"}`);
    };

    evictBtn.onclick = (e) => {
      e.stopPropagation();
      menu.style.display = "none";
      if (state.isEvicted) {
        alert("You have been evicted from this burner room and cannot evict other members.");
        return;
      }
      const reason = prompt(`Evict member ${short(peer)} from room? Enter reason:`, "policy violation");
      if (reason !== null && reason.trim()) {
        try {
          client.evictPeer(peer, reason.trim());
          appendMessage("system", `Proposed eviction of ${short(peer)} (${reason.trim()}). Rotated room key.`, Date.now(), true);
        } catch (err) {
          alert("Eviction error: " + (err.message || err));
        }
      }
    };

    ul.appendChild(li);
  }
}

function switchSession(sessionId) {
  state.activeSession = sessionId;
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.classList.toggle("active", btn.getAttribute("data-session") === sessionId);
  });

  const badge = $("active-target-badge");
  if (badge) {
    badge.textContent = sessionId === "main"
      ? "Target: 📢 Group Room"
      : `Target: 💬 DM with ${short(sessionId)}`;
  }

  renderSessionMessages();
}

function renderSessionMessages() {
  const ul = $("messages");
  ul.textContent = "";
  const session = state.sessions[state.activeSession];
  if (!session) return;
  for (const item of session.messages) {
    if (item.type === "msg") {
      appendMessageToDOM(item.author, item.text, item.ts, item.mine);
    } else if (item.type === "attach") {
      appendAttachmentToDOM(item.meta, item.blobUrl, item.mine, item.isOffer);
    }
  }
}

function appendMessageToDOM(author, text, ts, mine) {
  const ul = $("messages");
  const li = document.createElement("li");
  if (mine || (state.me && author === state.me.address)) {
    li.classList.add("mine");
  }

  const timeStr = new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const metaDiv = document.createElement("div");
  metaDiv.className = "msg-meta";

  const strong = document.createElement("strong");
  strong.textContent = mine ? "You" : short(author);
  metaDiv.appendChild(strong);

  const timeSpan = document.createElement("span");
  timeSpan.textContent = timeStr;
  metaDiv.appendChild(timeSpan);

  const bodyDiv = document.createElement("div");
  bodyDiv.className = "msg-body";
  bodyDiv.textContent = text;

  li.appendChild(metaDiv);
  li.appendChild(bodyDiv);
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
}

function appendMessage(author, text, ts, mine, targetSession) {
  const sessKey = targetSession || state.activeSession || "main";
  if (!state.sessions[sessKey]) {
    state.sessions[sessKey] = {
      id: sessKey,
      name: sessKey === "main" ? "📢 Group Room" : `💬 DM: ${short(sessKey)}`,
      messages: [],
    };
  }
  state.sessions[sessKey].messages.push({ type: "msg", author, text, ts, mine });

  if (sessKey === state.activeSession) {
    appendMessageToDOM(author, text, ts, mine);
  }
}

function addDMSession(peer, roomID, roomKey) {
  if (!state.sessions[peer]) {
    state.sessions[peer] = {
      id: peer,
      peer,
      roomID,
      roomKey,
      name: `💬 DM: ${short(peer)}`,
      messages: [],
    };
    renderSessionTabs();
  }
}

function renderSessionTabs() {
  const tabsContainer = $("session-tabs");
  if (!tabsContainer) return;
  tabsContainer.textContent = "";

  const mainBtn = document.createElement("button");
  mainBtn.type = "button";
  mainBtn.className = `tab-btn ${state.activeSession === "main" ? "active" : ""}`;
  mainBtn.setAttribute("data-session", "main");
  mainBtn.id = "tab-main";
  mainBtn.textContent = "📢 Group Room";
  mainBtn.onclick = () => switchSession("main");
  tabsContainer.appendChild(mainBtn);

  for (const [key, sess] of Object.entries(state.sessions)) {
    if (key === "main") continue;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `tab-btn ${state.activeSession === key ? "active" : ""}`;
    btn.setAttribute("data-session", key);

    const nameSpan = document.createElement("span");
    nameSpan.textContent = sess.name;
    btn.appendChild(nameSpan);

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "tab-close";
    closeBtn.title = "Close DM";
    closeBtn.textContent = "✕";
    closeBtn.onclick = (e) => {
      e.stopPropagation();
      delete state.sessions[key];
      if (state.activeSession === key) {
        switchSession("main");
      }
      renderSessionTabs();
    };
    btn.appendChild(closeBtn);

    btn.onclick = () => switchSession(key);
    tabsContainer.appendChild(btn);
  }
}

async function startDirectMessage(peer) {
  if (state.sessions[peer]) {
    switchSession(peer);
    return;
  }
  try {
    const res = client.sendDirectInvite(peer, "dm", "Private Chat");
    if (res && res.status === "ok" && res.payload) {
      addDMSession(peer, res.payload.room_id, res.payload.room_key);
      switchSession(peer);
      appendMessage("system", `Direct invite sent to peer ${short(peer)}. Starting private session.`, Date.now(), false, peer);
    } else {
      console.warn("Direct invite failed: " + ((res && res.error) || "Unknown error"));
    }
  } catch (err) {
    console.error("sendDirectInvite error", err);
  }
}

// ---- Attachment Rendering ----

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function createSaveLink(blobUrl, name) {
  const a = document.createElement("a");
  if (typeof blobUrl === "string" && blobUrl.startsWith("blob:")) {
    a.href = blobUrl;
  }
  a.download = name;
  a.className = "small-btn";
  a.textContent = "Save File";
  return a;
}

function appendAttachmentToDOM(meta, blobUrl, mine, isOffer) {
  const ul = $("messages");
  if (!ul || !meta) return;

  const fileID = meta.file_id || meta.FileID;
  if (document.getElementById(`attach-li-${fileID}`)) {
    return;
  }

  const li = document.createElement("li");
  li.id = `attach-li-${fileID}`;
  if (mine) li.classList.add("mine");

  const formattedSize = formatBytes(meta.size || meta.Size || 0);
  const name = meta.name || meta.Name || "file.bin";
  const mime = meta.mime || meta.MIME || "application/octet-stream";

  let badgeText = isOffer ? "Available" : "SHA-256 Verified";
  if (mine) badgeText = "Shared";

  const metaDiv = document.createElement("div");
  metaDiv.className = "msg-meta";
  const authorStrong = document.createElement("strong");
  authorStrong.textContent = mine ? "You" : "Peer";
  const badgeSpan = document.createElement("span");
  badgeSpan.className = "attachment-badge";
  badgeSpan.id = `badge-${fileID}`;
  badgeSpan.textContent = badgeText;
  metaDiv.appendChild(authorStrong);
  metaDiv.appendChild(badgeSpan);

  const cardDiv = document.createElement("div");
  cardDiv.className = "attachment-card";
  cardDiv.id = `attach-card-${fileID}`;

  const iconDiv = document.createElement("div");
  iconDiv.className = "attachment-icon";
  iconDiv.textContent = "📁";
  cardDiv.appendChild(iconDiv);

  const infoDiv = document.createElement("div");
  infoDiv.className = "attachment-info";

  const nameDiv = document.createElement("div");
  nameDiv.className = "attachment-name";
  nameDiv.textContent = name;
  infoDiv.appendChild(nameDiv);

  const sizeDiv = document.createElement("div");
  sizeDiv.className = "attachment-size";
  sizeDiv.textContent = `${formattedSize} · ${mime}`;
  infoDiv.appendChild(sizeDiv);

  const progWrap = document.createElement("div");
  progWrap.className = "attachment-progress";
  progWrap.id = `prog-wrap-${fileID}`;
  progWrap.style.display = "none";

  const progBg = document.createElement("div");
  progBg.className = "progress-bar-bg";
  const progFill = document.createElement("div");
  progFill.className = "progress-bar-fill";
  progFill.id = `prog-fill-${fileID}`;
  progBg.appendChild(progFill);

  const progText = document.createElement("span");
  progText.className = "progress-text";
  progText.id = `prog-text-${fileID}`;
  progText.textContent = "0%";

  progWrap.appendChild(progBg);
  progWrap.appendChild(progText);
  infoDiv.appendChild(progWrap);
  cardDiv.appendChild(infoDiv);

  if (isOffer && !mine) {
    const actionWrap = document.createElement("div");
    actionWrap.id = `action-${fileID}`;
    const dlBtn = document.createElement("button");
    dlBtn.type = "button";
    dlBtn.className = "small-btn primary download-btn";
    dlBtn.textContent = "⬇️ Download";
    dlBtn.addEventListener("click", () => startDownloadAttachment(fileID));
    actionWrap.appendChild(dlBtn);
    cardDiv.appendChild(actionWrap);
  } else if (blobUrl) {
    const actionWrap = document.createElement("div");
    actionWrap.id = `action-${fileID}`;
    actionWrap.appendChild(createSaveLink(blobUrl, name));
    cardDiv.appendChild(actionWrap);
  }

  li.appendChild(metaDiv);
  li.appendChild(cardDiv);
  ul.appendChild(li);
  ul.scrollTop = ul.scrollHeight;
}

function appendAttachment(meta, dataOrBlobUrl, mine) {
  if (!meta) return;
  const fileID = meta.file_id || meta.FileID;
  if (seenAttachments.has(fileID)) return;
  seenAttachments.add(fileID);

  let blobUrl = "";
  const mime = meta.mime || meta.MIME || "application/octet-stream";
  if (typeof dataOrBlobUrl === "string" && dataOrBlobUrl.startsWith("blob:")) {
    blobUrl = trackBlobUrl(dataOrBlobUrl);
  } else if (dataOrBlobUrl instanceof Uint8Array || dataOrBlobUrl instanceof ArrayBuffer) {
    const blob = new Blob([dataOrBlobUrl], { type: mime });
    blobUrl = trackBlobUrl(URL.createObjectURL(blob));
  }

  const session = state.sessions["main"];
  if (session) {
    session.messages.push({ type: "attach", meta, blobUrl, mine, isOffer: false });
  }
  if (state.activeSession === "main") {
    appendAttachmentToDOM(meta, blobUrl, mine, false);
  }
}

function appendAttachmentOffer(meta, mine) {
  if (!meta) return;
  const fileID = meta.file_id || meta.FileID;
  if (seenAttachments.has(fileID)) return;
  seenAttachments.add(fileID);

  const session = state.sessions["main"];
  if (session) {
    session.messages.push({ type: "attach", meta, blobUrl: "", mine, isOffer: !mine });
  }
  if (state.activeSession === "main") {
    appendAttachmentToDOM(meta, "", mine, !mine);
  }
}

window.startDownloadAttachment = function (fileID) {
  const btnWrap = $(`action-${fileID}`);
  const progWrap = $(`prog-wrap-${fileID}`);
  if (btnWrap) btnWrap.style.display = "none";
  if (progWrap) progWrap.style.display = "flex";
  const badge = $(`badge-${fileID}`);
  if (badge) badge.textContent = "Downloading...";
  client.downloadAttachment(fileID);
};

function updateAttachmentProgress(fileID, received, total) {
  const fill = $(`prog-fill-${fileID}`);
  const text = $(`prog-text-${fileID}`);
  const progWrap = $(`prog-wrap-${fileID}`);
  if (progWrap && progWrap.style.display === "none") {
    progWrap.style.display = "flex";
  }
  const pct = Math.min(100, Math.round((received / total) * 100));
  if (fill) fill.style.width = `${pct}%`;
  if (text) text.textContent = `${pct}% (${received}/${total})`;
  if (received % 200 === 0 || received === total) {
    console.log(`[Attachment Progress] ${fileID}: ${pct}% (${received}/${total} chunks)`);
  }
}

function handleAttachmentCompleted(meta, dataOrBytes) {
  if (!meta) return;
  const fileID = meta.file_id || meta.FileID;
  const progWrap = $(`prog-wrap-${fileID}`);
  if (progWrap) progWrap.style.display = "none";

  const badge = $(`badge-${fileID}`);
  if (badge) badge.textContent = "SHA-256 Verified";

  const mime = meta.mime || meta.MIME || "application/octet-stream";
  let blobUrl = "";
  if (dataOrBytes instanceof Uint8Array || dataOrBytes instanceof ArrayBuffer) {
    const blob = new Blob([dataOrBytes], { type: mime });
    blobUrl = trackBlobUrl(URL.createObjectURL(blob));
  } else {
    try {
      const uint8 = client.getAttachmentData(fileID);
      if (uint8 && uint8 instanceof Uint8Array) {
        const blob = new Blob([uint8], { type: mime });
        blobUrl = trackBlobUrl(URL.createObjectURL(blob));
      }
    } catch (e) {
      console.error("getAttachmentData error", e);
    }
  }

  for (const sessKey of Object.keys(state.sessions)) {
    const s = state.sessions[sessKey];
    for (const m of s.messages) {
      if (m.type === "attach" && (m.meta.file_id === fileID || m.meta.FileID === fileID)) {
        m.blobUrl = blobUrl;
        m.isOffer = false;
      }
    }
  }

  const action = $(`action-${fileID}`);
  if (action && blobUrl) {
    action.style.display = "block";
    action.textContent = "";
    const name = meta.name || meta.Name || "file.bin";
    action.appendChild(createSaveLink(blobUrl, name));
  }
}

window.appendAttachment = appendAttachment;
window.appendAttachmentOffer = appendAttachmentOffer;
window.updateAttachmentProgress = updateAttachmentProgress;
window.handleAttachmentCompleted = handleAttachmentCompleted;

// ---- Scoped Secondary WebRTC A/V & SFrame Media UI ----

function currentCallTarget() {
  if (state.activeSession && state.activeSession !== "main") {
    const sess = state.sessions[state.activeSession];
    if (sess && sess.roomID) {
      return { scopeID: sess.roomID, isDM: true, peer: sess.peer };
    }
  }
  return { scopeID: state.roomID, isDM: false, peer: null };
}

function currentCallOptions() {
  const sending = !!state.micEnabled || !!state.camEnabled || !!state.screenStream;
  return {
    listenOnly: !sending,
    audio: !!state.micEnabled,
    video: !!state.camEnabled,
    screen: !!state.screenStream,
  };
}

function updateCallBadge(epochOverride) {
  const lockBadge = $("sframe-lock-badge");
  if (!lockBadge) return;
  if (!state.voiceConnected || !state.activeCallScope) {
    lockBadge.style.display = "none";
    return;
  }
  lockBadge.style.display = "inline-block";
  const scopeTag = state.activeCallScope.isDM ? "DM" : `Epoch ${epochOverride ?? "-"}`;
  lockBadge.textContent = `🔒 E2EE SFrame (${scopeTag})`;
}

function updateVideoGridVisibility() {
  const grid = $("video-grid");
  if (!grid) return;
  const hasLocal = (state.camEnabled && state.camStream) || !!state.screenStream;
  const hasRemote = state.remoteMedia && state.remoteMedia.size > 0;
  const hasSpeaking = state.speakingPeers && state.speakingPeers.size > 0;
  grid.style.display = hasLocal || hasRemote || hasSpeaking ? "flex" : "none";
}

function setupSpeakingAnalyser(peerAddr, track) {
  if (!track || track.kind !== "audio") return;
  if (state.audioAnalysers.has(peerAddr)) {
    const old = state.audioAnalysers.get(peerAddr);
    clearInterval(old.timer);
    try { old.source.disconnect(); } catch {}
    state.audioAnalysers.delete(peerAddr);
  }
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass || typeof window.MediaStream !== "function") return;
    if (!state.audioCtx) state.audioCtx = new AudioContextClass();
    if (state.audioCtx.state === "suspended") {
      state.audioCtx.resume().catch(() => {});
    }
    const source = state.audioCtx.createMediaStreamSource(new window.MediaStream([track]));
    const analyser = state.audioCtx.createAnalyser();
    analyser.fftSize = 256;
    source.connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);

    const timer = setInterval(() => {
      if (!state.voiceConnected || !state.remoteMedia.has(peerAddr)) {
        clearInterval(timer);
        return;
      }
      analyser.getByteTimeDomainData(data);
      let sum = 0;
      for (let i = 0; i < data.length; i++) {
        const d = (data[i] - 128) / 128;
        sum += d * d;
      }
      const rms = Math.sqrt(sum / data.length);
      const speaking = rms > 0.015;
      const prevSpeaking = !!state.speakingPeers.get(peerAddr);
      if (speaking !== prevSpeaking) {
        if (speaking) {
          state.speakingPeers.set(peerAddr, true);
        } else {
          state.speakingPeers.delete(peerAddr);
        }
        const tile = document.getElementById(`video-peer-${peerAddr}`);
        if (tile) tile.classList.toggle("speaking", speaking);
        renderPeers();
      }
    }, 120);

    state.audioAnalysers.set(peerAddr, { timer, source, analyser });
  } catch {}
}

function handleRemoteCallPresence(scopeID, peerAddr, payload) {
  if (!scopeID || !peerAddr || !payload || (state.me && peerAddr === state.me.address)) {
    return;
  }
  const key = `${scopeID}::${peerAddr}`;
  if (payload.action === "leave") {
    state.remoteCallPresence.delete(key);
    if (state.voiceConnected && state.activeCallScope && state.activeCallScope.scopeID === scopeID) {
      removePeerMedia(peerAddr);
    }
    return;
  }
  state.remoteCallPresence.set(key, payload);
  if (state.voiceConnected && state.activeCallScope && state.activeCallScope.scopeID === scopeID) {
    const entry = state.remoteMedia.get(peerAddr);
    if (entry) {
      entry.hasVideo = !!(payload.video || payload.screen);
      syncRemotePeerTile(peerAddr);
    }
  }
}

function peerSendingVideo(scopeID, peerAddr) {
  const cached = state.remoteCallPresence.get(`${scopeID}::${peerAddr}`);
  if (cached) {
    return !!(cached.video || cached.screen);
  }
  const activeCall = client && client.activeCalls && typeof client.activeCalls.get === "function"
    ? client.activeCalls.get(scopeID)
    : null;
  const peerState = activeCall && activeCall.peers && typeof activeCall.peers.get === "function"
    ? activeCall.peers.get(peerAddr)
    : null;
  return !!(peerState && (peerState.video || peerState.screen));
}

function syncRemotePeerTile(peerAddr) {
  const entry = state.remoteMedia.get(peerAddr);
  if (!entry) return;

  if (!entry.container) {
    const container = document.createElement("div");
    container.className = "video-container";
    container.id = `video-peer-${peerAddr}`;

    const avatarDiv = document.createElement("div");
    avatarDiv.className = "audio-avatar";
    avatarDiv.id = `audio-avatar-${peerAddr}`;
    avatarDiv.textContent = "🎙️";

    const labelEl = document.createElement("div");
    labelEl.className = "video-label";
    labelEl.id = `video-label-${peerAddr}`;

    container.appendChild(avatarDiv);
    container.appendChild(labelEl);
    $("video-grid").appendChild(container);

    entry.container = container;
    entry.avatarEl = avatarDiv;
    entry.labelEl = labelEl;
  }

  if (entry.audioStream) {
    if (!entry.audioEl) {
      const audioEl = document.createElement("audio");
      audioEl.id = `audio-el-${peerAddr}`;
      audioEl.autoplay = true;
      audioEl.playsInline = true;
      audioEl.muted = false;
      audioEl.style.display = "none";
      entry.container.appendChild(audioEl);
      entry.audioEl = audioEl;
    }
    if (entry.audioEl.srcObject !== entry.audioStream) {
      entry.audioEl.srcObject = entry.audioStream;
    }
    if (typeof entry.audioEl.play === "function") {
      entry.audioEl.play().catch(() => {});
    }
  }

  const showVideo = !!(entry.hasVideo && entry.videoTrack);
  if (showVideo) {
    if (!entry.videoEl) {
      const videoEl = document.createElement("video");
      videoEl.id = `video-el-${peerAddr}`;
      videoEl.className = "remote-video-frame";
      videoEl.autoplay = true;
      videoEl.playsInline = true;
      videoEl.muted = true; // Audio renders via entry.audioEl so cam toggles never interrupt audio.
      entry.container.appendChild(videoEl);
      entry.videoEl = videoEl;
    }
    if (entry.videoStream && entry.videoEl.srcObject !== entry.videoStream) {
      entry.videoEl.srcObject = entry.videoStream;
    }
    if (typeof entry.videoEl.play === "function") {
      entry.videoEl.play().catch(() => {});
    }
    entry.container.classList.remove("audio-tile");
    if (entry.avatarEl) entry.avatarEl.style.display = "none";
    if (entry.labelEl) entry.labelEl.textContent = `Peer ${short(peerAddr)} (🔒 Video)`;
  } else {
    if (entry.videoEl) {
      entry.videoEl.srcObject = null;
      if (entry.videoEl.parentNode) {
        entry.videoEl.parentNode.removeChild(entry.videoEl);
      }
      entry.videoEl = null;
    }
    entry.container.classList.add("audio-tile");
    if (entry.avatarEl) entry.avatarEl.style.display = "block";
    if (entry.labelEl) entry.labelEl.textContent = `Peer ${short(peerAddr)} (🔒 Voice)`;
  }

  updateVideoGridVisibility();
  renderPeers();
}

function handleRemoteCallTrack(scopeID, peerAddr, kind, track, stream) {
  if (!state.voiceConnected || !state.activeCallScope || state.activeCallScope.scopeID !== scopeID) {
    return;
  }
  if (!peerAddr || !track) return;

  let entry = state.remoteMedia.get(peerAddr);
  if (!entry) {
    entry = {
      audioStream: null,
      videoStream: null,
      audioTrack: null,
      videoTrack: null,
      hasAudio: false,
      hasVideo: peerSendingVideo(scopeID, peerAddr),
      container: null,
      audioEl: null,
      videoEl: null,
      avatarEl: null,
      labelEl: null,
    };
    state.remoteMedia.set(peerAddr, entry);
  } else {
    entry.hasVideo = peerSendingVideo(scopeID, peerAddr);
  }

  if (kind === "video") {
    entry.videoTrack = track;
    entry.videoStream = typeof window.MediaStream === "function" ? new window.MediaStream([track]) : (stream || null);
  } else {
    entry.audioTrack = track;
    entry.audioStream = typeof window.MediaStream === "function" ? new window.MediaStream([track]) : (stream || null);
    entry.hasAudio = true;
    setupSpeakingAnalyser(peerAddr, track);
  }

  syncRemotePeerTile(peerAddr);
}

function removePeerMedia(peerAddr) {
  if (!peerAddr) return;
  if (state.audioAnalysers && state.audioAnalysers.has(peerAddr)) {
    const item = state.audioAnalysers.get(peerAddr);
    clearInterval(item.timer);
    try { item.source.disconnect(); } catch {}
    state.audioAnalysers.delete(peerAddr);
  }
  const entry = state.remoteMedia ? state.remoteMedia.get(peerAddr) : null;
  if (entry) {
    if (entry.audioEl) entry.audioEl.srcObject = null;
    if (entry.videoEl) entry.videoEl.srcObject = null;
    if (entry.container && entry.container.parentNode) {
      entry.container.parentNode.removeChild(entry.container);
    }
  } else {
    const videoEl = document.getElementById(`video-el-${peerAddr}`);
    if (videoEl) videoEl.srcObject = null;
    const container = document.getElementById(`video-peer-${peerAddr}`);
    if (container && container.parentNode) {
      container.parentNode.removeChild(container);
    }
  }
  if (state.speakingPeers) state.speakingPeers.delete(peerAddr);
  if (state.remoteMedia) state.remoteMedia.delete(peerAddr);
  updateVideoGridVisibility();
  renderPeers();
}

async function ensureCallJoined() {
  if (state.voiceConnected && state.activeCallScope) {
    return state.activeCallScope;
  }
  const target = currentCallTarget();
  if (!target.scopeID) {
    throw new Error("No active room or DM scope");
  }
  state.voiceConnected = true;
  state.activeCallScope = { scopeID: target.scopeID, isDM: target.isDM };
  let res;
  try {
    res = await client.joinCall(target.scopeID, target.isDM, currentCallOptions());
  } catch (err) {
    state.voiceConnected = false;
    state.activeCallScope = null;
    throw err;
  }
  const activeCall = client.activeCalls && typeof client.activeCalls.get === "function"
    ? client.activeCalls.get(target.scopeID)
    : null;
  if (activeCall && activeCall.peers) {
    for (const [peerAddr, p] of activeCall.peers.entries()) {
      state.remoteCallPresence.set(`${target.scopeID}::${peerAddr}`, p);
      const entry = state.remoteMedia.get(peerAddr);
      if (entry) {
        entry.hasVideo = !!(p && (p.video || p.screen));
        syncRemotePeerTile(peerAddr);
      }
    }
  }
  const btnVoice = $("btn-voice");
  if (btnVoice) {
    btnVoice.textContent = "🔊 Leave Voice";
    btnVoice.classList.add("active");
  }
  const epoch = res && res.bundle ? res.bundle.epoch : undefined;
  updateCallBadge(epoch);
  return state.activeCallScope;
}

function leaveVoiceCallUIOnly() {
  state.voiceConnected = false;
  state.activeCallScope = null;
  state.micEnabled = false;
  state.camEnabled = false;

  if (state.localStream) {
    state.localStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.localStream = null;
  }
  if (state.camStream) {
    state.camStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.camStream = null;
  }
  if (state.screenStream) {
    state.screenStream.getTracks().forEach((t) => { try { t.stop(); } catch {} });
    state.screenStream = null;
  }
  try { client.setLocalMediaTracks({ audioTrack: null, videoTrack: null, videoKind: null }); } catch {}

  const btnVoice = $("btn-voice");
  if (btnVoice) {
    btnVoice.textContent = "🔊 Join Voice";
    btnVoice.classList.remove("active");
  }
  const btnMic = $("btn-mic");
  if (btnMic) {
    btnMic.textContent = "🎤 Enable Mic";
    btnMic.classList.remove("active");
  }
  const btnCam = $("btn-cam");
  if (btnCam) {
    btnCam.textContent = "📷 Cam Off";
    btnCam.classList.remove("active");
  }
  const btnScreen = $("btn-screen");
  if (btnScreen) {
    btnScreen.textContent = "🖥️ Share Screen";
    btnScreen.classList.remove("active");
  }
  if ($("local-video")) $("local-video").srcObject = null;
  if ($("local-video-container")) $("local-video-container").style.display = "none";

  for (const peer of Array.from(state.remoteMedia.keys())) {
    removePeerMedia(peer);
  }
  state.remoteMedia.clear();
  if (state.remoteCallPresence) {
    state.remoteCallPresence.clear();
  }
  updateCallBadge();
  updateVideoGridVisibility();
  renderPeers();
}

async function setupMedia() {
  const btnVoice = $("btn-voice");
  if (btnVoice) {
    btnVoice.onclick = async () => {
      if (!state.voiceConnected) {
        try {
          const AudioContextClass = window.AudioContext || window.webkitAudioContext;
          if (AudioContextClass) {
            if (!state.audioCtx) state.audioCtx = new AudioContextClass();
            if (state.audioCtx.state === "suspended") {
              try { await state.audioCtx.resume(); } catch {}
            }
          }
          await ensureCallJoined();
        } catch (err) {
          console.error("join call error", err);
          alert("Cannot join encrypted call: " + (err.message || err));
        }
      } else {
        const scopeID = state.activeCallScope ? state.activeCallScope.scopeID : null;
        if (scopeID) {
          try { client.leaveCall(scopeID); } catch {}
        }
        leaveVoiceCallUIOnly();
      }
    };
  }

  $("btn-mic").onclick = async () => {
    if (!state.localStream) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: {
            echoCancellation: true,
            noiseSuppression: true,
            autoGainControl: true,
          },
        });
        state.localStream = stream;
        state.micEnabled = true;
        $("btn-mic").textContent = "🎤 Mic Live";
        $("btn-mic").classList.add("active");
        const audioTrack = stream.getAudioTracks()[0] || null;
        await client.setLocalMediaTracks({ audioTrack });
        const scope = await ensureCallJoined();
        await client.updateCallOptions(scope.scopeID, currentCallOptions());
      } catch (err) {
        console.error("microphone access error", err);
        state.micEnabled = false;
        $("btn-mic").textContent = "⚠️ Mic Error: " + (err.name || err.message || "Denied");
      }
    } else {
      state.micEnabled = !state.micEnabled;
      state.localStream.getAudioTracks().forEach((t) => (t.enabled = state.micEnabled));
      $("btn-mic").textContent = state.micEnabled ? "🎤 Mic Live" : "🔇 Mic Muted";
      $("btn-mic").classList.toggle("active", state.micEnabled);
      const audioTrack = state.micEnabled ? state.localStream.getAudioTracks()[0] || null : null;
      await client.setLocalMediaTracks({ audioTrack });
      if (state.voiceConnected && state.activeCallScope) {
        await client.updateCallOptions(state.activeCallScope.scopeID, currentCallOptions());
      }
    }
  };

  $("btn-cam").onclick = async () => {
    const nextCam = !state.camEnabled;
    if (nextCam) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
        state.camStream = stream;
        state.camEnabled = true;
        $("btn-cam").textContent = "📷 Cam On";
        $("btn-cam").classList.add("active");
        $("local-video").srcObject = stream;
        $("local-video-container").style.display = "block";
        $("local-video-label").textContent = "You (Camera)";
        updateVideoGridVisibility();

        const videoTrack = stream.getVideoTracks()[0] || null;
        await client.setLocalMediaTracks({ videoTrack, videoKind: "cam" });
        const scope = await ensureCallJoined();
        await client.updateCallOptions(scope.scopeID, currentCallOptions());
      } catch (err) {
        console.warn("cam access failed", err);
        state.camEnabled = false;
        $("btn-cam").textContent = "📷 Cam Off";
        $("btn-cam").classList.remove("active");
        $("local-video-container").style.display = "none";
        updateVideoGridVisibility();
      }
    } else {
      if (state.camStream) {
        state.camStream.getTracks().forEach((t) => t.stop());
        state.camStream = null;
      }
      state.camEnabled = false;
      $("btn-cam").textContent = "📷 Cam Off";
      $("btn-cam").classList.remove("active");
      if (state.screenStream) {
        const scrTrack = state.screenStream.getVideoTracks()[0] || null;
        await client.setLocalMediaTracks({ videoTrack: scrTrack, videoKind: "screen" });
      } else {
        await client.setLocalMediaTracks({ videoTrack: null, videoKind: null });
        $("local-video").srcObject = null;
        $("local-video-container").style.display = "none";
      }
      if (state.voiceConnected && state.activeCallScope) {
        await client.updateCallOptions(state.activeCallScope.scopeID, currentCallOptions());
      }
      updateVideoGridVisibility();
    }
  };

  $("btn-screen").onclick = async () => {
    if (!state.screenStream) {
      try {
        const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
        state.screenStream = stream;
        $("btn-screen").classList.add("active");
        $("btn-screen").textContent = "🖥️ Stop Screen";
        $("local-video").srcObject = stream;
        $("local-video-container").style.display = "block";
        $("local-video-label").textContent = "You (Screen Share)";
        updateVideoGridVisibility();

        const videoTrack = stream.getVideoTracks()[0] || null;
        await client.setLocalMediaTracks({ videoTrack, videoKind: "screen" });
        const scope = await ensureCallJoined();
        await client.updateCallOptions(scope.scopeID, currentCallOptions());
        if (videoTrack) {
          videoTrack.onended = () => stopScreenShare();
        }
      } catch (err) {
        console.warn("screen share error", err);
      }
    } else {
      await stopScreenShare();
    }
  };

  async function stopScreenShare() {
    if (state.screenStream) {
      state.screenStream.getTracks().forEach((t) => t.stop());
      state.screenStream = null;
    }
    $("btn-screen").classList.remove("active");
    $("btn-screen").textContent = "🖥️ Share Screen";
    if (state.camEnabled && state.camStream) {
      $("local-video").srcObject = state.camStream;
      $("local-video-label").textContent = "You (Camera)";
      $("local-video-container").style.display = "block";
      const camTrack = state.camStream.getVideoTracks()[0] || null;
      await client.setLocalMediaTracks({ videoTrack: camTrack, videoKind: "cam" });
    } else {
      await client.setLocalMediaTracks({ videoTrack: null, videoKind: null });
      $("local-video").srcObject = null;
      $("local-video-container").style.display = "none";
    }
    if (state.voiceConnected && state.activeCallScope) {
      await client.updateCallOptions(state.activeCallScope.scopeID, currentCallOptions());
    }
    updateVideoGridVisibility();
  }
}

// ---- Copy Invite Link ----

function copyInviteLink() {
  if (state.isEvicted) {
    alert("You have been evicted from this burner room and cannot create invite links.");
    return;
  }
  let url = window.location.href;
  try {
    const invData = client.getInviteData(15 * 60 * 1000);
    if (invData && invData.url) {
      url = invData.url;
    }
  } catch (e) {
    console.warn("channel invite generation fallback to standard hash", e);
  }
  window.lastCopiedInviteUrl = url;
  const btn = $("btn-copy-link");

  const showCopied = () => {
    const orig = btn.textContent;
    btn.textContent = "✅ Copied!";
    setTimeout(() => {
      btn.textContent = orig;
    }, 2000);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url).then(showCopied, fallbackCopy);
  } else {
    fallbackCopy();
  }

  function fallbackCopy() {
    const ta = document.createElement("textarea");
    ta.value = url;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      showCopied();
    } catch {
      prompt("Copy your burner room invite link:", url);
    }
    document.body.removeChild(ta);
  }
}

// ---- Event Listeners ----

function setupUI() {
  $("btn-create-room").onclick = async () => {
    try {
      cleanupUIResources();
      const created = await client.createRoom(15 * 60 * 1000);
      updateAddressHash(created.hash);
    } catch (err) {
      console.error("Room creation error:", err);
      alert("Room creation error: " + (err.message || err));
    }
  };

  const joinBtn = $("btn-join-room");
  if (joinBtn) {
    joinBtn.onclick = async () => {
      const input = $("join-room-input");
      const val = (input ? input.value : "").trim();
      if (!val) return;
      try {
        await enterSessionFromLink(val);
      } catch (err) {
        alert(err.message || "Invalid room link or parameters. Expected format: #room=<uuid>&key=<key>");
      }
    };
  }

  const joinInput = $("join-room-input");
  if (joinInput) {
    joinInput.onkeydown = (e) => {
      if (e.key === "Enter") {
        $("btn-join-room").click();
      }
    };
  }

  $("btn-copy-link").onclick = copyInviteLink;

  const rotateBtn = $("btn-rotate-key");
  if (rotateBtn) {
    rotateBtn.onclick = () => {
      if (state.isEvicted) {
        alert("You have been evicted from this burner room and cannot rotate keys.");
        return;
      }
      try {
        const res = client.rotateEpochKey();
        const orig = rotateBtn.textContent;
        rotateBtn.textContent = `✅ Rotated (Epoch ${res.epoch_id})!`;
        setTimeout(() => {
          rotateBtn.textContent = orig;
        }, 2000);
      } catch (e) {
        alert("Key rotation error: " + (e.message || e));
        console.error("failed to rotate epoch key", e);
      }
    };
  }

  const dmAcceptBtn = $("btn-dm-accept");
  if (dmAcceptBtn) {
    dmAcceptBtn.onclick = () => {
      if (state.pendingInvite) {
        try {
          client.respondDirectInvite(state.pendingInvite.raw, true);
          client.registerDMSession(state.pendingInvite.pay.room_id, state.pendingInvite.pay.room_key, state.pendingInvite.inv.from_sign_pub);
          addDMSession(state.pendingInvite.inv.from_sign_pub, state.pendingInvite.pay.room_id, state.pendingInvite.pay.room_key);
          switchSession(state.pendingInvite.inv.from_sign_pub);
          state.pendingInvite = null;
        } catch (e) {
          alert("Failed to accept DM invite: " + (e.message || e));
          console.error("failed to accept DM invite", e);
          return;
        }
      }
      const modal = $("dm-invite-modal");
      if (modal) modal.close();
    };
  }

  const dmDeclineBtn = $("btn-dm-decline");
  if (dmDeclineBtn) {
    dmDeclineBtn.onclick = () => {
      if (state.pendingInvite) {
        try {
          client.respondDirectInvite(state.pendingInvite.raw, false);
        } catch (e) {
          console.error("failed to decline DM invite", e);
        }
        state.pendingInvite = null;
      }
      const modal = $("dm-invite-modal");
      if (modal) modal.close();
    };
  }

  $("composer").onsubmit = (e) => {
    e.preventDefault();
    if (state.isEvicted && state.activeSession === "main") return;
    const input = $("chat-input");
    const text = input.value.trim();
    if (!text) return;

    if (state.activeSession === "main") {
      try {
        const res = client.sendMessage(text);
        console.log(`[Cotilla] sent message '${text}' (res: ${JSON.stringify(res)})`);
        appendMessage(state.me.address, text, Date.now(), true);
      } catch (err) {
        appendMessage("system", `Failed to send message: ${err.message || err}`, Date.now(), false);
        return;
      }
    } else {
      const sess = state.sessions[state.activeSession];
      if (sess) {
        try {
          client.sendDMMessage(sess.peer, sess.roomID, sess.roomKey, text);
          appendMessage(state.me.address, text, Date.now(), true, sess.peer);
        } catch (err) {
          appendMessage("system", `Failed to send DM: ${err.message || err}`, Date.now(), false, sess.peer);
          return;
        }
      }
    }
    input.value = "";
  };

  $("file-input").onchange = async (e) => {
    if (state.isEvicted && state.activeSession === "main") return;
    const file = e.target.files[0];
    if (!file) return;
    e.target.value = "";

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const res = client.shareAttachment(file.name, file.type || "application/octet-stream", bytes);
      const blobUrl = trackBlobUrl(URL.createObjectURL(file));
      appendAttachment(res, blobUrl, true);
    } catch (err) {
      console.error("file sharing failed", err);
      appendMessage("system", `File share failed: ${err.message || err}`, Date.now(), false);
    }
  };

  document.addEventListener("click", () => {
    document.querySelectorAll(".peer-context-menu").forEach((m) => {
      m.style.display = "none";
    });
  });

  window.addEventListener("hashchange", () => {
    const params = window.CotillaClient.parseLink(window.location.hash);
    if (params && (params.room !== state.roomID || params.key !== state.roomKey)) {
      enterSessionFromLink(window.location.hash).catch((err) => {
        console.error("hashchange join error:", err);
      });
    }
  });
}

// ---- Main ----

async function main() {
  bindClientEvents();
  setupUI();
  setupMedia();
  updateVideoGridVisibility();
  await client.loadWasm();

  const hashParams = window.CotillaClient.parseLink(window.location.hash);
  if (hashParams) {
    await enterSessionFromLink(window.location.hash);
  } else {
    $("landing").style.display = "flex";
  }
}

main();
