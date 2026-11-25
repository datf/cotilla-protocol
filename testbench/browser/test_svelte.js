const puppeteer = require("puppeteer-core");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SERVER_URL = process.env.SERVER_URL || "http://cotilla-signaling:8080";
const SVELTE_URL = process.env.SVELTE_URL || `${SERVER_URL}/svelte/`;
const SEEDER_URL = process.env.SEEDER_URL || "http://cotilla-seeder:8081";
const NATIVE_ALICE_URL = process.env.NATIVE_ALICE_URL || "http://cotilla-alice:8080";
const NATIVE_BOB_URL = process.env.NATIVE_BOB_URL || "http://cotilla-bob:8080";
const NATIVE_CHARLIE_URL = process.env.NATIVE_CHARLIE_URL || "http://cotilla-charlie:8080";

const colorReset = "\x1b[0m";
const colorGreen = "\x1b[32m";
const colorCyan = "\x1b[36m";
const colorRed = "\x1b[31m";
const colorBold = "\x1b[1m";

function logStep(step, msg) {
  console.log(`\n${colorBold}${colorCyan}[${step}] ${msg}${colorReset}`);
}

function logPass(msg) {
  console.log(`   ${colorGreen}✓${colorReset} ${msg}`);
}

function logFail(msg) {
  console.error(`   ${colorRed}✗ ${msg}${colorReset}`);
  process.exit(1);
}

function fetchJSON(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    }).on("error", reject);
  });
}

function postJSON(url, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = http.request(
      url,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(data);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

async function waitForSeederReady(timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const health = await fetchJSON(`${SEEDER_URL}/health`);
      if (
        health &&
        health.status === "seeding" &&
        health.app_id === "cotilla-svelte" &&
        Array.isArray(health.connected_peers) &&
        health.connected_peers.length >= 1
      ) {
        return health;
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  logFail(`Timed out waiting for cotilla-seeder at ${SEEDER_URL}/health`);
}

function attachStrictObservers(page, label, opts = {}) {
  const state = {
    pageErrors: [],
    consoleErrors: [],
    forbiddenRequests: [],
    debugLogs: [],
    consoleLogs: [],
  };

  page.on("pageerror", (err) => {
    const msg = err && err.message ? err.message : String(err);
    console.error(`[${label} PageError] ${msg}`);
    state.pageErrors.push(msg);
  });

  page.on("console", (msg) => {
    const type = msg.type();
    const text = msg.text();
    if (type === "debug" || type === "info") {
      state.debugLogs.push(text);
    }
    state.consoleLogs.push(`[${type}] ${text}`);
    if (state.consoleLogs.length > 250) {
      state.consoleLogs.shift();
    }
    if (type === "error") {
      // Offline Google Fonts stylesheet fails to resolve in isolated container networks.
      if (text.includes("ERR_NAME_NOT_RESOLVED") || text.includes("fonts.googleapis.com")) {
        return;
      }
      if (opts.allowConsoleErrorPredicate && opts.allowConsoleErrorPredicate(text)) {
        return;
      }
      console.error(`[${label} ConsoleError] ${text}`);
      state.consoleErrors.push(text);
    }
  });

  page.on("response", (res) => {
    if (res.status() >= 400) {
      console.error(`[${label} HTTP ${res.status()}] ${res.url()}`);
    }
  });

  page.on("request", (req) => {
    const url = req.url();
    if (
      url.includes("cotilla.wasm") ||
      url.includes("cotilla.js") ||
      url.includes("wasm_exec.js") ||
      url.includes("sframe-worker.js") ||
      url.includes("/_app/")
    ) {
      console.error(`[${label} ForbiddenHTTPRequest] ${url}`);
      state.forbiddenRequests.push(url);
    }
  });

  return state;
}

function assertCleanPage(state, label) {
  if (state.pageErrors.length > 0) {
    logFail(`${label} recorded ${state.pageErrors.length} uncaught pageerror(s): ${JSON.stringify(state.pageErrors)}`);
  }
  if (state.consoleErrors.length > 0) {
    logFail(`${label} recorded ${state.consoleErrors.length} console.error(s): ${JSON.stringify(state.consoleErrors)}`);
  }
  if (state.forbiddenRequests.length > 0) {
    logFail(`${label} made forbidden HTTP requests (expected 100% self-contained bootstrap+seeder bundle): ${JSON.stringify(state.forbiddenRequests)}`);
  }
}

async function openSeededSveltePage(ctx, url, label, opts = {}) {
  const page = await ctx.newPage();
  const obs = attachStrictObservers(page, label, opts);
  await page.goto(url, { waitUntil: "domcontentloaded" });

  // Wait for bootstrap -> seeder download -> Svelte UI mount
  await page.waitForFunction(
    () =>
      window.__COTILLA_BOOTSTRAP__ &&
      window.__COTILLA_BOOTSTRAP__.manifest &&
      window.__COTILLA_BOOTSTRAP__.manifest.app_id === "cotilla-svelte" &&
      window.cotillaApp &&
      window.cotillaApp.wasmReady === true &&
      document.getElementById("app") !== null,
    { timeout: 30000 }
  );

  // Allow one short tick for any post-shutdown bootstrap DataChannel close handlers to flush
  await new Promise((r) => setTimeout(r, 300));
  assertCleanPage(obs, label);
  return { page, obs };
}

async function clickButtonByText(page, textSubstring) {
  const clicked = await page.evaluate((sub) => {
    const buttons = Array.from(document.querySelectorAll("button"));
    const target = buttons.find((b) => !b.disabled && (b.textContent || "").includes(sub));
    if (!target) return false;
    target.click();
    return true;
  }, textSubstring);
  if (!clicked) {
    logFail(`Could not find enabled button matching "${textSubstring}"`);
  }
}

async function clickButtonByTitle(page, titleSubstring) {
  const clicked = await page.evaluate((sub) => {
    const buttons = Array.from(document.querySelectorAll("button"));
    const target = buttons.find((b) => !b.disabled && (b.getAttribute("title") || "").includes(sub));
    if (!target) return false;
    target.click();
    return true;
  }, titleSubstring);
  if (!clicked) {
    logFail(`Could not find enabled button with title matching "${titleSubstring}"`);
  }
}

async function sendSvelteChat(page, text) {
  const inputSel = 'input[type="text"][placeholder*="encrypted message"], input[type="text"][placeholder*="private message"]';
  await page.waitForSelector(inputSel, { visible: true, timeout: 10000 });
  await page.type(inputSel, text);
  await page.click('button[title="Send message"]');
}

async function waitSvelteMessage(page, text, timeoutMs = 15000, obs = null, label = "page") {
  try {
    await page.waitForFunction(
      (expected) => {
        const main = document.querySelector("main");
        return main && (main.textContent || "").includes(expected);
      },
      { timeout: timeoutMs },
      text
    );
  } catch (err) {
    const snap = await page
      .evaluate(() => ({
        inRoom: window.cotillaApp?.inRoom,
        roomID: window.cotillaApp?.roomID,
        me: window.cotillaApp?.me?.address,
        activeEpoch: window.cotillaApp?.activeEpoch,
        wasmEpoch: window.cotilla ? window.cotilla.currentEpoch() : -1,
        connectedPeers: window.cotilla ? JSON.parse(window.cotilla.connectedPeers()) : [],
        activeSessionId: window.cotillaApp?.activeSessionId,
        directPeerCount: window.cotillaApp?.directPeerCount,
        peerCount: window.cotillaApp?.peerCount,
        peers: Array.from(window.cotillaApp?.peers?.keys?.() || []),
        msgCount: (window.cotillaApp?.messages?.get?.("main") || []).length,
        msgs: (window.cotillaApp?.messages?.get?.("main") || []).map((m) => m.text),
        mainText: document.querySelector("main")?.textContent?.slice(0, 300) || null,
      }))
      .catch((e) => ({ evalErr: String(e) }));
    console.error(`[${label} waitSvelteMessage FAIL] expected=${text} snap=${JSON.stringify(snap)}`);
    if (obs && obs.consoleLogs) {
      console.error(`[${label} recent consoleLogs]:\n${obs.consoleLogs.slice(-60).join("\n")}`);
    }
    throw err;
  }
}

async function waitCallStats(page, predicate, timeoutMs = 20000, label = "call stats") {
  const deadline = Date.now() + timeoutMs;
  let lastStats = null;
  while (Date.now() < deadline) {
    lastStats = await page.evaluate(() => (window.cotillaClient ? window.cotillaClient.getCallStats() : null));
    if (lastStats && predicate(lastStats)) {
      return lastStats;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  logFail(`Timed out waiting for ${label}; lastStats=${JSON.stringify(lastStats)}`);
}

function makeUniqueAttachmentFile(name, sizeBytes, seedByte) {
  const tmpPath = path.join(os.tmpdir(), `${Date.now()}-${seedByte}-${name}`);
  const buf = Buffer.alloc(sizeBytes);
  for (let i = 0; i < sizeBytes; i++) {
    buf[i] = (seedByte + i * 31 + (i >> 8)) & 0xff;
  }
  fs.writeFileSync(tmpPath, buf);
  return tmpPath;
}

async function launchChromium({ secure = true } = {}) {
  const args = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--autoplay-policy=no-user-gesture-required",
  ];
  if (secure) {
    args.push(
      `--unsafely-treat-insecure-origin-as-secure=${SERVER_URL}`,
      "--use-fake-ui-for-media-stream",
      "--use-fake-device-for-media-stream",
      "--enable-usermedia-screen-capturing",
      "--auto-select-desktop-capture-source=Entire screen"
    );
  }
  return puppeteer.launch({
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
    headless: "new",
    defaultViewport: { width: 1280, height: 800 },
    args,
  });
}

async function runSvelteE2E() {
  console.log(`\n${colorBold}${colorCyan}=== Cotilla Bootstrap -> Seeder -> Svelte E2E Suite ===${colorReset}`);
  console.log(`Target Bootstrap URL: ${SVELTE_URL}`);
  console.log(`Seeder Health URL:    ${SEEDER_URL}/health`);

  const seederHealth = await waitForSeederReady();
  logPass(`Seeder active: app=${seederHealth.app_id}, seq=${seederHealth.seq}, file=${seederHealth.file_id}`);

  // ===========================================================================
  // PART A: SECURE CONTEXT (3+ Svelte Browsers + Seeder + Mixed Native Mesh)
  // ===========================================================================
  const browser = await launchChromium({ secure: true });
  try {
    const defaultCtx = browser.defaultBrowserContext();
    try {
      await defaultCtx.overridePermissions(SERVER_URL, ["microphone", "camera"]);
    } catch {}

    // -------------------------------------------------------------------------
    // STEP 1: 3-Peer Bootstrap -> Seeder Download -> Svelte Room Creation & Join
    // -------------------------------------------------------------------------
    logStep("1/5", "3-peer Bootstrap -> Seeder -> Svelte launch & invite hash preservation...");
    const ctx1 = await browser.createBrowserContext();
    const ctx2 = await browser.createBrowserContext();
    const ctx3 = await browser.createBrowserContext();
    for (const ctx of [ctx1, ctx2, ctx3]) {
      await ctx.overridePermissions(SERVER_URL, ["microphone", "camera"]).catch(() => {});
    }

    const { page: p1, obs: obs1 } = await openSeededSveltePage(ctx1, SVELTE_URL, "Svelte-P1");
    logPass("Peer 1 bootstrapped cotilla-svelte via seeder with 0 JS/WASM errors and 0 extra HTTP requests.");

    await clickButtonByText(p1, "Create Burner Room");
    await p1.waitForFunction(
      () => window.cotillaApp && window.cotillaApp.inRoom && window.cotillaApp.currentRoomHash && window.cotillaApp.me?.address,
      { timeout: 15000 }
    );
    const inviteHash = await p1.evaluate(() => window.cotillaApp.currentRoomHash);
    const p1Addr = await p1.evaluate(() => window.cotillaApp.me.address);
    const inviteURL = `${SVELTE_URL}${inviteHash.startsWith("#") ? inviteHash : "#" + inviteHash}`;

    const [{ page: p2, obs: obs2 }, { page: p3, obs: obs3 }] = await Promise.all([
      openSeededSveltePage(ctx2, inviteURL, "Svelte-P2"),
      openSeededSveltePage(ctx3, inviteURL, "Svelte-P3"),
    ]);

    try {
      await Promise.all([
        p1.waitForFunction(() => window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
        p2.waitForFunction(() => window.cotillaApp.inRoom && window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
        p3.waitForFunction(() => window.cotillaApp.inRoom && window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
      ]);
    } catch (waitErr) {
      const snap = async (pg) => pg.evaluate(() => ({
        inRoom: window.cotillaApp?.inRoom,
        directPeerCount: window.cotillaApp?.directPeerCount,
        activeEpoch: window.cotillaApp?.activeEpoch,
        peers: window.cotillaApp?.peers,
        connected: window.cotilla ? JSON.parse(window.cotilla.connectedPeers()) : [],
        status: window.cotillaApp?.statusText,
      })).catch((e) => ({ evalErr: e.message }));
      console.error("[DEBUG] Mesh timeout snapshot:", JSON.stringify({
        p1: await snap(p1), p2: await snap(p2), p3: await snap(p3),
      }, null, 2));
      throw waitErr;
    }
    const p2Addr = await p2.evaluate(() => window.cotillaApp.me.address);
    const p3Addr = await p3.evaluate(() => window.cotillaApp.me.address);
    logPass(`All 3 Svelte peers bootstrapped and formed direct WebRTC mesh (epoch >= 1, 0 errors).`);

    // -------------------------------------------------------------------------
    // STEP 2: 3-Peer Chat, On-Demand Unique Attachment, 1:1 DM, Rotate, Evict
    // -------------------------------------------------------------------------
    logStep("2/5", "Testing 3-peer Svelte chat, on-demand attachment, 1:1 DM, key rotation & eviction...");
    const msg1 = `Svelte-P1-hello-${Date.now()}`;
    const msg2 = `Svelte-P2-reply-${Date.now()}`;
    await sendSvelteChat(p1, msg1);
    await Promise.all([
      waitSvelteMessage(p2, msg1, 15000, obs2, "Svelte-P2"),
      waitSvelteMessage(p3, msg1, 15000, obs3, "Svelte-P3"),
    ]);
    await sendSvelteChat(p2, msg2);
    await Promise.all([waitSvelteMessage(p1, msg2), waitSvelteMessage(p3, msg2)]);
    logPass("3-peer bidirectional encrypted chat verified.");

    // Unique-seed attachment upload on P1 -> On-demand download on P2
    const attachPath = makeUniqueAttachmentFile("svelte-e2e-doc.bin", 128 * 1024, 73);
    try {
      const fileInput = await p1.$('input[type="file"]');
      await fileInput.uploadFile(attachPath);
      await p2.waitForFunction(
        () => Array.from(document.querySelectorAll("main button")).some((b) => (b.textContent || "").includes("Download")),
        { timeout: 15000 }
      );
      await p3.waitForFunction(
        () => Array.from(document.querySelectorAll("main button")).some((b) => (b.textContent || "").includes("Download")),
        { timeout: 15000 }
      );
      // Ensure P2 did NOT auto-download and no app-dist bundle leaked into user chat
      const autoDownloadInfo = await p2.evaluate(() => ({
        links: Array.from(document.querySelectorAll("main a[download]")).map((a) => ({
          href: a.getAttribute("href"),
          download: a.getAttribute("download"),
          text: a.textContent,
        })),
        msgs: window.cotillaApp?.messages?.get?.("main") || [],
      }));
      if (autoDownloadInfo.msgs.some((m) => m?.name === "cotilla-svelte.html")) {
        logFail(`App-dist bundle leaked into user Group Room chat feed: ${JSON.stringify(autoDownloadInfo.msgs)}`);
      }
      if (autoDownloadInfo.links.some((a) => (a.text || "").includes("Save File"))) {
        logFail(`Peer 2 auto-downloaded attachment instead of waiting for user click! debug=${JSON.stringify(autoDownloadInfo)}`);
      }
      await clickButtonByText(p2, "Download");
      await p2.waitForFunction(
        () => Array.from(document.querySelectorAll("main a[download]")).some((a) => (a.textContent || "").includes("Save File")),
        { timeout: 15000 }
      );
      logPass("On-demand attachment offer & chunk download verified across Svelte UI.");
    } finally {
      try { fs.unlinkSync(attachPath); } catch {}
    }

    // 1:1 DM from P1 to P2 via Peer Context Menu
    const openMenuForPeer = async (page, shortAddr) => {
      const opened = await page.evaluate((short) => {
        const items = Array.from(document.querySelectorAll("aside li"));
        const row = items.find((li) => (li.textContent || "").includes(short));
        if (!row) return false;
        const btn = row.querySelector('button[title="Member actions"]');
        if (!btn) return false;
        btn.click();
        return true;
      }, shortAddr);
      if (!opened) logFail(`Could not open Member actions menu for ${shortAddr}`);
    };

    await openMenuForPeer(p1, p2Addr.slice(0, 8));
    await clickButtonByText(p1, "Direct Message");
    await p2.waitForFunction(
      () => Array.from(document.querySelectorAll("button")).some((b) => (b.textContent || "").includes("Accept & Join")),
      { timeout: 10000 }
    );
    await clickButtonByText(p2, "Accept & Join");
    await p2.waitForFunction(
      (addr) => window.cotillaApp.activeSessionId === addr,
      { timeout: 10000 },
      p1Addr
    );
    const dmSecret = `Svelte-DM-Secret-${Date.now()}`;
    await sendSvelteChat(p1, dmSecret);
    await waitSvelteMessage(p2, dmSecret, 15000);
    const p3SawDM = await p3.evaluate((s) => (document.querySelector("main")?.innerText || "").includes(s), dmSecret);
    if (p3SawDM) {
      logFail("Peer 3 unexpectedly saw private 1:1 DM between Peer 1 and Peer 2!");
    }
    logPass("1:1 DM session isolation verified (Peer 3 cannot observe DM).");

    // Switch back to Group Room, rotate epoch, and evict Peer 3
    await clickButtonByText(p1, "Group Room");
    await p1.evaluate(() => window.cotillaApp.rotateKey());
    await p1.waitForFunction(() => window.cotillaApp.activeEpoch >= 2, { timeout: 10000 });

    await openMenuForPeer(p1, p3Addr.slice(0, 8));
    await clickButtonByText(p1, "Evict Member");
    await p1.waitForFunction(() => (document.body.innerText || "").includes("Evict Member?"), { timeout: 5000 });
    await p1.evaluate(() => {
      const btns = Array.from(document.querySelectorAll("button"));
      const confirmBtn = btns.reverse().find((b) => (b.textContent || "").includes("Evict Member"));
      if (confirmBtn) confirmBtn.click();
    });
    await p3.waitForFunction(() => window.cotillaApp.isEvicted === true, { timeout: 15000 });
    logPass("Key rotation & member eviction verified; evicted peer locked out.");

    // -------------------------------------------------------------------------
    // STEP 3: 3-Peer Secondary WebRTC SFrame Group Call (Audio + Video)
    // -------------------------------------------------------------------------
    logStep("3/5", "Testing 3-peer Svelte SFrame Group Call (Audio + Video)...");
    // Add Peer 4 via fresh post-eviction invite so P1, P2, P4 form a clean 3-peer group call
    const p1EpochBefore = await p1.evaluate(() => window.cotillaApp.activeEpoch);
    const freshHash2 = await p1.evaluate(() => window.cotillaApp.client.getInviteData(15 * 60 * 1000).hash);
    const inviteURL2 = `${SVELTE_URL}${freshHash2.startsWith("#") ? freshHash2 : "#" + freshHash2}`;
    const ctx4 = await browser.createBrowserContext();
    await ctx4.overridePermissions(SERVER_URL, ["microphone", "camera"]).catch(() => {});
    const { page: p4, obs: obs4 } = await openSeededSveltePage(ctx4, inviteURL2, "Svelte-P4");
    await Promise.all([
      p1.waitForFunction((ep) => window.cotillaApp.activeEpoch > ep, { timeout: 25000 }, p1EpochBefore),
      p2.waitForFunction((ep) => window.cotillaApp.activeEpoch > ep, { timeout: 25000 }, p1EpochBefore),
      p4.waitForFunction(
        (ep) => window.cotillaApp.inRoom && window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch > ep,
        { timeout: 25000 },
        p1EpochBefore
      ),
    ]);

    await Promise.all([
      clickButtonByText(p1, "Group Call"),
      clickButtonByText(p2, "Group Call"),
      clickButtonByText(p4, "Group Call"),
    ]);

    await Promise.all([
      p1.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
      p2.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
      p4.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
    ]);
    await Promise.all([
      clickButtonByTitle(p1, "Enable Microphone"),
      clickButtonByTitle(p2, "Enable Microphone"),
      clickButtonByTitle(p4, "Enable Microphone"),
    ]);
    await clickButtonByTitle(p1, "Turn On Camera");

    await Promise.all([
      waitCallStats(p1, (s) => s.secondaryPeerCount >= 2 && s.sframe.encryptedAudio > 0 && s.sframe.encryptedVideo > 0 && s.sframe.decryptedAudio > 0 && s.sframe.pipeErrors === 0 && s.sframe.rejected === 0, 25000, "Svelte-P1 3-peer SFrame call"),
      waitCallStats(p2, (s) => s.secondaryPeerCount >= 2 && s.sframe.decryptedAudio > 0 && s.sframe.decryptedVideo > 0 && s.sframe.pipeErrors === 0 && s.sframe.rejected === 0, 25000, "Svelte-P2 3-peer SFrame call"),
      waitCallStats(p4, (s) => s.secondaryPeerCount >= 2 && s.sframe.decryptedAudio > 0 && s.sframe.decryptedVideo > 0 && s.sframe.pipeErrors === 0 && s.sframe.rejected === 0, 25000, "Svelte-P4 3-peer SFrame call"),
    ]);
    logPass("3-peer Svelte SFrame Audio+Video call verified (0 pipeErrors, 0 rejected frames).");

    assertCleanPage(obs1, "Svelte-P1");
    assertCleanPage(obs2, "Svelte-P2");
    assertCleanPage(obs3, "Svelte-P3");
    assertCleanPage(obs4, "Svelte-P4");

    await Promise.all([ctx1.close(), ctx2.close(), ctx3.close(), ctx4.close()]);

    // -------------------------------------------------------------------------
    // STEP 4: Mixed Mesh — 3 Seeded Svelte Chromium + 3 Native Go Containers
    // -------------------------------------------------------------------------
    logStep("4/5", "Testing 6-client mixed mesh (3 Svelte Chromium + 3 Native Go containers)...");
    const mixedRoomURL = `${SVELTE_URL}#room=bench-ephemeral-room-1234&key=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY`;
    const mCtx1 = await browser.createBrowserContext();
    const mCtx2 = await browser.createBrowserContext();
    const mCtx3 = await browser.createBrowserContext();
    for (const ctx of [mCtx1, mCtx2, mCtx3]) {
      await ctx.overridePermissions(SERVER_URL, ["microphone", "camera"]).catch(() => {});
    }

    const [{ page: mp1, obs: mObs1 }, { page: mp2, obs: mObs2 }, { page: mp3, obs: mObs3 }] = await Promise.all([
      openSeededSveltePage(mCtx1, mixedRoomURL, "Mixed-Svelte-1"),
      openSeededSveltePage(mCtx2, mixedRoomURL, "Mixed-Svelte-2"),
      openSeededSveltePage(mCtx3, mixedRoomURL, "Mixed-Svelte-3"),
    ]);

    await Promise.all([
      mp1.waitForFunction(() => window.cotillaApp.directPeerCount >= 5, { timeout: 25000 }),
      mp2.waitForFunction(() => window.cotillaApp.directPeerCount >= 5, { timeout: 25000 }),
      mp3.waitForFunction(() => window.cotillaApp.directPeerCount >= 5, { timeout: 25000 }),
    ]);

    const nativeMsg = `Native-Alice-to-Svelte-${Date.now()}`;
    await postJSON(`${NATIVE_ALICE_URL}/send`, { text: nativeMsg });
    await Promise.all([
      waitSvelteMessage(mp1, nativeMsg, 15000, mObs1, "Mixed-Svelte-1"),
      waitSvelteMessage(mp2, nativeMsg, 15000, mObs2, "Mixed-Svelte-2"),
      waitSvelteMessage(mp3, nativeMsg, 15000, mObs3, "Mixed-Svelte-3"),
    ]);

    const svelteToNativeMsg = `Svelte-1-to-Native-${Date.now()}`;
    await sendSvelteChat(mp1, svelteToNativeMsg);
    const nativeDeadline = Date.now() + 15000;
    let nativeGotSvelte = false;
    while (Date.now() < nativeDeadline) {
      const msgs = await fetchJSON(`${NATIVE_BOB_URL}/messages`);
      if (Array.isArray(msgs) && msgs.some((m) => m.text && m.text.includes(svelteToNativeMsg))) {
        nativeGotSvelte = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!nativeGotSvelte) logFail("Native Bob did not receive message from Svelte-1!");
    logPass("Bidirectional chat verified across 3 Svelte Chromium + 3 Native Go clients (6-peer mixed mesh).");

    // Mixed-mesh SFrame A/V call across 3 Svelte + 3 Native Go
    const [beforeA, beforeB, beforeC] = await Promise.all([
      fetchJSON(`${NATIVE_ALICE_URL}/call/stats`),
      fetchJSON(`${NATIVE_BOB_URL}/call/stats`),
      fetchJSON(`${NATIVE_CHARLIE_URL}/call/stats`),
    ]);
    await Promise.all([
      postJSON(`${NATIVE_ALICE_URL}/call/join`, { audio: true, video: true }),
      postJSON(`${NATIVE_BOB_URL}/call/join`, { audio: true, video: true }),
      postJSON(`${NATIVE_CHARLIE_URL}/call/join`, { audio: true, video: true }),
    ]);
    await Promise.all([
      clickButtonByText(mp1, "Group Call"),
      clickButtonByText(mp2, "Group Call"),
      clickButtonByText(mp3, "Group Call"),
    ]);
    await Promise.all([
      mp1.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
      mp2.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
      mp3.waitForSelector('button[title="Enable Microphone"]', { visible: true, timeout: 10000 }),
    ]);
    await Promise.all([
      clickButtonByTitle(mp1, "Enable Microphone"),
      clickButtonByTitle(mp2, "Enable Microphone"),
      clickButtonByTitle(mp3, "Enable Microphone"),
    ]);
    await clickButtonByTitle(mp1, "Turn On Camera");

    const opusSilenceB64 = Buffer.from([0xf8, 0xff, 0xfe]).toString("base64");
    const callDeadline = Date.now() + 25000;
    let mixedCallOK = false;
    while (Date.now() < callDeadline) {
      await postJSON(`${NATIVE_ALICE_URL}/call/send-media`, { kind: "audio", payload: opusSilenceB64, count: 2 }).catch(() => {});
      const [stA, stB, stC, w1, w2, w3] = await Promise.all([
        fetchJSON(`${NATIVE_ALICE_URL}/call/stats`),
        fetchJSON(`${NATIVE_BOB_URL}/call/stats`),
        fetchJSON(`${NATIVE_CHARLIE_URL}/call/stats`),
        mp1.evaluate(() => window.cotillaClient.getCallStats()),
        mp2.evaluate(() => window.cotillaClient.getCallStats()),
        mp3.evaluate(() => window.cotillaClient.getCallStats()),
      ]);
      const nativeOk = (st, before) =>
        Array.isArray(st.channel_call_peers) &&
        st.channel_call_peers.length >= 5 &&
        st.stats &&
        st.stats.decrypted_audio > (before?.stats?.decrypted_audio || 0) &&
        st.stats.decrypted_video > (before?.stats?.decrypted_video || 0) &&
        st.stats.rejected === 0;
      const webOk = (s) =>
        s && s.secondaryPeerCount >= 5 && s.sframe.decryptedAudio > 0 && s.sframe.pipeErrors === 0 && s.sframe.rejected === 0;
      if (nativeOk(stA, beforeA) && nativeOk(stB, beforeB) && nativeOk(stC, beforeC) && webOk(w1) && webOk(w2) && webOk(w3)) {
        mixedCallOK = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    if (!mixedCallOK) logFail("Mixed-mesh 6-client SFrame call did not complete cleanly!");
    logPass("Mixed-mesh SFrame A/V call verified across 3 Svelte Chromium + 3 Native Go clients.");

    await Promise.all([
      postJSON(`${NATIVE_ALICE_URL}/call/leave`, { clear_frames: true }),
      postJSON(`${NATIVE_BOB_URL}/call/leave`, { clear_frames: true }),
      postJSON(`${NATIVE_CHARLIE_URL}/call/leave`, { clear_frames: true }),
    ]);

    assertCleanPage(mObs1, "Mixed-Svelte-1");
    assertCleanPage(mObs2, "Mixed-Svelte-2");
    assertCleanPage(mObs3, "Mixed-Svelte-3");
    await Promise.all([mCtx1.close(), mCtx2.close(), mCtx3.close()]);
  } finally {
    await browser.close();
  }

  // ===========================================================================
  // PART B: INSECURE NON-LOCALHOST HTTP CONTEXT (Reproducing http://homeassistant:8902)
  // ===========================================================================
  logStep("5/5", "Testing insecure non-localhost HTTP origin (isSecureContext === false, reproducing LAN HTTP)...");
  const insecureBrowser = await launchChromium({ secure: false });
  try {
    const iCtx1 = await insecureBrowser.createBrowserContext();
    const iCtx2 = await insecureBrowser.createBrowserContext();
    const iCtx3 = await insecureBrowser.createBrowserContext();

    const { page: ip1, obs: iObs1 } = await openSeededSveltePage(iCtx1, SVELTE_URL, "Insecure-P1");
    const isSecure = await ip1.evaluate(() => window.isSecureContext);
    if (isSecure !== false) {
      logFail(`Expected window.isSecureContext === false for ${SVELTE_URL}, got ${isSecure}`);
    }
    logPass("Insecure HTTP bootstrap -> Svelte launch completed with 0 JS/WASM errors.");

    await clickButtonByText(ip1, "Create Burner Room");
    await ip1.waitForFunction(() => window.cotillaApp && window.cotillaApp.inRoom && window.cotillaApp.currentRoomHash, { timeout: 15000 });
    const insecureInvite = `${SVELTE_URL}${await ip1.evaluate(() => window.cotillaApp.currentRoomHash)}`;

    const [{ page: ip2, obs: iObs2 }, { page: ip3, obs: iObs3 }] = await Promise.all([
      openSeededSveltePage(iCtx2, insecureInvite, "Insecure-P2"),
      openSeededSveltePage(iCtx3, insecureInvite, "Insecure-P3"),
    ]);

    await Promise.all([
      ip1.waitForFunction(() => window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
      ip2.waitForFunction(() => window.cotillaApp.inRoom && window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
      ip3.waitForFunction(() => window.cotillaApp.inRoom && window.cotillaApp.directPeerCount >= 2 && window.cotillaApp.activeEpoch >= 1, { timeout: 25000 }),
    ]);

    const insecureChat = `Insecure-HTTP-Chat-${Date.now()}`;
    await sendSvelteChat(ip1, insecureChat);
    await Promise.all([
      waitSvelteMessage(ip2, insecureChat, 15000, iObs2, "Insecure-P2"),
      waitSvelteMessage(ip3, insecureChat, 15000, iObs3, "Insecure-P3"),
    ]);
    logPass("3-peer text chat works cleanly on insecure LAN HTTP origin.");

    // Attempt to join Group Call -> must notify user cleanly without uncaught importKey errors
    await clickButtonByText(ip1, "Group Call");
    await ip1.waitForFunction(() => (document.body.innerText || "").includes("HTTPS or localhost"), { timeout: 5000 });
    const joinedAfterFail = await ip1.evaluate(() => window.cotillaApp.callJoined);
    if (joinedAfterFail) {
      logFail("Expected callJoined to remain false on insecure HTTP origin!");
    }
    logPass("Joining Group Call on insecure HTTP shows clean HTTPS/localhost error toast with 0 uncaught worker errors.");

    // Attempt Settings -> Test Mic -> must notify cleanly without uncaught errors
    await clickButtonByTitle(ip1, "Device & Audio Preferences");
    await ip1.waitForFunction(
      () => Array.from(document.querySelectorAll("button")).some((b) => (b.textContent || "").includes("Test Mic")),
      { timeout: 5000 }
    );
    await clickButtonByText(ip1, "Test Mic");
    await ip1.waitForFunction(() => (document.body.innerText || "").includes("Microphone access requires HTTPS or localhost"), { timeout: 5000 });
    logPass("Testing Mic in Settings on insecure HTTP shows clean HTTPS/localhost toast with 0 uncaught errors.");

    assertCleanPage(iObs1, "Insecure-P1");
    assertCleanPage(iObs2, "Insecure-P2");
    assertCleanPage(iObs3, "Insecure-P3");

    await Promise.all([iCtx1.close(), iCtx2.close(), iCtx3.close()]);
  } finally {
    await insecureBrowser.close();
  }

  console.log(`\n${colorBold}${colorGreen}=== ALL SVELTE BOOTSTRAP + SEEDER E2E SCENARIOS PASSED! ===${colorReset}\n`);
}

runSvelteE2E().catch((err) => {
  logFail(`Unhandled error in runSvelteE2E: ${err.message}\n${err.stack}`);
});
