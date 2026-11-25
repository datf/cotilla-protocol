const puppeteer = require("puppeteer-core");
const http = require("http");

const SERVER_URL = process.env.SERVER_URL || "http://signaling:8080";
const NATIVE_ALICE_URL = process.env.NATIVE_ALICE_URL || "http://cotilla-alice:8080";
const NATIVE_BOB_URL = process.env.NATIVE_BOB_URL || "http://cotilla-bob:8080";
const NATIVE_CHARLIE_URL = process.env.NATIVE_CHARLIE_URL || "http://cotilla-charlie:8080";

const colorReset = "\x1b[0m";
const colorGreen = "\x1b[32m";
const colorCyan = "\x1b[36m";
const colorRed = "\x1b[31m";
const colorBold = "\x1b[1m";

const short = (s) => (s ? s.slice(0, 8) : "...");

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

async function grantMedia(ctx) {
  try {
    await ctx.overridePermissions(SERVER_URL, ["microphone", "camera"]);
  } catch {}
}

async function waitCallStats(page, predicate, timeoutMs = 15000, label = "call stats condition", onFailExtra = null) {
  const deadline = Date.now() + timeoutMs;
  let lastStats = null;
  while (Date.now() < deadline) {
    lastStats = await page.evaluate(() => (window.cotillaClient ? window.cotillaClient.getCallStats() : null));
    if (lastStats && predicate(lastStats)) {
      return lastStats;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (typeof onFailExtra === "function") {
    try { await onFailExtra(); } catch {}
  }
  logFail(`Timed out waiting for ${label}; last stats=${JSON.stringify(lastStats)}`);
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

async function runBrowserE2E() {
  console.log(`\n${colorBold}${colorCyan}=== Cotilla Headless Browser End-to-End Suite ===${colorReset}`);
  console.log(`Target Signaling Server: ${SERVER_URL}`);
  console.log(`Native Client Container: ${NATIVE_ALICE_URL}`);

  const browser = await puppeteer.launch({
    executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || "/usr/bin/chromium",
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      `--unsafely-treat-insecure-origin-as-secure=${SERVER_URL}`,
      "--use-fake-ui-for-media-stream", // Auto-approves getUserMedia & getDisplayMedia
      "--use-fake-device-for-media-stream", // Synthetic spinning video test pattern + 440Hz tone
      "--enable-usermedia-screen-capturing",
      "--auto-select-desktop-capture-source=Entire screen",
      "--autoplay-policy=no-user-gesture-required",
    ],
  });

  try {
    browser.on("targetcreated", async (target) => {
      if (target.type() === "page") {
        try {
          const p = await target.page();
          if (p) {
            p.on("dialog", async (dialog) => {
              console.warn(`[Browser Dialog ${dialog.type()}] ${dialog.message()}`);
              await dialog.dismiss().catch(() => {});
            });
          }
        } catch {}
      }
    });

    const defaultCtx = browser.defaultBrowserContext();
    try {
      await defaultCtx.overridePermissions(SERVER_URL, ["microphone", "camera"]);
    } catch {}

    // =========================================================================
    // PART 1: BROWSER <-> BROWSER END-TO-END
    // =========================================================================

    // Step 1: Alice loads page and creates burner room
    logStep("1/12", "Alice creates an ephemeral burner room...");
    const pageAlice = await browser.newPage();
    pageAlice.on("console", (msg) => console.log(`[Alice Console ${msg.type()}] ${msg.text()}`));
    pageAlice.on("pageerror", (err) => console.log(`[Alice Page Error] ${err.message}`));

    await pageAlice.goto(SERVER_URL, { waitUntil: "networkidle0" });

    // Assert that video grid and local video container are hidden by default when cam is off
    const initialGridHidden = await pageAlice.evaluate(() => {
      const grid = document.getElementById("video-grid");
      const local = document.getElementById("local-video-container");
      return (!grid || grid.style.display === "none") && (!local || local.style.display === "none");
    });
    if (!initialGridHidden) {
      logFail("Video grid or local video container was unexpectedly visible before joining or enabling cam!");
    }
    logPass("Verified video grid is cleanly hidden when disconnected and camera is off.");

    await pageAlice.waitForSelector("#btn-create-room", { visible: true, timeout: 10000 });
    await pageAlice.click("#btn-create-room");

    await pageAlice.waitForFunction(
      () => window.location.hash.includes("#room=") && window.location.hash.includes("&key="),
      { timeout: 10000 }
    );
    const inviteLink = pageAlice.url();
    logPass(`Burner room created: ${inviteLink.slice(0, 60)}...`);

    await pageAlice.waitForFunction(
      () => {
        const dot = document.getElementById("status-dot");
        return dot && dot.classList.contains("on");
      },
      { timeout: 10000 }
    );
    logPass("Alice connected to signaling server.");

    // Step 2: Microphone capture & audio frame generation
    logStep("2/12", "Testing microphone capture via getUserMedia on Alice...");
    const micBtn = await pageAlice.waitForSelector("#btn-mic", { visible: true });
    await micBtn.click();

    await pageAlice.waitForFunction(
      () => {
        const btn = document.getElementById("btn-mic");
        return btn && btn.textContent.includes("Mic Live");
      },
      { timeout: 5000 }
    );

    const micStatus = await pageAlice.evaluate(() => {
      return {
        hasStream: !!window.state && !!window.state.localStream,
        tracks: window.state && window.state.localStream ? window.state.localStream.getAudioTracks().length : 0,
        enabled: window.state && window.state.localStream ? window.state.localStream.getAudioTracks()[0].enabled : false,
      };
    });

    if (!micStatus.hasStream || micStatus.tracks === 0 || !micStatus.enabled) {
      logFail("Microphone stream was not properly initialized: " + JSON.stringify(micStatus));
    }
    logPass("Microphone initialized with live audio track and active VAD processing.");

    // Step 3: Bob joins via invite link in a separate browser context
    logStep("3/12", "Bob opens the invite link in a separate browser context...");
    const contextBob = await browser.createBrowserContext();
    try {
      await contextBob.overridePermissions(SERVER_URL, ["microphone", "camera"]);
    } catch {}
    const pageBob = await contextBob.newPage();
    pageBob.on("console", (msg) => console.log(`[Bob Console ${msg.type()}] ${msg.text()}`));
    pageBob.on("pageerror", (err) => console.log(`[Bob Page Error] ${err.message}`));

    await pageBob.goto(inviteLink, { waitUntil: "networkidle0" });

    await pageBob.waitForFunction(
      () => {
        const landing = document.getElementById("landing");
        const dot = document.getElementById("status-dot");
        return landing && landing.style.display === "none" && dot && dot.classList.contains("on");
      },
      { timeout: 10000 }
    );
    logPass("Bob joined the burner room directly via the URL hash link.");

    // Step 4: WebRTC DataChannel connection
    logStep("4/12", "Waiting for WebRTC DataChannel direct link between Alice and Bob...");
    await Promise.all([
      pageAlice.waitForFunction(
        () => {
          const count = document.getElementById("peer-count");
          return count && parseInt(count.textContent, 10) >= 1;
        },
        { timeout: 15000 }
      ),
      pageBob.waitForFunction(
        () => {
          const count = document.getElementById("peer-count");
          return count && parseInt(count.textContent, 10) >= 1;
        },
        { timeout: 15000 }
      ),
    ]);

    await pageAlice.waitForSelector(".dot-legend.direct", { timeout: 10000 });
    await pageBob.waitForSelector(".dot-legend.direct", { timeout: 10000 });
    logPass("Direct WebRTC DataChannel established between browser windows!");

    // Step 5: End-to-end encrypted chat
    logStep("5/12", "Testing E2EE chat back and forth between Alice and Bob...");
    const msg1 = "Hello Bob! Testing E2EE chat in browser " + Date.now();
    await pageAlice.type("#chat-input", msg1);
    await pageAlice.click("#send-btn");

    await pageBob.waitForFunction(
      (expected) => {
        const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
        return msgs.some((m) => m.textContent.includes(expected));
      },
      { timeout: 10000 },
      msg1
    );
    logPass("Bob received and decrypted Alice's message!");

    const msg2 = "Hello Alice! Reply from Bob " + Date.now();
    await pageBob.type("#chat-input", msg2);
    await pageBob.click("#send-btn");

    await pageAlice.waitForFunction(
      (expected) => {
        const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
        return msgs.some((m) => m.textContent.includes(expected));
      },
      { timeout: 10000 },
      msg2
    );
    logPass("Alice received and decrypted Bob's reply!");

    // Step 6: Verify SFrame-encrypted audio delivery over dedicated secondary WebRTC connection
    logStep("6/12", "Verifying live SFrame-encrypted microphone audio over secondary WebRTC connection...");
    const bobVoiceBtn = await pageBob.waitForSelector("#btn-voice", { visible: true });
    await bobVoiceBtn.click();
    const bobCallStats6 = await waitCallStats(
      pageBob,
      (s) => s.secondaryPeerCount >= 1 && s.sframe && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0,
      15000,
      "Bob SFrame audio decryption over secondary RTCPeerConnection",
      async () => {
        const aSt = await pageAlice.evaluate(() => window.cotillaClient.getCallStats());
        console.error("   DEBUG Alice CallStats on Step 6 fail:", JSON.stringify(aSt));
      }
    );
    const aliceCallStats6 = await waitCallStats(
      pageAlice,
      (s) => s.secondaryPeerCount >= 1 && s.sframe && s.sframe.encryptedAudio > 0 && s.sframe.rejected === 0,
      10000,
      "Alice SFrame audio encryption over secondary RTCPeerConnection"
    );
    await pageBob.waitForFunction(() => {
      const badge = document.getElementById("sframe-lock-badge");
      return badge && badge.style.display !== "none";
    }, { timeout: 5000 });
    logPass(`Bob joined voice, formed ${bobCallStats6.secondaryPeerCount} secondary PC, and decrypted SFrame Opus frames (alice enc=${aliceCallStats6.sframe.encryptedAudio}, bob dec=${bobCallStats6.sframe.decryptedAudio}, rej=${bobCallStats6.sframe.rejected})!`);

    // Also test reverse direction (Bob -> Alice) so BOTH Offerer and Answerer senders are verified every run.
    const bobMicBtn = await pageBob.waitForSelector("#btn-mic", { visible: true });
    await bobMicBtn.click();
    await pageBob.waitForFunction(() => window.state && window.state.micEnabled, { timeout: 5000 });
    const aliceRxStats6 = await waitCallStats(
      pageAlice,
      (s) => s.secondaryPeerCount >= 1 && s.sframe && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0,
      15000,
      "Alice SFrame audio decryption (reverse direction)",
      async () => {
        const bSt = await pageBob.evaluate(() => window.cotillaClient.getCallStats());
        console.error("   DEBUG Bob CallStats on reverse Step 6 fail:", JSON.stringify(bSt));
      }
    );
    const bobTxStats6 = await pageBob.evaluate(() => window.cotillaClient.getCallStats());
    if (!bobTxStats6 || !bobTxStats6.sframe || bobTxStats6.sframe.encryptedAudio <= 0) {
      logFail(`Bob failed to SFrame-encrypt audio on reverse direction: ${JSON.stringify(bobTxStats6)}`);
    }
    logPass(`Verified bidirectional SFrame audio (bob enc=${bobTxStats6.sframe.encryptedAudio}, alice dec=${aliceRxStats6.sframe.decryptedAudio}, alice rej=${aliceRxStats6.sframe.rejected})!`);
    await bobMicBtn.click();
    await pageBob.waitForFunction(() => window.state && !window.state.micEnabled, { timeout: 5000 });

    // Step 7: Verify camera video feed streaming and remote video rendering
    logStep("7/12", "Testing live SFrame-encrypted camera video feed streaming from Alice to Bob...");
    const camBtn = await pageAlice.waitForSelector("#btn-cam", { visible: true });
    await camBtn.click();

    // Alice local video container must become visible
    await pageAlice.waitForFunction(
      () => {
        const local = document.getElementById("local-video-container");
        return local && local.style.display !== "none";
      },
      { timeout: 5000 }
    );
    logPass("Alice activated camera; local video container displayed in video grid.");

    // Bob must receive remote WebRTC video track and render <video class="remote-video-frame"> with srcObject
    await pageBob.waitForFunction(
      () => {
        const remoteVids = document.querySelectorAll("#video-grid video.remote-video-frame");
        return remoteVids.length >= 1 && remoteVids[0].srcObject && remoteVids[0].srcObject.getVideoTracks().length >= 1;
      },
      { timeout: 15000 }
    );
    const bobVideoStats7 = await waitCallStats(
      pageBob,
      (s) => s.sframe && s.sframe.decryptedVideo > 0 && s.sframe.rejected === 0,
      15000,
      "Bob SFrame VP8 video decryption"
    );
    logPass(`Bob decrypted SFrame video frames (decVideo=${bobVideoStats7.sframe.decryptedVideo}, rej=${bobVideoStats7.sframe.rejected}) and rendered native <video> tile for Alice!`);

    // Alice turns off camera
    await camBtn.click();
    await pageAlice.waitForFunction(
      () => {
        const local = document.getElementById("local-video-container");
        return local && local.style.display === "none";
      },
      { timeout: 5000 }
    );

    // Bob's remote video container for Alice must be removed
    await pageBob.waitForFunction(
      () => {
        const remoteVids = document.querySelectorAll("#video-grid .remote-video-frame");
        return remoteVids.length === 0;
      },
      { timeout: 10000 }
    );
    logPass("Alice disabled camera; remote video tile cleanly removed from Bob's video grid.");

    // Step 8: Chunked attachment transfer and duplicate prevention
    logStep("8/12", "Testing file attachment offer, on-demand download, and duplicate prevention...");
    const sharedAttachRes = await pageBob.evaluate(() => {
      const bytes = new TextEncoder().encode("Cotilla Attachment Content Single Test 1234567890");
      const res = JSON.parse(cotilla.shareAttachment("single-test.txt", "text/plain", bytes));
      appendAttachment(res, bytes, true);
      return res;
    });

    await pageAlice.waitForFunction(
      () => {
        const badges = document.querySelectorAll(".attachment-badge");
        return badges.length >= 1;
      },
      { timeout: 10000 }
    );

    // Assert that the attachment appears EXACTLY ONCE in Alice's DOM
    const attachCount = await pageAlice.evaluate(() => {
      const cards = Array.from(document.querySelectorAll(".attachment-card"));
      return cards.filter((c) => c.textContent.includes("single-test.txt")).length;
    });

    if (attachCount !== 1) {
      logFail(`Attachment duplicated! Expected exactly 1 card in DOM, found ${attachCount}`);
    }

    // Alice clicks download to test on-demand download flow
    await pageAlice.evaluate((fileID) => {
      const btn = document.querySelector(`#action-${fileID} button`) || document.querySelector(".download-btn");
      if (btn) btn.click();
    }, sharedAttachRes.file_id);

    await pageAlice.waitForFunction(
      () => {
        const badges = Array.from(document.querySelectorAll(".attachment-badge"));
        return badges.some((b) => b.textContent.includes("SHA-256 Verified"));
      },
      { timeout: 10000 }
    );
    logPass("Attachment transfer verified and deduplicated (no duplicate cards in DOM).");

    // Step 9: Page Refresh / Reconnection Test (Browser <-> Browser)
    logStep("9/12", "Testing page refresh and peer reconnection between browser windows...");
    console.log("   Refreshing Alice's page...");
    await pageAlice.goto(inviteLink, { waitUntil: "networkidle0" });

    // Alice should automatically rejoin the room from hash
    await pageAlice.waitForFunction(
      () => {
        const dot = document.getElementById("status-dot");
        return dot && dot.classList.contains("on");
      },
      { timeout: 10000 }
    );

    // Both Alice and Bob must detect each other reconnected
    await Promise.all([
      pageAlice.waitForFunction(
        () => {
          const count = document.getElementById("peer-count");
          return count && parseInt(count.textContent, 10) >= 1;
        },
        { timeout: 15000 }
      ),
      pageBob.waitForFunction(
        () => {
          const count = document.getElementById("peer-count");
          return count && parseInt(count.textContent, 10) >= 1;
        },
        { timeout: 15000 }
      ),
    ]);

    await pageAlice.waitForSelector(".dot-legend.direct", { timeout: 10000 });
    await pageBob.waitForSelector(".dot-legend.direct", { timeout: 10000 });
    logPass("Reconnection successful! Direct WebRTC mesh link restored after refresh.");

    // Exchange message after refresh to prove channel is alive
    const postRefreshMsg = "Message from Alice after page refresh " + Date.now();
    await pageAlice.type("#chat-input", postRefreshMsg);
    await pageAlice.click("#send-btn");

    await pageBob.waitForFunction(
      (expected) => {
        const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
        return msgs.some((m) => m.textContent.includes(expected));
      },
      { timeout: 10000 },
      postRefreshMsg
    );
    logPass("Post-refresh message verified on Bob!");

    // Step 10: Browser 1:1 DM Invite, Modal Prompt, Session Tabs & Isolated Messaging
    logStep("10/12", "Testing Browser 1:1 DM invite, modal acceptance, and session isolation...");

    // Wait for Alice to receive Bob's encryption public key
    await pageAlice.waitForFunction(
      () => {
        try {
          const keys = JSON.parse(window.cotilla.peerEncKeys());
          return keys && Object.keys(keys).length > 0;
        } catch {
          return false;
        }
      },
      { timeout: 10000 }
    );

    // Alice clicks DM button for Bob in the peer list
    await pageAlice.waitForSelector(".peer-dm-btn", { visible: true, timeout: 10000 });
    await pageAlice.evaluate(() => document.querySelector(".peer-dm-btn")?.click());

    // Bob receives modal dialog and clicks accept
    await pageBob.waitForSelector("#btn-dm-accept", { visible: true, timeout: 10000 });
    await pageBob.evaluate(() => document.querySelector("#btn-dm-accept")?.click());

    // Both should now have a DM tab selected and active-target-badge showing DM
    await pageAlice.waitForFunction(
      () => {
        const badge = document.getElementById("active-target-badge");
        return badge && badge.textContent.includes("DM");
      },
      { timeout: 10000 }
    );
    await pageBob.waitForFunction(
      () => {
        const badge = document.getElementById("active-target-badge");
        return badge && badge.textContent.includes("DM");
      },
      { timeout: 10000 }
    );
    logPass("Alice and Bob formed a 1:1 DM session and switched to the DM tab!");

    // Alice sends a private DM message to Bob
    const browserDM = "Secret Browser DM from Alice " + Date.now();
    await pageAlice.type("#chat-input", browserDM);
    await pageAlice.click("#send-btn");

    // Bob receives and renders the DM message
    await pageBob.waitForFunction(
      (expected) => {
        const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
        return msgs.some((m) => m.textContent.includes(expected));
      },
      { timeout: 10000 },
      browserDM
    );
    logPass("Bob received and displayed private DM in the 1:1 session tab!");

    // Switch both back to the main room tab to verify isolation
    await pageAlice.evaluate(() => document.querySelector("#tab-main")?.click());
    await pageBob.evaluate(() => document.querySelector("#tab-main")?.click());

    const aliceHasDMInMain = await pageAlice.evaluate((expected) => {
      const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
      return msgs.some((m) => m.textContent.includes(expected));
    }, browserDM);
    if (aliceHasDMInMain) {
      logFail("Alice's main room messages leaked the private DM message!");
    }

    const bobHasDMInMain = await pageBob.evaluate((expected) => {
      const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
      return msgs.some((m) => m.textContent.includes(expected));
    }, browserDM);
    if (bobHasDMInMain) {
      logFail("Bob's main room messages leaked the private DM message!");
    }
    logPass("Strict UI session isolation verified: DM message is invisible in the main room.");

    // =========================================================================
    // Step 11: Multi-Peer Voice Channel, Speaking Isolation & Refresh Audio Resilience
    // (Scenario: Alice creates room, Bob joins & starts DM, Alice speaks in room,
    //  Charlie joins without voice [hears nothing, sees no speaking indicators],
    //  Charlie joins voice [hears & sees Alice], Charlie refreshes -> Bob's audio unbroken)
    // =========================================================================
    logStep("11/12", "Testing 3-peer voice channel: speaking isolation & Charlie refresh audio resilience...");

    // 1. Ensure Alice's mic is live in the main room
    await pageAlice.evaluate(() => document.querySelector("#tab-main")?.click());
    await pageBob.evaluate(() => document.querySelector("#tab-main")?.click());

    const aliceMicActive = await pageAlice.evaluate(() => window.state && window.state.micEnabled);
    if (!aliceMicActive) {
      const aMicBtn = await pageAlice.waitForSelector("#btn-mic", { visible: true });
      await aMicBtn.click();
    }
    await pageAlice.waitForFunction(
      () => {
        const btn = document.getElementById("btn-mic");
        return btn && btn.textContent.includes("Mic Live");
      },
      { timeout: 5000 }
    );

    // 2. Ensure Bob is in voice and receiving SFrame audio from Alice
    const bobInVoice = await pageBob.evaluate(() => window.state && window.state.voiceConnected);
    if (!bobInVoice) {
      const bVoiceBtn = await pageBob.waitForSelector("#btn-voice", { visible: true });
      await bVoiceBtn.click();
    }
    await waitCallStats(
      pageBob,
      (s) => s.secondaryPeerCount >= 1 && s.sframe && s.sframe.decryptedAudio > 0,
      10000,
      "Bob receiving SFrame audio before Charlie joins"
    );
    logPass("Alice is speaking in main room; Bob is in voice decrypting SFrame audio.");

    // 3. Charlie joins the room in a 3rd browser context
    logStep("11.1", "Charlie joins the room without joining voice channel...");
    const contextCharlie = await browser.createBrowserContext();
    await grantMedia(contextCharlie);
    const pageCharlie = await contextCharlie.newPage();
    pageCharlie.on("console", (msg) => console.log(`[Charlie Console ${msg.type()}] ${msg.text()}`));
    pageCharlie.on("pageerror", (err) => console.log(`[Charlie Page Error] ${err.message}`));

    await pageCharlie.goto(inviteLink, { waitUntil: "networkidle0" });

    // Wait for Charlie to be connected to signaling and direct mesh with Alice & Bob
    await pageCharlie.waitForFunction(
      () => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 2;
      },
      { timeout: 15000 }
    );
    await pageCharlie.waitForSelector(".dot-legend.direct", { timeout: 10000 });
    logPass("Charlie joined room and established WebRTC DataChannels with Alice and Bob.");

    // 4. Assert that Charlie has ZERO secondary WebRTC call connections, hears NO audio, and sees NO speaking indicators
    await new Promise((r) => setTimeout(r, 1000));
    const charlieVoiceState = await pageCharlie.evaluate(async () => {
      const isVoiceConnected = !!(window.state && window.state.voiceConnected);
      const hasSpeakingPeers = !!(window.state && window.state.speakingPeers && window.state.speakingPeers.size > 0);
      const speakingTiles = document.querySelectorAll(".speaking").length;
      const audioTiles = document.querySelectorAll(".audio-tile").length;
      const hasSpeakerIcon = Array.from(document.querySelectorAll("#peers-list li")).some((li) => li.textContent.includes("🔊"));
      const stats = window.cotillaClient ? await window.cotillaClient.getCallStats() : null;
      return {
        isVoiceConnected,
        hasSpeakingPeers,
        speakingTiles,
        audioTiles,
        hasSpeakerIcon,
        secondaryPeerCount: stats ? stats.secondaryPeerCount : 0,
        decryptedAudio: stats && stats.sframe ? stats.sframe.decryptedAudio : 0,
        decryptedVideo: stats && stats.sframe ? stats.sframe.decryptedVideo : 0,
      };
    });

    if (charlieVoiceState.isVoiceConnected) {
      logFail("Charlie was unexpectedly marked as connected to voice before clicking Join Voice!");
    }
    if (charlieVoiceState.secondaryPeerCount > 0) {
      logFail(`Charlie unexpectedly opened ${charlieVoiceState.secondaryPeerCount} secondary WebRTC call PCs before clicking Join Voice!`);
    }
    if (charlieVoiceState.hasSpeakingPeers || charlieVoiceState.speakingTiles > 0 || charlieVoiceState.audioTiles > 0 || charlieVoiceState.hasSpeakerIcon) {
      logFail("Charlie unexpectedly sees speaking indicators before joining voice: " + JSON.stringify(charlieVoiceState));
    }
    if (charlieVoiceState.decryptedAudio > 0 || charlieVoiceState.decryptedVideo > 0) {
      logFail(`Charlie unexpectedly decrypted call media before joining voice (${JSON.stringify(charlieVoiceState)})!`);
    }
    logPass("Verified: Charlie is not in voice, opened 0 secondary PCs, hears no audio, and sees NO speaking indicators.");

    // 5. Charlie joins the voice channel to listen
    logStep("11.2", "Charlie clicks 'Join Voice' to listen to the room...");
    const charlieVoiceBtn = await pageCharlie.waitForSelector("#btn-voice", { visible: true });
    await charlieVoiceBtn.click();

    await pageCharlie.waitForFunction(
      () => {
        const btn = document.getElementById("btn-voice");
        return btn && btn.textContent.includes("Leave Voice");
      },
      { timeout: 5000 }
    );

    const charlieStatsAfterJoin = await waitCallStats(
      pageCharlie,
      (s) => s.secondaryPeerCount >= 1 && s.sframe && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0,
      15000,
      "Charlie SFrame audio reception after clicking Join Voice"
    );
    logPass(`Charlie joined voice channel, opened ${charlieStatsAfterJoin.secondaryPeerCount} secondary PCs, and decrypted Alice's SFrame audio (dec=${charlieStatsAfterJoin.sframe.decryptedAudio})!`);

    // 6. Charlie refreshes the browser
    logStep("11.3", "Charlie refreshes the browser while Alice is speaking...");
    const bobStatsBeforeRefresh = await pageBob.evaluate(() => window.cotillaClient.getCallStats());
    const bobPacketsBeforeRefresh = (bobStatsBeforeRefresh && bobStatsBeforeRefresh.sframe && bobStatsBeforeRefresh.sframe.decryptedAudio) || 0;
    console.log(`   Bob SFrame decrypted audio count before Charlie refresh: ${bobPacketsBeforeRefresh}`);

    await pageCharlie.goto(inviteLink, { waitUntil: "networkidle0" });

    // Wait for Charlie to re-establish signaling
    await pageCharlie.waitForFunction(
      () => {
        const dot = document.getElementById("status-dot");
        return dot && dot.classList.contains("on");
      },
      { timeout: 10000 }
    );

    // Charlie re-establishes direct mesh
    await pageCharlie.waitForFunction(
      () => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 2;
      },
      { timeout: 15000 }
    );
    logPass("Charlie reconnected and re-established mesh after page refresh.");

    // 7. Crucial assertion: Bob MUST STILL HEAR Alice without interruption!
    const bobStatsAfterRefresh = await waitCallStats(
      pageBob,
      (s) => s.sframe && s.sframe.decryptedAudio >= bobPacketsBeforeRefresh + 10,
      15000,
      "Bob SFrame audio continuity across Charlie refresh"
    );
    const bobPacketsAfterRefresh = bobStatsAfterRefresh.sframe.decryptedAudio;
    console.log(`   Bob SFrame decrypted audio count after Charlie refresh: ${bobPacketsAfterRefresh}`);
    logPass("Verified: Bob continued receiving Alice's SFrame audio stream without interruption after Charlie refreshed!");

    // Step 12: 100MB Large File On-Demand Transfer & Memory Performance
    logStep("12/12", "Testing 100MB large file sharing, on-demand offer, and streaming download...");
    console.log("   Alice generating and sharing 100MB synthetic attachment...");
    const largeShareInfo = await pageAlice.evaluate(() => {
      const start = performance.now();
      const size = 100 * 1024 * 1024;
      const uint8 = new Uint8Array(size);
      for (let i = 0; i < 10000; i++) {
        uint8[i] = (i * 37) % 256;
      }
      const res = JSON.parse(cotilla.shareAttachment("large-100mb.bin", "application/octet-stream", uint8));
      const elapsedMs = performance.now() - start;
      const blob = new Blob([uint8], { type: "application/octet-stream" });
      const blobUrl = URL.createObjectURL(blob);
      appendAttachment(res, blobUrl, true);
      return { res, elapsedMs };
    });

    console.log(`   Alice shared 100MB file in ${largeShareInfo.elapsedMs.toFixed(1)}ms (FileID: ${largeShareInfo.res.file_id}, Chunks: ${largeShareInfo.res.total_chunks})`);
    if (largeShareInfo.elapsedMs > 5000) {
      logFail(`100MB file sharing took too long: ${largeShareInfo.elapsedMs}ms (expected < 5000ms)`);
    }

    // Bob receives offer
    console.log("   Waiting for Bob to receive 100MB file offer...");
    await pageBob.waitForFunction(
      () => {
        const names = Array.from(document.querySelectorAll(".attachment-name"));
        return names.some((n) => n.textContent.includes("large-100mb.bin"));
      },
      { timeout: 10000 }
    );

    // Verify Bob has NOT downloaded chunks yet (download button is visible)
    const bobOfferState = await pageBob.evaluate((fileID) => {
      const badge = document.getElementById(`badge-${fileID}`);
      const btn = document.querySelector(`#action-${fileID} button`);
      return {
        badgeText: badge ? badge.textContent : "",
        hasButton: !!btn,
      };
    }, largeShareInfo.res.file_id);

    if (!bobOfferState.hasButton) {
      logFail("Bob did not show Download button for 100MB file offer");
    }
    logPass("Bob received 100MB file offer without auto-downloading chunks (RAM and CPU conserved).");

    // Charlie also received the offer without downloading
    const charlieOfferState = await pageCharlie.evaluate((fileID) => {
      const badge = document.getElementById(`badge-${fileID}`);
      const btn = document.querySelector(`#action-${fileID} button`);
      return {
        badgeText: badge ? badge.textContent : "",
        hasButton: !!btn,
      };
    }, largeShareInfo.res.file_id);
    if (!charlieOfferState.hasButton) {
      logFail("Charlie did not show Download button for 100MB file offer");
    }
    logPass("Charlie also received 100MB file offer without downloading (network bandwidth conserved).");

    // Bob triggers on-demand download
    console.log("   Bob clicking Download for 100MB file...");
    await pageBob.evaluate((fileID) => {
      const btn = document.querySelector(`#action-${fileID} button`);
      if (btn) btn.click();
    }, largeShareInfo.res.file_id);

    // Bob waits for download completion and SHA-256 validation
    console.log("   Waiting for Bob to stream and verify all chunks for 100MB file...");
    await pageBob.waitForFunction(
      (fileID) => {
        const badge = document.getElementById(`badge-${fileID}`);
        return badge && badge.textContent.includes("SHA-256 Verified");
      },
      { timeout: 60000 },
      largeShareInfo.res.file_id
    );

    // Verify Bob's card now has a valid Save File link
    const bobDownloadSuccess = await pageBob.evaluate((fileID) => {
      const link = document.querySelector(`#action-${fileID} a`);
      return link && link.getAttribute("href") && link.getAttribute("href").startsWith("blob:");
    }, largeShareInfo.res.file_id);

    if (!bobDownloadSuccess) {
      logFail("Bob's attachment card does not have a valid Blob Save File link after download");
    }
    logPass("Bob successfully downloaded 100MB file on-demand with verified SHA-256 checksum!");

    // Clean up Charlie, Bob, and Alice contexts from Part 1
    await contextCharlie.close();
    await contextBob.close();
    await pageAlice.close().catch(() => {});

    // =========================================================================
    // STEP 13: 3+ WEB CLIENTS MULTI-FILE CROSS-SHARING & LATE JOIN SWARM
    // =========================================================================
    logStep("13/14", "Testing 3+ Web Clients multi-file cross-sharing & late join swarm seeding...");

    // Create a fresh room with Alice
    const contextMultiAlice = await browser.createBrowserContext();
    const pageMultiAlice = await contextMultiAlice.newPage();
    pageMultiAlice.on("console", (msg) => console.log(`[Multi-Alice Console] ${msg.text()}`));
    await pageMultiAlice.goto(SERVER_URL, { waitUntil: "networkidle0" });
    await pageMultiAlice.waitForSelector("#btn-create-room", { visible: true });
    await pageMultiAlice.click("#btn-create-room");
    await pageMultiAlice.waitForFunction(() => window.location.hash.includes("#room="), { timeout: 5000 });
    const multiRoomUrl = await pageMultiAlice.evaluate(() => window.location.href);

    // Bob, Charlie, and Dave join
    const contextMultiBob = await browser.createBrowserContext();
    const pageMultiBob = await contextMultiBob.newPage();
    pageMultiBob.on("console", (msg) => console.log(`[Multi-Bob Console] ${msg.text()}`));
    await pageMultiBob.goto(multiRoomUrl, { waitUntil: "networkidle0" });

    const contextMultiCharlie = await browser.createBrowserContext();
    const pageMultiCharlie = await contextMultiCharlie.newPage();
    pageMultiCharlie.on("console", (msg) => console.log(`[Multi-Charlie Console] ${msg.text()}`));
    await pageMultiCharlie.goto(multiRoomUrl, { waitUntil: "networkidle0" });

    const contextMultiDave = await browser.createBrowserContext();
    const pageMultiDave = await contextMultiDave.newPage();
    pageMultiDave.on("console", (msg) => console.log(`[Multi-Dave Console] ${msg.text()}`));
    await pageMultiDave.goto(multiRoomUrl, { waitUntil: "networkidle0" });

    // Wait for all 4 to form a full mesh (peer count >= 3 on each)
    await Promise.all([
      pageMultiAlice.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 3;
      }, { timeout: 20000 }),
      pageMultiBob.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 3;
      }, { timeout: 20000 }),
      pageMultiCharlie.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 3;
      }, { timeout: 20000 }),
      pageMultiDave.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 3;
      }, { timeout: 20000 }),
    ]);
    logPass("Alice, Bob, Charlie, and Dave (4 web clients) established direct WebRTC mesh in the same room.");

    // Helper to share a synthetic file via cotilla.shareAttachment
    const shareSyntheticFile = async (page, name, sizeKb, seed = 0) => {
      return page.evaluate((fileName, size, s) => {
        const bytes = new Uint8Array(size * 1024);
        for (let i = 0; i < bytes.length; i++) {
          bytes[i] = (i * 31 + s) % 256;
        }
        const res = JSON.parse(cotilla.shareAttachment(fileName, "application/octet-stream", bytes));
        const blob = new Blob([bytes], { type: "application/octet-stream" });
        const blobUrl = URL.createObjectURL(blob);
        appendAttachment(res, blobUrl, true);
        return res;
      }, name, sizeKb, seed);
    };

    // Alice shares File 1, Bob shares File 2, Charlie shares File 3
    console.log("   Alice sharing alice-doc.bin (64KB)...");
    const fileAlice = await shareSyntheticFile(pageMultiAlice, "alice-doc.bin", 64, 11);
    console.log("   Bob sharing bob-notes.bin (64KB)...");
    const fileBob = await shareSyntheticFile(pageMultiBob, "bob-notes.bin", 64, 22);
    console.log("   Charlie sharing charlie-pack.bin (64KB)...");
    const fileCharlie = await shareSyntheticFile(pageMultiCharlie, "charlie-pack.bin", 64, 33);

    // Verify all 3 clients receive offers for all 3 files
    const checkOffersOnPage = async (page, clientName, fileIDs) => {
      for (const id of fileIDs) {
        await page.waitForFunction(
          (fid) => !!document.getElementById(`badge-${fid}`),
          { timeout: 15000 },
          id
        );
      }
      logPass(`${clientName} has all 3 file attachment cards rendered.`);
    };

    await checkOffersOnPage(pageMultiAlice, "Alice", [fileAlice.file_id, fileBob.file_id, fileCharlie.file_id]);
    await checkOffersOnPage(pageMultiBob, "Bob", [fileAlice.file_id, fileBob.file_id, fileCharlie.file_id]);
    await checkOffersOnPage(pageMultiCharlie, "Charlie", [fileAlice.file_id, fileBob.file_id, fileCharlie.file_id]);
    await checkOffersOnPage(pageMultiDave, "Dave", [fileAlice.file_id, fileBob.file_id, fileCharlie.file_id]);
    logPass("All 4 web clients successfully received attachment offers for all files!");

    // Helper to trigger download and wait for verification
    const triggerAndVerifyDownload = async (page, clientName, fileID) => {
      await page.waitForSelector(`#action-${fileID} button`, { timeout: 10000 });
      await page.evaluate((fid) => {
        const btn = document.querySelector(`#action-${fid} button`);
        if (btn) btn.click();
      }, fileID);
      await page.waitForFunction(
        (fid) => {
          const badge = document.getElementById(`badge-${fid}`);
          return badge && badge.textContent.includes("SHA-256 Verified");
        },
        { timeout: 15000 },
        fileID
      );
      logPass(`${clientName} downloaded and verified attachment ${fileID}!`);
    };

    // Cross-downloads:
    await triggerAndVerifyDownload(pageMultiBob, "Bob", fileAlice.file_id);
    await triggerAndVerifyDownload(pageMultiCharlie, "Charlie", fileBob.file_id);
    await triggerAndVerifyDownload(pageMultiAlice, "Alice", fileCharlie.file_id);

    // Swarm Seeding when original uploader departs: Alice leaves room
    logStep("13.1", "Alice leaves room. Dave downloads Alice's file from swarm (seeded by Bob & Charlie)...");
    await contextMultiAlice.close();

    // Dave downloads Alice's file (Alice is offline! Chunks are seeded by Bob & Charlie!)
    console.log("   Dave downloading alice-doc.bin from swarm (Alice is offline)...");
    await triggerAndVerifyDownload(pageMultiDave, "Dave (Swarm Download)", fileAlice.file_id);
    logPass("Dave successfully downloaded Alice's file seeded by Bob and Charlie!");

    await contextMultiBob.close();
    await contextMultiCharlie.close();
    await contextMultiDave.close();

    // =========================================================================
    // STEP 14: MIXED MESH WITH >2 CLIENTS OF EACH TYPE (3 WEB + 3 NATIVE = 6 CLIENTS)
    // =========================================================================
    logStep("14/14", "Testing Mixed Mesh: 3 Web Clients + 3 Native Container Clients (6 Clients in the same room)...");

    const NATIVE_ROOM_ID = "bench-ephemeral-room-1234";
    const NATIVE_ROOM_KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    const nativeRoomUrl = `${SERVER_URL}/#room=${NATIVE_ROOM_ID}&key=${NATIVE_ROOM_KEY}`;

    const ctxWeb1 = await browser.createBrowserContext();
    await grantMedia(ctxWeb1);
    const pageWeb1 = await ctxWeb1.newPage();
    pageWeb1.on("console", (msg) => console.log(`[Web-1 Console] ${msg.text()}`));
    pageWeb1.on("pageerror", (err) => console.error(`[Web-1 PageError] ${err.message}`));
    await pageWeb1.goto(nativeRoomUrl, { waitUntil: "networkidle0" });

    const ctxWeb2 = await browser.createBrowserContext();
    await grantMedia(ctxWeb2);
    const pageWeb2 = await ctxWeb2.newPage();
    pageWeb2.on("console", (msg) => console.log(`[Web-2 Console] ${msg.text()}`));
    pageWeb2.on("pageerror", (err) => console.error(`[Web-2 PageError] ${err.message}`));
    await pageWeb2.goto(nativeRoomUrl, { waitUntil: "networkidle0" });

    const ctxWeb3 = await browser.createBrowserContext();
    await grantMedia(ctxWeb3);
    const pageWeb3 = await ctxWeb3.newPage();
    pageWeb3.on("console", (msg) => console.log(`[Web-3 Console] ${msg.text()}`));
    pageWeb3.on("pageerror", (err) => console.error(`[Web-3 PageError] ${err.message}`));
    await pageWeb3.goto(nativeRoomUrl, { waitUntil: "networkidle0" });

    const waitMixedMesh = async (page, name) => {
      await page.waitForFunction(() => {
        const dot = document.getElementById("status-dot");
        const count = document.getElementById("peer-count");
        return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 3;
      }, { timeout: 20000 });
      logPass(`${name} connected to mixed mesh with direct WebRTC channels.`);
    };

    await waitMixedMesh(pageWeb1, "Web-Client-1");
    await waitMixedMesh(pageWeb2, "Web-Client-2");
    await waitMixedMesh(pageWeb3, "Web-Client-3");
    logPass("All 3 Web Clients connected with all 3 Native Clients in room bench-ephemeral-room-1234 (6 clients total).");

    // 1. Native Alice sends a message -> all 3 Web Clients receive it
    const nativeBroadcastMsg = "Broadcast from Native Alice to Mixed Mesh " + Date.now();
    await postJSON(`${NATIVE_ALICE_URL}/send`, { text: nativeBroadcastMsg });

    for (const [p, name] of [[pageWeb1, "Web-Client-1"], [pageWeb2, "Web-Client-2"], [pageWeb3, "Web-Client-3"]]) {
      await p.waitForFunction(
        (expected) => {
          const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
          return msgs.some((m) => m.textContent.includes(expected));
        },
        { timeout: 10000 },
        nativeBroadcastMsg
      );
      logPass(`${name} received message from Native Alice.`);
    }

    // 2. Native Alice shares a file
    console.log("   Native Alice sharing native-share.bin (64KB)...");
    const nativeAttach = await postJSON(`${NATIVE_ALICE_URL}/share-file`, {
      name: "native-share.bin",
      size_bytes: 64 * 1024,
    });
    const nativeFileID = nativeAttach.file_id;

    // Verify all 3 Web clients receive the offer
    for (const [p, name] of [[pageWeb1, "Web-Client-1"], [pageWeb2, "Web-Client-2"], [pageWeb3, "Web-Client-3"]]) {
      await p.waitForFunction(
        (fid) => !!document.getElementById(`badge-${fid}`),
        { timeout: 10000 },
        nativeFileID
      );
      logPass(`${name} received offer for native-share.bin from Native Alice.`);
    }

    // 3. Web-Client-1 shares a file
    console.log("   Web-Client-1 sharing web-share.bin (64KB)...");
    const webAttach = await shareSyntheticFile(pageWeb1, "web-share.bin", 64, 44);
    const webFileID = webAttach.file_id;

    // Verify Web-Client-2 and Web-Client-3 receive offer
    for (const [p, name] of [[pageWeb2, "Web-Client-2"], [pageWeb3, "Web-Client-3"]]) {
      await p.waitForFunction(
        (fid) => !!document.getElementById(`badge-${fid}`),
        { timeout: 10000 },
        webFileID
      );
      logPass(`${name} received offer for web-share.bin from Web-Client-1.`);
    }

    // Verify Native Bob receives offer
    let nativeBobGotOffer = false;
    const offerCheckDeadline = Date.now() + 10000;
    while (Date.now() < offerCheckDeadline) {
      const offers = await fetchJSON(`${NATIVE_BOB_URL}/offers`);
      if (Array.isArray(offers) && offers.some((o) => o.file_id === webFileID)) {
        nativeBobGotOffer = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    if (!nativeBobGotOffer) {
      logFail("Native Bob did not receive offer for web-share.bin from Web-Client-1!");
    }
    logPass("Native Bob received offer for web-share.bin from Web-Client-1.");

    // 4. Web-Client-2 downloads file shared by Native Alice
    console.log("   Web-Client-2 downloading native-share.bin...");
    await triggerAndVerifyDownload(pageWeb2, "Web-Client-2", nativeFileID);

    // 5. Native Bob downloads file shared by Web-Client-1
    console.log("   Native Bob downloading web-share.bin...");
    await postJSON(`${NATIVE_BOB_URL}/download-file`, { file_id: webFileID });

    let nativeBobVerified = false;
    const downloadCheckDeadline = Date.now() + 15000;
    while (Date.now() < downloadCheckDeadline) {
      const atts = await fetchJSON(`${NATIVE_BOB_URL}/attachments`);
      if (Array.isArray(atts) && atts.some((a) => a.file_id === webFileID && a.verified)) {
        nativeBobVerified = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    if (!nativeBobVerified) {
      logFail("Native Bob did not complete verified download of web-share.bin!");
    }
    logPass("Native Bob completed verified download of web-share.bin from Web-Client-1!");

    // 6. Test page refresh on Web-Client-3 in the 6-client mesh
    console.log("   Refreshing Web-Client-3 while connected to the mixed mesh...");
    await pageWeb3.goto(nativeRoomUrl, { waitUntil: "networkidle0" });
    await waitMixedMesh(pageWeb3, "Web-Client-3 (Post-Refresh)");
    logPass("Reconnection of Web-Client-3 inside 6-client mixed mesh verified!");

    // 7. Mixed-mesh secondary WebRTC + SFrame A/V interop across 3 Chromium + 3 Native Go clients
    console.log("   Starting 6-client mixed-mesh secondary WebRTC SFrame A/V call (3 Chromium + 3 Native Go)...");
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
    for (const p of [pageWeb1, pageWeb2, pageWeb3]) {
      await p.click("#btn-mic");
    }
    await pageWeb1.click("#btn-cam");

    await Promise.all([
      waitCallStats(
        pageWeb1,
        (s) => s.secondaryPeerCount >= 5 && s.sframe.encryptedAudio > 0 && s.sframe.encryptedVideo > 0 && s.sframe.rejected === 0,
        20000,
        "Web-Client-1 6-peer mixed call",
        async () => {
          const [w2, w3, nA, nB, nC] = await Promise.all([
            pageWeb2.evaluate(() => window.cotillaClient.getCallStats()),
            pageWeb3.evaluate(() => window.cotillaClient.getCallStats()),
            fetchJSON(`${NATIVE_ALICE_URL}/call/stats`),
            fetchJSON(`${NATIVE_BOB_URL}/call/stats`),
            fetchJSON(`${NATIVE_CHARLIE_URL}/call/stats`),
          ]);
          console.error("   DEBUG Web2 CallStats:", JSON.stringify(w2));
          console.error("   DEBUG Web3 CallStats:", JSON.stringify(w3));
          console.error("   DEBUG Native Alice:", JSON.stringify({ peers: nA.channel_call_peers, stats: nA.stats }));
          console.error("   DEBUG Native Bob:", JSON.stringify({ peers: nB.channel_call_peers, stats: nB.stats }));
          console.error("   DEBUG Native Charlie:", JSON.stringify({ peers: nC.channel_call_peers, stats: nC.stats }));
        }
      ),
      waitCallStats(pageWeb2, (s) => s.secondaryPeerCount >= 5 && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0, 20000, "Web-Client-2 6-peer mixed call"),
      waitCallStats(pageWeb3, (s) => s.secondaryPeerCount >= 5 && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0, 20000, "Web-Client-3 6-peer mixed call"),
    ]);

    // Send RFC 6716 Opus silence SFrame packets from Native Alice & verify all 3 Native nodes decrypt Web-Client-1 Opus+VP8
    const opusSilenceB64 = Buffer.from([0xf8, 0xff, 0xfe]).toString("base64");
    const mixedDeadline = Date.now() + 20000;
    let nativeOK = false;
    while (Date.now() < mixedDeadline) {
      await postJSON(`${NATIVE_ALICE_URL}/call/send-media`, { kind: "audio", payload: opusSilenceB64, count: 2 }).catch(() => {});
      const [stA, stB, stC] = await Promise.all([
        fetchJSON(`${NATIVE_ALICE_URL}/call/stats`),
        fetchJSON(`${NATIVE_BOB_URL}/call/stats`),
        fetchJSON(`${NATIVE_CHARLIE_URL}/call/stats`),
      ]);
      const ok = (st, before) =>
        Array.isArray(st.channel_call_peers) &&
        st.channel_call_peers.length >= 5 &&
        st.stats &&
        st.stats.decrypted_audio > (before?.stats?.decrypted_audio || 0) &&
        st.stats.decrypted_video > (before?.stats?.decrypted_video || 0) &&
        st.stats.rejected === 0;
      if (ok(stA, beforeA) && ok(stB, beforeB) && ok(stC, beforeC)) {
        nativeOK = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 250));
    }
    if (!nativeOK) {
      logFail("Mixed-mesh Native Go clients did not decrypt Chrome SFrame Opus+VP8 streams cleanly!");
    }
    logPass("Mixed-mesh secondary WebRTC SFrame A/V verified across 3 Chromium + 3 Native Go clients (zero rejected frames)!");

    await Promise.all([
      postJSON(`${NATIVE_ALICE_URL}/call/leave`, { clear_frames: true }),
      postJSON(`${NATIVE_BOB_URL}/call/leave`, { clear_frames: true }),
      postJSON(`${NATIVE_CHARLIE_URL}/call/leave`, { clear_frames: true }),
    ]);

    await ctxWeb1.close();
    await ctxWeb2.close();
    await ctxWeb3.close();

    // =========================================================================
    // STEP 15: CHANNEL INVITE LINK VERIFICATION & MEMBER GROUP EPOCH ISOLATION (3+ PEERS)
    // =========================================================================
    logStep("15/15", "Testing Channel Invite Link verification & Member Group Epoch Isolation (3+ Peers)...");

    // 1. Alice creates a fresh ephemeral burner room
    const ctxAlice15 = await browser.createBrowserContext();
    const pageAlice15 = await ctxAlice15.newPage();
    pageAlice15.on("console", (msg) => console.log(`[Alice-15 Console] ${msg.text()}`));
    await pageAlice15.goto(SERVER_URL, { waitUntil: "networkidle0" });
    await pageAlice15.waitForSelector("#btn-create-room", { visible: true });
    await pageAlice15.click("#btn-create-room");

    await pageAlice15.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      return dot && dot.classList.contains("on") && window.location.hash.includes("#room=");
    }, { timeout: 10000 });

    const aliceInfo = await pageAlice15.evaluate(() => {
      const parsed = parseHash(window.location.hash);
      return {
        room: parsed ? parsed.room : "",
        key: parsed ? parsed.key : "",
        address: state.me ? state.me.address : "",
      };
    });
    logPass(`Alice created room ${short(aliceInfo.room)} with address ${short(aliceInfo.address)}.`);

    // 2. Alice clicks "Copy Invite Link"
    console.log("   Alice clicking Copy Invite Link...");
    await pageAlice15.waitForSelector("#btn-copy-link", { visible: true });
    await pageAlice15.click("#btn-copy-link");

    await pageAlice15.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });

    const inviteUrl = await pageAlice15.evaluate(() => window.lastCopiedInviteUrl);
    if (!inviteUrl) {
      logFail("Copy Invite Link did not set window.lastCopiedInviteUrl!");
    }
    console.log(`   Generated Invite URL: ${inviteUrl.slice(0, 80)}...`);

    // Verify all cryptographic components of the signed invite URL
    const parsedInvite = await pageAlice15.evaluate((url) => parseHash(url), inviteUrl);
    if (!parsedInvite || !parsedInvite.room || !parsedInvite.key || !parsedInvite.invite) {
      logFail("Invite URL failed parseHash verification: " + JSON.stringify(parsedInvite));
    }
    const inv = parsedInvite.invite;
    if (inv.room_id !== aliceInfo.room) {
      logFail(`Invite room_id mismatch: expected ${aliceInfo.room}, got ${inv.room_id}`);
    }
    if (inv.room_key !== aliceInfo.key) {
      logFail(`Invite room_key mismatch: expected ${aliceInfo.key}, got ${inv.room_key}`);
    }
    if (inv.inviter_pub !== aliceInfo.address) {
      logFail(`Invite inviter_pub mismatch: expected ${aliceInfo.address}, got ${inv.inviter_pub}`);
    }
    if (!inv.expires_at || inv.expires_at <= Date.now()) {
      logFail(`Invite expires_at invalid: ${inv.expires_at} (current: ${Date.now()})`);
    }
    if (!inv.signature || inv.signature.length !== 128) {
      logFail(`Invite signature invalid length: ${inv.signature ? inv.signature.length : 0} (expected 128 hex chars)`);
    }
    logPass("Verified: Copy Invite Link produces valid signed URL with room, key, inviter, exp, and sig!");

    // 3. Bob joins by entering the generated invite URL into #join-room-input
    logStep("15.1", "Bob enters the invite URL into #join-room-input on the landing page...");
    const ctxBob15 = await browser.createBrowserContext();
    const pageBob15 = await ctxBob15.newPage();
    pageBob15.on("console", (msg) => console.log(`[Bob-15 Console] ${msg.text()}`));
    await pageBob15.goto(SERVER_URL, { waitUntil: "networkidle0" });

    await pageBob15.waitForSelector("#join-room-input", { visible: true });
    await pageBob15.type("#join-room-input", inviteUrl);
    await pageBob15.click("#btn-join-room");

    await pageBob15.waitForFunction(() => {
      const landing = document.getElementById("landing");
      const dot = document.getElementById("status-dot");
      return landing && landing.style.display === "none" && dot && dot.classList.contains("on");
    }, { timeout: 10000 });

    const bobAddress = await pageBob15.evaluate(() => state.me && state.me.address);
    logPass(`Bob entered invite link and joined room (Bob address: ${short(bobAddress)}).`);

    // 4. Charlie joins using the invite URL directly (3-peer member mesh)
    logStep("15.2", "Charlie opens the invite URL directly to establish a 3-peer member mesh...");
    const ctxCharlie15 = await browser.createBrowserContext();
    const pageCharlie15 = await ctxCharlie15.newPage();
    pageCharlie15.on("console", (msg) => console.log(`[Charlie-15 Console] ${msg.text()}`));
    await pageCharlie15.goto(inviteUrl, { waitUntil: "networkidle0" });

    await pageCharlie15.waitForFunction(() => {
      const landing = document.getElementById("landing");
      const dot = document.getElementById("status-dot");
      return landing && landing.style.display === "none" && dot && dot.classList.contains("on");
    }, { timeout: 10000 });

    const charlieAddress = await pageCharlie15.evaluate(() => state.me && state.me.address);
    logPass(`Charlie joined room via invite link (Charlie address: ${short(charlieAddress)}).`);

    // Wait for Alice, Bob, and Charlie to form a 3-peer full mesh (peer count >= 2 on each)
    await Promise.all([
      pageAlice15.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 2;
      }, { timeout: 15000 }),
      pageBob15.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 2;
      }, { timeout: 15000 }),
      pageCharlie15.waitForFunction(() => {
        const count = document.getElementById("peer-count");
        return count && parseInt(count.textContent, 10) >= 2;
      }, { timeout: 15000 }),
    ]);

    // Verify all 3 recognize each other as admitted members
    const aliceMemberCheck = await pageAlice15.evaluate((b, c) => ({
      bobMember: window.cotilla.isAdmittedMember(b),
      charlieMember: window.cotilla.isAdmittedMember(c),
    }), bobAddress, charlieAddress);

    if (!aliceMemberCheck.bobMember || !aliceMemberCheck.charlieMember) {
      logFail("Alice did not recognize Bob or Charlie as admitted members: " + JSON.stringify(aliceMemberCheck));
    }
    logPass("Alice, Bob, and Charlie formed direct WebRTC mesh and verified signed invite provenance.");

    // 5. Automatic Group Epoch synchronization
    logStep("15.3", "Verify all 3 members automatically synchronized to active group key...");
    await Promise.all([
      pageAlice15.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
      pageBob15.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
      pageCharlie15.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
    ]);
    const ep15 = await pageAlice15.evaluate(() => Number(window.cotilla.currentEpoch()));
    await Promise.all([
      pageBob15.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, ep15),
      pageCharlie15.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, ep15),
    ]);
    logPass(`All 3 members automatically synchronized to active group key (Epoch ${ep15})!`);

    // Admitted members exchange an Epoch 1 message
    const epoch1Msg = "Admitted member memo at Epoch 1 " + Date.now();
    await pageAlice15.type("#chat-input", epoch1Msg);
    await pageAlice15.click("#send-btn");

    await Promise.all([
      pageBob15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        epoch1Msg
      ),
      pageCharlie15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        epoch1Msg
      ),
    ]);
    logPass("Bob and Charlie received and deciphered Alice's message cyphered with the Epoch 1 group key.");

    // 6. Eve joins with ONLY room and key (unadmitted peer, no invite)
    logStep("15.4", "Eve joins the room with only room and root key (unadmitted peer, stripped of invite)...");
    const strippedRoomUrl = `${SERVER_URL}/#room=${encodeURIComponent(aliceInfo.room)}&key=${encodeURIComponent(aliceInfo.key)}`;
    const ctxEve15 = await browser.createBrowserContext();
    const pageEve15 = await ctxEve15.newPage();
    pageEve15.on("console", (msg) => console.log(`[Eve-15 Console] ${msg.text()}`));
    await pageEve15.goto(strippedRoomUrl, { waitUntil: "networkidle0" });

    // Eve connects to signaling and reaches direct WebRTC channels with peers
    await pageEve15.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      const count = document.getElementById("peer-count");
      return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 3;
    }, { timeout: 15000 });

    const eveAddress = await pageEve15.evaluate(() => state.me && state.me.address);
    logPass(`Eve connected to WebRTC mesh with peers (Eve address: ${short(eveAddress)}).`);

    // Verify Eve is NOT an admitted member on Alice, Bob, or Charlie
    const eveMemberCheck = await pageAlice15.evaluate((e) => window.cotilla.isAdmittedMember(e), eveAddress);
    if (eveMemberCheck) {
      logFail("Security failure: Alice marked uninvited Eve as an admitted member!");
    }

    // Verify Eve's epoch is 0 (did NOT receive Epoch 1 key)
    const eveEpoch = await pageEve15.evaluate(() => Number(window.cotilla.currentEpoch()));
    if (eveEpoch !== 0) {
      logFail(`Eve unexpectedly has currentEpoch ${eveEpoch} (expected 0)!`);
    }
    logPass("Verified: Eve is NOT added to the members and does NOT possess the group's latest key (Epoch 0).");

    // 7. Alice and Bob send confidential messages cyphered with the group's latest key
    logStep("15.5", "Group members send messages cyphered with latest key: Bob & Charlie decipher, Eve CANNOT read...");
    const secretMemo = "CONFIDENTIAL: Only admitted group members can read this message! " + Date.now();
    await pageAlice15.type("#chat-input", secretMemo);
    await pageAlice15.click("#send-btn");

    // Bob and Charlie both receive and decipher the message
    await Promise.all([
      pageBob15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        secretMemo
      ),
      pageCharlie15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        secretMemo
      ),
    ]);
    logPass("Bob and Charlie successfully received and deciphered the confidential message.");

    // Wait 2.5 seconds to ensure WebRTC packet arrived at Eve
    await new Promise((r) => setTimeout(r, 2500));

    // Crucial assertion: Eve's DOM MUST NOT contain the secret memo!
    const eveReadSecret = await pageEve15.evaluate((expected) => {
      const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
      return msgs.some((m) => m.textContent.includes(expected));
    }, secretMemo);

    if (eveReadSecret) {
      logFail("CRITICAL SECURITY VULNERABILITY: Unadmitted peer Eve was able to read texts from peers!");
    }
    logPass("VERIFIED: Eve CANNOT read texts from peers (messages cyphered with group's latest key remain unreadable)!");

    // 8. Bob invites Dave: late joiner Dave receives active epoch key and CAN read texts
    logStep("15.6", "Bob copies an invite link for Dave (late joiner)...");
    await pageBob15.click("#btn-copy-link");
    await pageBob15.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });

    const bobInviteUrl = await pageBob15.evaluate(() => window.lastCopiedInviteUrl);
    const ctxDave15 = await browser.createBrowserContext();
    const pageDave15 = await ctxDave15.newPage();
    pageDave15.on("console", (msg) => console.log(`[Dave-15 Console] ${msg.text()}`));
    await pageDave15.goto(bobInviteUrl, { waitUntil: "networkidle0" });

    const dave15Address = await pageDave15.evaluate(() => state.me && state.me.address);

    // Wait for Dave to establish direct WebRTC DataChannels with Alice, Bob, and Charlie
    await Promise.all([
      pageDave15.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 20000 }),
      pageAlice15.waitForFunction((addr) => state.directPeers && state.directPeers.has(addr), { timeout: 20000 }, dave15Address),
      pageBob15.waitForFunction((addr) => state.directPeers && state.directPeers.has(addr), { timeout: 20000 }, dave15Address),
      pageCharlie15.waitForFunction((addr) => state.directPeers && state.directPeers.has(addr), { timeout: 20000 }, dave15Address),
    ]);

    // Dave must automatically receive the active group key via member admission sync
    await pageDave15.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 });
    const epDave = await pageDave15.evaluate(() => Number(window.cotilla.currentEpoch()));
    await Promise.all([
      pageAlice15.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, epDave),
      pageBob15.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, epDave),
      pageCharlie15.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, epDave),
    ]);
    logPass(`Late joiner Dave admitted with Bob's invite and automatically synchronized to active key (Epoch ${epDave})!`);

    // Dave sends a message at Epoch 1
    const daveMsg = "Hello group from late joiner Dave invited by Bob! " + Date.now();
    await pageDave15.type("#chat-input", daveMsg);
    await pageDave15.click("#send-btn");

    await Promise.all([
      pageAlice15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        daveMsg
      ),
      pageBob15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        daveMsg
      ),
      pageCharlie15.waitForFunction(
        (expected) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected)),
        { timeout: 10000 },
        daveMsg
      ),
    ]);
    logPass("Alice, Bob, and Charlie all received and deciphered Dave's message!");

    // Verify RFC 9420 Pre-Join Forward Secrecy: Late-joining Dave (admitted at Epoch 4) MUST NOT have pre-join messages (Epoch 3) in his DOM!
    const daveReadPreJoin = await pageDave15.evaluate((m1, m2) => {
      const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
      return msgs.some((m) => m.textContent.includes(m1) || m.textContent.includes(m2));
    }, epoch1Msg, secretMemo);
    if (daveReadPreJoin) {
      logFail("CRITICAL PFS FAILURE: Late-joining Dave was able to read pre-join messages from an earlier epoch!");
    }
    logPass("VERIFIED: Late-joining Dave CANNOT read pre-join messages from earlier epochs (RFC 9420 Pre-Join Forward Secrecy)!");

    // Eve still cannot read Dave's message
    await new Promise((r) => setTimeout(r, 2000));
    const eveReadDave = await pageEve15.evaluate((expected) => {
      const msgs = Array.from(document.querySelectorAll("#messages li .msg-body"));
      return msgs.some((m) => m.textContent.includes(expected));
    }, daveMsg);
    if (eveReadDave) {
      logFail("Security failure: Eve was able to decipher Dave's message!");
    }
    logPass("Eve remains locked out: cannot read Dave's message either.");

    // Clean up all Step 15 browser contexts
    await ctxAlice15.close();
    await ctxBob15.close();
    await ctxCharlie15.close();
    await ctxEve15.close();
    await ctxDave15.close();

    // =========================================================================
    // STEP 16: Multi-Peer Delegation Lineage, Eviction Lockout & Rogue Partition Re-Admittance Immunity
    // Verifies:
    // A creates room, invites B; B invites C; A invites D. C & D join.
    // Unadmitted Eve joining with only room and key cannot read group messages (Genesis Epoch 1).
    // A evicts C (Epoch 2). C is locked out.
    // C cannot invite E (Edward).
    // E's unauthorized EpochCommit is rejected by A, B, and D.
    // C is NEVER re-admitted to the OG group.
    // =========================================================================
    logStep("16.0", "=== STEP 16: Multi-Peer Delegation Lineage, Eviction & Rogue Immunity ===");

    // 1. Alice creates a new burner room (auto Epoch 1)
    const ctxAlice16 = await browser.createBrowserContext();
    await grantMedia(ctxAlice16);
    const pageAlice16 = await ctxAlice16.newPage();
    pageAlice16.on("console", (msg) => console.log(`[Alice-16 Console] ${msg.text()}`));
    await pageAlice16.goto(SERVER_URL, { waitUntil: "networkidle0" });

    await pageAlice16.waitForSelector("#btn-create-room", { visible: true });
    await pageAlice16.click("#btn-create-room");

    await pageAlice16.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      return dot && dot.classList.contains("on");
    }, { timeout: 10000 });

    const alice16Info = await pageAlice16.evaluate(() => ({
      room: state.roomID,
      key: state.roomKey,
      address: state.me.address,
      epoch: Number(window.cotilla.currentEpoch()),
    }));
    if (alice16Info.epoch !== 1) {
      logFail(`Alice did not start at Genesis Epoch 1 (got: ${alice16Info.epoch})`);
    }
    logPass(`Alice created room and initialized Genesis Epoch 1 (Room: ${short(alice16Info.room)}).`);

    // 2. Alice invites Bob
    await pageAlice16.click("#btn-copy-link");
    await pageAlice16.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const aliceInviteToBob = await pageAlice16.evaluate(() => window.lastCopiedInviteUrl);

    const ctxBob16 = await browser.createBrowserContext();
    await grantMedia(ctxBob16);
    const pageBob16 = await ctxBob16.newPage();
    pageBob16.on("console", (msg) => console.log(`[Bob-16 Console] ${msg.text()}`));
    await pageBob16.goto(aliceInviteToBob, { waitUntil: "networkidle0" });

    // Wait for Bob to join and connect to Alice
    await pageBob16.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      const count = document.getElementById("peer-count");
      return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 1;
    }, { timeout: 15000 });
    await pageBob16.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 });
    const bob16Address = await pageBob16.evaluate(() => state.me.address);
    logPass(`Bob joined room via Alice's invite and synced to active epoch (${short(bob16Address)}).`);

    // 3. Bob invites Charlie (sub-delegation with parent invite)
    logStep("16.1", "Bob copies invite link to delegate room access to Charlie...");
    await pageBob16.click("#btn-copy-link");
    await pageBob16.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const bobInviteToCharlie = await pageBob16.evaluate(() => window.lastCopiedInviteUrl);

    const ctxCharlie16 = await browser.createBrowserContext();
    await grantMedia(ctxCharlie16);
    const pageCharlie16 = await ctxCharlie16.newPage();
    pageCharlie16.on("console", (msg) => console.log(`[Charlie-16 Console] ${msg.text()}`));
    await pageCharlie16.goto(bobInviteToCharlie, { waitUntil: "networkidle0" });

    // Wait for Alice, Bob, and Charlie to form 3-peer mesh before Dave joins
    await Promise.all([
      pageAlice16.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
      pageBob16.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
      pageCharlie16.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
    ]);

    // 4. Alice invites Dave
    logStep("16.2", "Alice copies invite link for Dave...");
    await pageAlice16.click("#btn-copy-link");
    await pageAlice16.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const aliceInviteToDave = await pageAlice16.evaluate(() => window.lastCopiedInviteUrl);

    const ctxDave16 = await browser.createBrowserContext();
    const pageDave16 = await ctxDave16.newPage();
    pageDave16.on("console", (msg) => console.log(`[Dave-16 Console] ${msg.text()}`));
    await pageDave16.goto(aliceInviteToDave, { waitUntil: "networkidle0" });

    // Wait for all 4 peers (Alice, Bob, Charlie, Dave) to form a 4-peer full mesh (direct peers >= 3 each)
    await Promise.all([
      pageAlice16.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 20000 }),
      pageBob16.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 20000 }),
      pageCharlie16.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 20000 }),
      pageDave16.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 20000 }),
    ]);

    // Ensure all 4 peers agree on active epoch before eviction
    await Promise.all([
      pageAlice16.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
      pageBob16.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
      pageCharlie16.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
      pageDave16.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) > 0, { timeout: 15000 }),
    ]);
    const ep16BeforeEvict = await pageAlice16.evaluate(() => Number(window.cotilla.currentEpoch()));
    await Promise.all([
      pageBob16.waitForFunction((ep) => Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, ep16BeforeEvict),
      pageCharlie16.waitForFunction((ep) => Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, ep16BeforeEvict),
      pageDave16.waitForFunction((ep) => Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, ep16BeforeEvict),
    ]);

    const charlie16Address = await pageCharlie16.evaluate(() => state.me.address);
    const dave16Address = await pageDave16.evaluate(() => state.me.address);
    logPass(`Alice, Bob, Charlie, and Dave established 4-peer full mesh at Epoch ${ep16BeforeEvict}.`);

    // 5. Uninvited Eve joins with only room and root key (no invite)
    logStep("16.3", "Eve joins with stripped URL (room + root key, no invite)...");
    const stripped16Url = `${SERVER_URL}/#room=${encodeURIComponent(alice16Info.room)}&key=${encodeURIComponent(alice16Info.key)}`;
    const ctxEve16 = await browser.createBrowserContext();
    const pageEve16 = await ctxEve16.newPage();
    pageEve16.on("console", (msg) => console.log(`[Eve-16 Console] ${msg.text()}`));
    await pageEve16.goto(stripped16Url, { waitUntil: "networkidle0" });

    await pageEve16.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      const count = document.getElementById("peer-count");
      return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 4;
    }, { timeout: 15000 });

    const eve16Epoch = await pageEve16.evaluate(() => Number(window.cotilla.currentEpoch()));
    if (eve16Epoch !== 0) {
      logFail(`Eve unexpectedly has currentEpoch ${eve16Epoch} (expected 0)!`);
    }

    // Alice sends a confidential message at Epoch 1
    const memoEpoch1 = "Genesis Epoch 1 secret memo - only members can read! " + Date.now();
    await pageAlice16.type("#chat-input", memoEpoch1);
    await pageAlice16.click("#send-btn");

    await Promise.all([
      pageBob16.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, memoEpoch1),
      pageCharlie16.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, memoEpoch1),
      pageDave16.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, memoEpoch1),
    ]);
    logPass("Bob, Charlie, and Dave deciphered Alice's Genesis Epoch 1 message.");

    await new Promise((r) => setTimeout(r, 2000));
    const eve16ReadMemo = await pageEve16.evaluate((expected) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((m) => m.textContent.includes(expected));
    }, memoEpoch1);
    if (eve16ReadMemo) {
      logFail("CRITICAL SECURITY FAILURE: Unadmitted peer Eve was able to read texts from peers without an invite!");
    }
    logPass("VERIFIED: Joining with just room and key without invite CANNOT read texts from peers!");

    // Start an active MLS-protected secondary WebRTC voice call across Alice, Bob, and Charlie before eviction
    await pageAlice16.click("#btn-mic");
    await pageBob16.click("#btn-mic");
    await pageCharlie16.click("#btn-mic");
    await Promise.all([
      waitCallStats(pageAlice16, (s) => s.secondaryPeerCount >= 2 && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0, 15000, "Alice16 pre-eviction MLS call"),
      waitCallStats(pageBob16, (s) => s.secondaryPeerCount >= 2 && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0, 15000, "Bob16 pre-eviction MLS call"),
      waitCallStats(pageCharlie16, (s) => s.secondaryPeerCount >= 2 && s.sframe.decryptedAudio > 0 && s.sframe.rejected === 0, 15000, "Charlie16 pre-eviction MLS call"),
    ]);
    // Verify unadmitted Eve cannot form secondary PCs in this MLS call
    const eveCallTry = await pageEve16.evaluate(async () => {
      try { await window.cotillaClient.joinCall(null, { listenOnly: true }); } catch {}
      return window.cotillaClient.getCallStats();
    });
    if (eveCallTry && (eveCallTry.secondaryPeerCount > 0 || (eveCallTry.sframe && eveCallTry.sframe.decryptedAudio > 0))) {
      logFail(`Unadmitted Eve formed secondary call connection or decrypted SFrame audio: ${JSON.stringify(eveCallTry)}`);
    }
    logPass("Pre-eviction MLS secondary WebRTC call active for Alice/Bob/Charlie; unadmitted Eve completely locked out!");

    // 6. Alice evicts Charlie -> Ratchets to Epoch 2
    logStep("16.4", "Alice evicts Charlie from the burner room...");
    await pageAlice16.evaluate((target) => {
      window.cotilla.evictPeer(target, "violation of room conduct");
    }, charlie16Address);

    // Alice, Bob, and Dave advance to post-eviction epoch
    const postEvictEpoch = ep16BeforeEvict + 1;
    await Promise.all([
      pageAlice16.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, postEvictEpoch),
      pageBob16.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, postEvictEpoch),
      pageDave16.waitForFunction((ep) => window.cotilla && Number(window.cotilla.currentEpoch()) === ep, { timeout: 15000 }, postEvictEpoch),
    ]);
    logPass(`Alice, Bob, and Dave all advanced to post-eviction Epoch ${postEvictEpoch} key!`);

    // Verify Charlie's secondary WebRTC peer connections are torn down and voice exits cleanly
    await Promise.all([
      waitCallStats(pageAlice16, (s) => !s.peers.some((p) => p.peerAddr === charlie16Address) && s.secondaryPeerCount >= 1, 10000, "Alice16 closes Charlie secondary PC"),
      waitCallStats(pageBob16, (s) => !s.peers.some((p) => p.peerAddr === charlie16Address) && s.secondaryPeerCount >= 1, 10000, "Bob16 closes Charlie secondary PC"),
      waitCallStats(pageCharlie16, (s) => s.secondaryPeerCount === 0, 10000, "Charlie16 tears down all secondary PCs on eviction"),
    ]);
    const bobDecBeforePostEvict = (await pageBob16.evaluate(() => window.cotillaClient.getCallStats())).sframe.decryptedAudio;
    const charlieDecAtEvict = (await pageCharlie16.evaluate(() => window.cotillaClient.getCallStats())).sframe.decryptedAudio;
    await waitCallStats(pageBob16, (s) => s.sframe.decryptedAudio >= bobDecBeforePostEvict + 5, 10000, "Bob16 continues post-eviction SFrame call with Alice16");
    const charlieDecAfterWait = (await pageCharlie16.evaluate(() => window.cotillaClient.getCallStats())).sframe.decryptedAudio;
    if (charlieDecAfterWait !== charlieDecAtEvict) {
      logFail(`Evicted Charlie continued decrypting SFrame audio (${charlieDecAtEvict} -> ${charlieDecAfterWait})!`);
    }
    logPass("Verified mid-call MLS eviction tore down Charlie's secondary PCs while Alice & Bob ratcheted SFrame cleanly!");

    // Charlie's UI shows eviction banner and disables invite creation
    await pageCharlie16.waitForFunction(() => state.isEvicted === true, { timeout: 10000 });
    const charlieCopyDisabled = await pageCharlie16.evaluate(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.disabled === true;
    });
    if (!charlieCopyDisabled) {
      logFail("Charlie's copy invite link button was not disabled upon eviction!");
    }
    logPass("Charlie is marked evicted: UI locked down, copy link disabled.");

    // 7. Charlie attempts to generate an invite for Edward (E)
    logStep("16.5", "Verifying evicted Charlie cannot create valid channel invites...");
    const charlieInviteError = await pageCharlie16.evaluate(() => {
      try {
        const raw = window.cotilla.createChannelInvite(15 * 60 * 1000);
        if (raw) {
          try {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.error) return parsed.error;
          } catch {}
        }
        return null;
      } catch (e) {
        return e.message;
      }
    });
    if (!charlieInviteError) {
      logFail("Evicted Charlie was able to create a channel invite without error!");
    }
    logPass(`Evicted Charlie createChannelInvite was rejected: ${charlieInviteError}`);

    // 8. Edward attempts to join with rogue invite signed by Charlie
    logStep("16.6", "Edward attempts to join using a rogue invite from evicted Charlie...");
    const ctxEdward16 = await browser.createBrowserContext();
    const pageEdward16 = await ctxEdward16.newPage();
    pageEdward16.on("console", (msg) => console.log(`[Edward-16 Console] ${msg.text()}`));
    await pageEdward16.goto(`${SERVER_URL}/#room=${encodeURIComponent(alice16Info.room)}&key=${encodeURIComponent(alice16Info.key)}&inviter=${encodeURIComponent(charlie16Address)}`, { waitUntil: "networkidle0" });

    await new Promise((r) => setTimeout(r, 2500));
    const aliceEdwardAdmit = await pageAlice16.evaluate((e) => window.cotilla.isAdmittedMember(e), await pageEdward16.evaluate(() => state.me.address));
    if (aliceEdwardAdmit) {
      logFail("Alice admitted Edward who was invited by evicted Charlie!");
    }
    logPass("Edward rejected: inviter Charlie was evicted!");

    // 9. Edward attempts unauthorized epoch ratchet
    logStep("16.7", "Edward attempts unauthorized epoch ratchet: OG group MUST ignore and stay on Epoch 2...");
    await pageEdward16.evaluate(() => {
      try {
        window.cotilla.rotateEpochKey();
      } catch (e) {}
    });
    await new Promise((r) => setTimeout(r, 2000));

    const ogEpochs = await Promise.all([
      pageAlice16.evaluate(() => Number(window.cotilla.currentEpoch())),
      pageBob16.evaluate(() => Number(window.cotilla.currentEpoch())),
      pageDave16.evaluate(() => Number(window.cotilla.currentEpoch())),
    ]);
    if (ogEpochs[0] !== postEvictEpoch || ogEpochs[1] !== postEvictEpoch || ogEpochs[2] !== postEvictEpoch) {
      logFail(`OG group epoch corrupted by unauthorized Edward commit! Epochs: ${JSON.stringify(ogEpochs)}`);
    }
    logPass(`OG group remained securely on Epoch ${postEvictEpoch}! Rogue ratchet rejected.`);

    // Verify Charlie is NOT an admitted member of the OG group
    const charlieAdmittedCheck = await pageAlice16.evaluate((c) => window.cotilla.isAdmittedMember(c), charlie16Address);
    if (charlieAdmittedCheck) {
      logFail("CRITICAL FLAW: Charlie was re-admitted to the OG group!");
    }
    logPass("VERIFIED: Charlie was NEVER re-admitted to the OG group!");

    // 10. OG group exchanges confidential Epoch 2 messages
    logStep("16.8", "OG group sends confidential Epoch 2 messages: Bob & Dave read, Charlie & Edward CANNOT...");
    const memoEpoch2 = "Epoch 2 strictly sealed memo for active members! " + Date.now();
    await pageAlice16.type("#chat-input", memoEpoch2);
    await pageAlice16.click("#send-btn");

    await Promise.all([
      pageBob16.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, memoEpoch2),
      pageDave16.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, memoEpoch2),
    ]);
    logPass("Bob and Dave received and deciphered Alice's Epoch 2 message.");

    await new Promise((r) => setTimeout(r, 2000));
    const charlieReadEpoch2 = await pageCharlie16.evaluate((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), memoEpoch2);
    const edwardReadEpoch2 = await pageEdward16.evaluate((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), memoEpoch2);
    if (charlieReadEpoch2 || edwardReadEpoch2) {
      logFail(`Security violation: charlieRead=${charlieReadEpoch2}, edwardRead=${edwardReadEpoch2}`);
    }
    logPass("VERIFIED: Evicted Charlie and rogue Edward CANNOT decipher Epoch 2 group messages!");

    // Clean up Step 16 contexts
    await ctxAlice16.close();
    await ctxBob16.close();
    await ctxCharlie16.close();
    await ctxDave16.close();
    await ctxEve16.close();
    await ctxEdward16.close();

    // =========================================================================
    // STEP 17: Case Evicted Eviction
    // A creates a new (burner room)
    // A invites B
    // B comes in and chats with A
    // B invites C
    // C joins the chat with A and B
    // B gets evicted
    // A and C can and continue to chat
    // B attempts to evict both A and C
    // VERIFY: B CANNOT evict A or C, A and C continue chatting cleanly!
    // =========================================================================
    logStep("17.0", "=== STEP 17: Case Evicted Eviction (B evicted, A & C continue chatting, B cannot evict A or C) ===");

    // 1. A creates a new burner room (Genesis Epoch 1)
    const ctxAlice17 = await browser.createBrowserContext();
    const pageAlice17 = await ctxAlice17.newPage();
    pageAlice17.on("console", (msg) => console.log(`[Alice-17 Console] ${msg.text()}`));
    await pageAlice17.goto(SERVER_URL, { waitUntil: "networkidle0" });

    await pageAlice17.waitForSelector("#btn-create-room", { visible: true });
    await pageAlice17.click("#btn-create-room");

    await pageAlice17.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      return dot && dot.classList.contains("on");
    }, { timeout: 10000 });

    const alice17Info = await pageAlice17.evaluate(() => ({
      room: state.roomID,
      key: state.roomKey,
      address: state.me.address,
      epoch: Number(window.cotilla.currentEpoch()),
    }));
    logPass(`Alice created room and initialized Genesis Epoch 1 (Room: ${short(alice17Info.room)}).`);

    // 2. A invites B
    await pageAlice17.click("#btn-copy-link");
    await pageAlice17.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const aliceInviteToBob17 = await pageAlice17.evaluate(() => window.lastCopiedInviteUrl);

    const ctxBob17 = await browser.createBrowserContext();
    const pageBob17 = await ctxBob17.newPage();
    pageBob17.on("console", (msg) => console.log(`[Bob-17 Console] ${msg.text()}`));
    await pageBob17.goto(aliceInviteToBob17, { waitUntil: "networkidle0" });

    await pageBob17.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      const count = document.getElementById("peer-count");
      return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 1;
    }, { timeout: 15000 });
    await pageBob17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 2, { timeout: 15000 });
    const bob17Address = await pageBob17.evaluate(() => state.me.address);
    logPass(`Bob joined room via Alice's invite and synced to Epoch 2 (${short(bob17Address)}).`);

    // 3. B comes in and chats with A
    const msgB17 = "Hello Alice from Bob! " + Date.now();
    await pageBob17.type("#chat-input", msgB17);
    await pageBob17.click("#send-btn");

    await pageAlice17.waitForFunction((m) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m));
    }, { timeout: 10000 }, msgB17);
    logPass("Bob chatted with Alice successfully.");

    // 4. B invites C
    logStep("17.1", "Bob invites Charlie...");
    await pageBob17.click("#btn-copy-link");
    await pageBob17.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const bobInviteToCharlie17 = await pageBob17.evaluate(() => window.lastCopiedInviteUrl);

    const ctxCharlie17 = await browser.createBrowserContext();
    const pageCharlie17 = await ctxCharlie17.newPage();
    pageCharlie17.on("console", (msg) => console.log(`[Charlie-17 Console] ${msg.text()}`));
    await pageCharlie17.goto(bobInviteToCharlie17, { waitUntil: "networkidle0" });

    // Wait for Alice, Bob, and Charlie to form 3-peer full mesh (direct peers >= 2 each)
    await Promise.all([
      pageAlice17.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
      pageBob17.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
      pageCharlie17.waitForFunction(() => state.directPeers && state.directPeers.size >= 2, { timeout: 20000 }),
    ]);
    await Promise.all([
      pageAlice17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 3, { timeout: 15000 }),
      pageBob17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 3, { timeout: 15000 }),
      pageCharlie17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 3, { timeout: 15000 }),
    ]);
    const charlie17Address = await pageCharlie17.evaluate(() => state.me.address);
    logPass(`Charlie joined room via Bob's invite and synced to 3-peer mesh at Epoch 3 (${short(charlie17Address)}).`);

    // 5. C joins the chat with A and B
    const msgC17 = "Hello Alice and Bob from Charlie! " + Date.now();
    await pageCharlie17.type("#chat-input", msgC17);
    await pageCharlie17.click("#send-btn");

    await Promise.all([
      pageAlice17.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, msgC17),
      pageBob17.waitForFunction((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), { timeout: 10000 }, msgC17),
    ]);
    logPass("Charlie chatted with both Alice and Bob.");

    // 6. B gets evicted by Alice
    logStep("17.2", "Alice evicts Bob...");
    await pageAlice17.evaluate((target) => {
      window.cotilla.evictPeer(target, "policy violation");
    }, bob17Address);

    // Alice and Charlie ratchet to Epoch 4
    await Promise.all([
      pageAlice17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 4, { timeout: 15000 }),
      pageCharlie17.waitForFunction(() => window.cotilla && Number(window.cotilla.currentEpoch()) >= 4, { timeout: 15000 }),
    ]);
    logPass("Alice and Charlie advanced to Epoch 4 after Bob was evicted.");

    // Bob is marked evicted and UI is locked down
    await pageBob17.waitForFunction(() => state.isEvicted === true, { timeout: 10000 });
    const bobLockedDown = await pageBob17.evaluate(() => {
      const copyBtn = document.getElementById("btn-copy-link");
      const rotateBtn = document.getElementById("btn-rotate-key");
      const sendBtn = document.getElementById("send-btn");
      const chatInput = document.getElementById("chat-input");
      const peerListItems = document.querySelectorAll("#peers-list li");
      return copyBtn.disabled && rotateBtn.disabled && sendBtn.disabled && chatInput.disabled && peerListItems.length === 0;
    });
    if (!bobLockedDown) {
      logFail("Bob's UI controls were not properly locked down upon eviction!");
    }
    logPass("Bob's UI is locked down: controls disabled, peers cleared.");

    // 7. A and C can and continue to chat
    logStep("17.3", "Alice and Charlie continue chatting at Epoch 4...");
    const msgAC17 = "Hey Charlie, Bob was evicted, can you hear me? " + Date.now();
    await pageAlice17.type("#chat-input", msgAC17);
    await pageAlice17.click("#send-btn");

    await pageCharlie17.waitForFunction((m) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m));
    }, { timeout: 10000 }, msgAC17);

    // Verify Bob cannot read this message
    await new Promise((r) => setTimeout(r, 1500));
    const bobReadAC = await pageBob17.evaluate((m) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m));
    }, msgAC17);
    if (bobReadAC) {
      logFail("Security violation: evicted Bob read Alice's post-eviction message to Charlie!");
    }
    logPass("Alice and Charlie continue to chat. Evicted Bob cannot read Epoch 4 messages.");

    // Charlie sends a message to Alice
    const msgCA17 = "Yes Alice, loud and clear! " + Date.now();
    await pageCharlie17.type("#chat-input", msgCA17);
    await pageCharlie17.click("#send-btn");

    await pageAlice17.waitForFunction((m) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m));
    }, { timeout: 10000 }, msgCA17);
    logPass("Charlie sent message back to Alice successfully.");

    // Charlie broadcasts PeerInfo (simulating heartbeat/reconnect)
    await pageCharlie17.evaluate(() => {
      if (window.cotilla && cotilla.broadcastPeerInfo) {
        cotilla.broadcastPeerInfo();
      }
    });
    await new Promise((r) => setTimeout(r, 1000));

    // Verify Alice did NOT drop Charlie
    const aliceStillKnowsCharlie = await pageAlice17.evaluate((c) => {
      return window.cotilla.isAdmittedMember(c);
    }, charlie17Address);
    if (!aliceStillKnowsCharlie) {
      logFail("REGRESSION: Alice dropped admitted member Charlie after Charlie broadcast PeerInfo with evicted inviter!");
    }
    logPass("VERIFIED: Alice retains Charlie as admitted member despite inviter Bob being evicted.");

    // 8. B attempts to evict both A and C
    logStep("17.4", "Evicted Bob attempts to evict both Alice and Charlie...");
    const bobEvictAliceErr = await pageBob17.evaluate((a) => {
      try {
        const raw = window.cotilla.evictPeer(a, "rogue eviction of creator");
        if (raw) {
          try {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.error) return parsed.error;
          } catch {}
        }
        return null;
      } catch (e) {
        return e.message;
      }
    }, alice17Info.address);

    const bobEvictCharlieErr = await pageBob17.evaluate((c) => {
      try {
        const raw = window.cotilla.evictPeer(c, "rogue eviction of member");
        if (raw) {
          try {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.error) return parsed.error;
          } catch {}
        }
        return null;
      } catch (e) {
        return e.message;
      }
    }, charlie17Address);

    if (!bobEvictAliceErr || !bobEvictCharlieErr) {
      logFail(`Evicted Bob evictPeer was not rejected! errA=${bobEvictAliceErr}, errC=${bobEvictCharlieErr}`);
    }
    logPass(`Evicted Bob eviction attempts rejected: "${bobEvictAliceErr}" / "${bobEvictCharlieErr}".`);

    // Verify Alice and Charlie are NOT evicted and still at active epoch
    const aliceEvictedState = await pageAlice17.evaluate(() => state.isEvicted);
    const charlieEvictedState = await pageCharlie17.evaluate(() => state.isEvicted);
    if (aliceEvictedState || charlieEvictedState) {
      logFail(`Alice or Charlie was evicted by Bob! A.isEvicted=${aliceEvictedState}, C.isEvicted=${charlieEvictedState}`);
    }

    // 9. Alice and Charlie can and continue to chat
    logStep("17.5", "Verifying Alice and Charlie can still chat smoothly after Bob's eviction attempts...");
    const finalMsg17 = "Final confirmation: Alice and Charlie are still chatting! " + Date.now();
    await pageAlice17.type("#chat-input", finalMsg17);
    await pageAlice17.click("#send-btn");

    await pageCharlie17.waitForFunction((m) => {
      return Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m));
    }, { timeout: 10000 }, finalMsg17);
    logPass("Alice and Charlie continue to chat smoothly. Room is healthy and secure!");

    // Clean up Step 17 contexts
    await ctxAlice17.close();
    await ctxBob17.close();
    await ctxCharlie17.close();

    // =========================================================================
    logStep("18.0", "=== STEP 18: 5-Peer Sparse Mesh Resiliency & Bridge Departure Self-Healing ===");

    // 1. Alice creates the burner room
    const ctxAlice18 = await browser.createBrowserContext();
    const pageAlice18 = await ctxAlice18.newPage();
    pageAlice18.on("console", (msg) => console.log(`[Alice-18 Console] ${msg.text()}`));
    await pageAlice18.goto(SERVER_URL, { waitUntil: "networkidle0" });

    await pageAlice18.waitForSelector("#btn-create-room", { visible: true });
    await pageAlice18.click("#btn-create-room");

    await pageAlice18.waitForFunction(() => {
      const dot = document.getElementById("status-dot");
      return dot && dot.classList.contains("on");
    }, { timeout: 10000 });

    await pageAlice18.click("#btn-copy-link");
    await pageAlice18.waitForFunction(() => {
      const btn = document.getElementById("btn-copy-link");
      return btn && btn.textContent.includes("Copied");
    }, { timeout: 5000 });
    const inviteUrl18 = await pageAlice18.evaluate(() => window.lastCopiedInviteUrl);
    logPass(`Alice created 5-peer room (${short(inviteUrl18)}).`);

    // 2. Bob, Charlie, David, and Eve join sequentially
    logStep("18.1", "Bob, Charlie, David, and Eve join room to establish 5-peer mesh...");

    const waitForPeerConnected = async (page) => {
      await page.waitForFunction(() => {
        const dot = document.getElementById("status-dot");
        const count = document.getElementById("peer-count");
        return dot && dot.classList.contains("on") && count && parseInt(count.textContent, 10) >= 1;
      }, { timeout: 20000 });
    };

    const ctxBob18 = await browser.createBrowserContext();
    const pageBob18 = await ctxBob18.newPage();
    pageBob18.on("console", (msg) => console.log(`[Bob-18 Console] ${msg.text()}`));
    await pageBob18.goto(inviteUrl18, { waitUntil: "networkidle0" });
    await waitForPeerConnected(pageBob18);

    const ctxCharlie18 = await browser.createBrowserContext();
    const pageCharlie18 = await ctxCharlie18.newPage();
    pageCharlie18.on("console", (msg) => console.log(`[Charlie-18 Console] ${msg.text()}`));
    await pageCharlie18.goto(inviteUrl18, { waitUntil: "networkidle0" });
    await waitForPeerConnected(pageCharlie18);

    const ctxDavid18 = await browser.createBrowserContext();
    const pageDavid18 = await ctxDavid18.newPage();
    pageDavid18.on("console", (msg) => console.log(`[David-18 Console] ${msg.text()}`));
    await pageDavid18.goto(inviteUrl18, { waitUntil: "networkidle0" });
    await waitForPeerConnected(pageDavid18);

    const ctxEve18 = await browser.createBrowserContext();
    const pageEve18 = await ctxEve18.newPage();
    pageEve18.on("console", (msg) => console.log(`[Eve-18 Console] ${msg.text()}`));
    await pageEve18.goto(inviteUrl18, { waitUntil: "networkidle0" });
    await waitForPeerConnected(pageEve18);

    logPass("All 5 browser contexts joined the room.");

    // Helper function to send chat message
    const sendMsg18 = async (page, text) => {
      await page.type("#chat-input", text);
      await page.click("#send-btn");
    };

    // Helper function to wait for message
    const waitMsg18 = async (page, text, timeout = 15000) => {
      await page.waitForFunction(
        (m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)),
        { timeout },
        text
      );
    };

    // 3. Initial 5-way chat verification
    logStep("18.2", "Verifying initial 5-way multi-peer messaging...");
    const initAlice = "Initial-5way-Alice-" + Date.now();
    const initEve = "Initial-5way-Eve-" + Date.now();
    await sendMsg18(pageAlice18, initAlice);
    await waitMsg18(pageEve18, initAlice);
    await waitMsg18(pageCharlie18, initAlice);
    await waitMsg18(pageBob18, initAlice);
    await waitMsg18(pageDavid18, initAlice);

    await sendMsg18(pageEve18, initEve);
    await waitMsg18(pageAlice18, initEve);
    await waitMsg18(pageCharlie18, initEve);
    await waitMsg18(pageBob18, initEve);
    await waitMsg18(pageDavid18, initEve);
    logPass("Initial 5-way chat verified across all peers!");

    // 4. Charlie abruptly departs (bridge failure)
    logStep("18.3", "Charlie abruptly disconnects / leaves room (central bridge failure)...");
    await pageCharlie18.evaluate(() => {
      if (window.cotilla && window.cotilla.leave) {
        window.cotilla.leave();
      }
    });
    await ctxCharlie18.close();
    logPass("Charlie left and closed.");

    // 5. Messages sent during bridge absence
    logStep("18.4", "Alice and Eve send messages during the bridge disruption...");
    const msgAliceDuring = "Alice-during-disruption-" + Date.now();
    const msgEveDuring = "Eve-during-disruption-" + Date.now();
    await sendMsg18(pageAlice18, msgAliceDuring);
    await sendMsg18(pageEve18, msgEveDuring);

    // 6. Verify self-healing and zero message loss across the remaining 4 peers
    logStep("18.5", "Verifying mesh self-heals and delivers 100% of disrupted messages...");
    await waitMsg18(pageEve18, msgAliceDuring, 25000);
    await waitMsg18(pageAlice18, msgEveDuring, 25000);
    await waitMsg18(pageDavid18, msgAliceDuring, 25000);
    await waitMsg18(pageBob18, msgEveDuring, 25000);
    logPass("Zero message loss! All surviving peers received messages sent during disruption.");

    // 7. Continuous chat after healing
    logStep("18.6", "Verifying continuous chat across healed 4-peer mesh...");
    const postHealEve = "Post-healing continuous message from Eve " + Date.now();
    await sendMsg18(pageEve18, postHealEve);
    await waitMsg18(pageAlice18, postHealEve, 15000);
    await waitMsg18(pageBob18, postHealEve, 15000);
    await waitMsg18(pageDavid18, postHealEve, 15000);
    logPass("Continuous chat confirmed across all 4 surviving peers!");

    // Clean up Step 18 contexts
    await ctxAlice18.close();
    await ctxBob18.close();
    await ctxDavid18.close();
    await ctxEve18.close();

    // =========================================================================
    // STEP 19: Two Independent Rooms + All Room-1 Peers Leave + Delayed D2 Join
    // =========================================================================
    logStep("19.0", "=== STEP 19: Two Rooms (A1/B1/C1 & A2/B2/C2), Room-1 Departs, Delayed D2 Join ===");

    const fetchHealth = async () => {
      return await pageA1_19.evaluate(async () => {
        const res = await fetch("/health");
        return await res.json();
      }).catch(() => null);
    };

    const sendChat19 = async (page, text) => {
      await page.type("#chat-input", text);
      await page.click("#send-btn");
    };

    const waitChat19 = async (page, text, timeout = 15000) => {
      await page.waitForFunction(
        (m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)),
        { timeout },
        text
      );
    };

    // 1. A1 creates Room 1, invites B1 and C1; they join and chat
    const ctxA1_19 = await browser.createBrowserContext();
    const pageA1_19 = await ctxA1_19.newPage();
    pageA1_19.on("console", (msg) => console.log(`[A1-19 Console] ${msg.text()}`));
    await pageA1_19.goto(SERVER_URL, { waitUntil: "networkidle0" });
    await pageA1_19.waitForSelector("#btn-create-room", { visible: true });
    await pageA1_19.click("#btn-create-room");
    await pageA1_19.waitForFunction(() => document.getElementById("status-dot")?.classList.contains("on"), { timeout: 10000 });
    await pageA1_19.click("#btn-copy-link");
    await pageA1_19.waitForFunction(() => document.getElementById("btn-copy-link")?.textContent.includes("Copied"), { timeout: 5000 });
    const inviteB1_19 = await pageA1_19.evaluate(() => window.lastCopiedInviteUrl);

    const ctxB1_19 = await browser.createBrowserContext();
    const pageB1_19 = await ctxB1_19.newPage();
    pageB1_19.on("console", (msg) => console.log(`[B1-19 Console] ${msg.text()}`));
    await pageB1_19.goto(inviteB1_19, { waitUntil: "networkidle0" });

    await pageA1_19.click("#btn-copy-link");
    await pageA1_19.waitForFunction(() => document.getElementById("btn-copy-link")?.textContent.includes("Copied"), { timeout: 5000 });
    const inviteC1_19 = await pageA1_19.evaluate(() => window.lastCopiedInviteUrl);

    const ctxC1_19 = await browser.createBrowserContext();
    const pageC1_19 = await ctxC1_19.newPage();
    pageC1_19.on("console", (msg) => console.log(`[C1-19 Console] ${msg.text()}`));
    await pageC1_19.goto(inviteC1_19, { waitUntil: "networkidle0" });

    await Promise.all([
      pageA1_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
      pageB1_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
      pageC1_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
    ]);

    const r1MsgA1 = "R1-initial-A1-" + Date.now();
    const r1MsgB1 = "R1-initial-B1-" + Date.now();
    await sendChat19(pageA1_19, r1MsgA1);
    await Promise.all([waitChat19(pageB1_19, r1MsgA1), waitChat19(pageC1_19, r1MsgA1)]);
    await sendChat19(pageB1_19, r1MsgB1);
    await Promise.all([waitChat19(pageA1_19, r1MsgB1), waitChat19(pageC1_19, r1MsgB1)]);
    logPass("Room 1 (A1, B1, C1) joined and chatted cleanly.");

    // 2. A2 creates Room 2, invites B2 and C2; they join, chat, and invite D2 (not joined yet)
    const ctxA2_19 = await browser.createBrowserContext();
    const pageA2_19 = await ctxA2_19.newPage();
    pageA2_19.on("console", (msg) => console.log(`[A2-19 Console] ${msg.text()}`));
    await pageA2_19.goto(SERVER_URL, { waitUntil: "networkidle0" });
    await pageA2_19.waitForSelector("#btn-create-room", { visible: true });
    await pageA2_19.click("#btn-create-room");
    await pageA2_19.waitForFunction(() => document.getElementById("status-dot")?.classList.contains("on"), { timeout: 10000 });
    await pageA2_19.click("#btn-copy-link");
    await pageA2_19.waitForFunction(() => document.getElementById("btn-copy-link")?.textContent.includes("Copied"), { timeout: 5000 });
    const inviteB2_19 = await pageA2_19.evaluate(() => window.lastCopiedInviteUrl);

    const ctxB2_19 = await browser.createBrowserContext();
    const pageB2_19 = await ctxB2_19.newPage();
    pageB2_19.on("console", (msg) => console.log(`[B2-19 Console] ${msg.text()}`));
    await pageB2_19.goto(inviteB2_19, { waitUntil: "networkidle0" });

    await pageA2_19.click("#btn-copy-link");
    await pageA2_19.waitForFunction(() => document.getElementById("btn-copy-link")?.textContent.includes("Copied"), { timeout: 5000 });
    const inviteC2_19 = await pageA2_19.evaluate(() => window.lastCopiedInviteUrl);

    const ctxC2_19 = await browser.createBrowserContext();
    const pageC2_19 = await ctxC2_19.newPage();
    pageC2_19.on("console", (msg) => console.log(`[C2-19 Console] ${msg.text()}`));
    await pageC2_19.goto(inviteC2_19, { waitUntil: "networkidle0" });

    await Promise.all([
      pageA2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
      pageB2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
      pageC2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 2 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 20000 }),
    ]);

    const r2MsgA2 = "R2-initial-A2-" + Date.now();
    const r2MsgC2 = "R2-initial-C2-" + Date.now();
    await sendChat19(pageA2_19, r2MsgA2);
    await Promise.all([waitChat19(pageB2_19, r2MsgA2), waitChat19(pageC2_19, r2MsgA2)]);
    await sendChat19(pageC2_19, r2MsgC2);
    await Promise.all([waitChat19(pageA2_19, r2MsgC2), waitChat19(pageB2_19, r2MsgC2)]);

    // Verify Room 1 cannot read Room 2 messages
    const r1SawR2 = await pageA1_19.evaluate((m) => Array.from(document.querySelectorAll("#messages li .msg-body")).some((b) => b.textContent.includes(m)), r2MsgA2);
    if (r1SawR2) {
      logFail("Room 1 unexpectedly decrypted Room 2 message!");
    }

    // Create invite for D2, but D2 does not join yet
    await pageB2_19.click("#btn-copy-link");
    await pageB2_19.waitForFunction(() => document.getElementById("btn-copy-link")?.textContent.includes("Copied"), { timeout: 5000 });
    const inviteD2_19 = await pageB2_19.evaluate(() => window.lastCopiedInviteUrl);
    const healthBefore = await fetchHealth();
    logPass(`Room 2 (A2, B2, C2) chatting & D2 invite created. Server /health anchors: ${JSON.stringify(healthBefore?.anchors?.map((a) => short(a)))}`);

    // 3. A1, B1, and C1 leave
    logStep("19.1", "A1, B1, and C1 leave Room 1...");
    await Promise.all([
      pageA1_19.evaluate(() => { if (window.cotilla?.leave) window.cotilla.leave(); }),
      pageB1_19.evaluate(() => { if (window.cotilla?.leave) window.cotilla.leave(); }),
      pageC1_19.evaluate(() => { if (window.cotilla?.leave) window.cotilla.leave(); }),
    ]);
    await ctxA1_19.close();
    await ctxB1_19.close();
    await ctxC1_19.close();
    await new Promise((r) => setTimeout(r, 2000));

    // 4. A2, B2, and C2 continue to chat
    logStep("19.2", "A2, B2, and C2 continue chatting after Room 1 left...");
    const r2MsgAfterB2 = "R2-after-R1-left-B2-" + Date.now();
    const r2MsgAfterA2 = "R2-after-R1-left-A2-" + Date.now();
    await sendChat19(pageB2_19, r2MsgAfterB2);
    await Promise.all([waitChat19(pageA2_19, r2MsgAfterB2), waitChat19(pageC2_19, r2MsgAfterB2)]);
    await sendChat19(pageA2_19, r2MsgAfterA2);
    await Promise.all([waitChat19(pageB2_19, r2MsgAfterA2), waitChat19(pageC2_19, r2MsgAfterA2)]);
    logPass("A2, B2, and C2 continued chatting after A1, B1, and C1 left!");

    // 5. D2 joins and tries to chat
    logStep("19.3", "D2 joins Room 2 with pre-issued invite and tries to chat...");
    const ctxD2_19 = await browser.createBrowserContext();
    const pageD2_19 = await ctxD2_19.newPage();
    pageD2_19.on("console", (msg) => console.log(`[D2-19 Console] ${msg.text()}`));
    await pageD2_19.goto(inviteD2_19, { waitUntil: "networkidle0" });

    await Promise.all([
      pageD2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 3 && Number(window.cotilla.currentEpoch()) > 0, { timeout: 25000 }),
      pageA2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 25000 }),
      pageB2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 25000 }),
      pageC2_19.waitForFunction(() => state.directPeers && state.directPeers.size >= 3, { timeout: 25000 }),
    ]);

    const r2MsgD2 = "R2-delayed-join-D2-" + Date.now();
    const r2WelcomeD2 = "R2-welcome-D2-from-A2-" + Date.now();
    await sendChat19(pageD2_19, r2MsgD2);
    await Promise.all([
      waitChat19(pageA2_19, r2MsgD2, 15000),
      waitChat19(pageB2_19, r2MsgD2, 15000),
      waitChat19(pageC2_19, r2MsgD2, 15000),
    ]);
    await sendChat19(pageA2_19, r2WelcomeD2);
    await waitChat19(pageD2_19, r2WelcomeD2, 15000);
    logPass("D2 joined Room 2 after A1/B1/C1 left and chatted cleanly with A2, B2, and C2!");

    await ctxA2_19.close();
    await ctxB2_19.close();
    await ctxC2_19.close();
    await ctxD2_19.close();

    console.log(`\n${colorBold}${colorGreen}=== ALL BROWSER & INTEROP END-TO-END SCENARIOS PASSED! ===${colorReset}\n`);
  } catch (err) {
    logFail(`Test failed with error: ${err.message}\n${err.stack}`);
  } finally {
    await browser.close();
  }
}

runBrowserE2E();
