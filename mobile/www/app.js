// ScamShield AI - phone app logic.
//
// The app does NOT decide anything itself: it sends the message or
// screenshot to the ScamShield backend API (backend/api.py), which runs the
// same Python scanner as the website, and then displays the answer.
//
// Security note: every piece of text that comes from a message or from the
// server is shown with textContent, never innerHTML, so a malicious message
// cannot inject code into the app.

(function () {
  "use strict";

  const CONFIG = window.SCAMSHIELD_CONFIG || {};
  const KEYS = { api: "scamshield.apiUrl", keep: "scamshield.keepHistory", history: "scamshield.history" };
  const $ = (id) => document.getElementById(id);

  // ---------- storage (wrapped: storage can be unavailable) ----------
  function load(key, fallback) {
    try {
      const value = localStorage.getItem(key);
      return value === null ? fallback : JSON.parse(value);
    } catch (e) { return fallback; }
  }
  function save(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* ignore */ }
  }

  // ---------- Capacitor plugins (only exist inside the phone app) ----------
  function plugin(name) {
    const cap = window.Capacitor;
    if (!cap || !cap.isNativePlatform || !cap.isNativePlatform()) return null;
    if (cap.isPluginAvailable && !cap.isPluginAvailable(name)) return null;
    try { return cap.registerPlugin ? cap.registerPlugin(name) : (cap.Plugins || {})[name] || null; }
    catch (e) { return null; }
  }
  const Share = plugin("Share");
  const Clipboard = plugin("Clipboard");
  const Haptics = plugin("Haptics");
  const ShareReceiver = plugin("ShareReceiver"); // our own Android plugin

  // ---------- state ----------
  const state = {
    apiUrl: load(KEYS.api, CONFIG.defaultApiUrl || ""),
    keepHistory: load(KEYS.keep, false),
    history: load(KEYS.history, []),
    report: null,
  };

  // ---------- navigation ----------
  function show(screen) {
    document.querySelectorAll(".screen").forEach((s) => s.classList.toggle("active", s.id === "screen-" + screen));
    document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.screen === screen));
    window.scrollTo(0, 0);
  }
  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => show(tab.dataset.screen)));
  $("open-settings").addEventListener("click", () => show("settings"));

  // ---------- feedback ----------
  let toastTimer = null;
  function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 5000);
  }
  function busy(on, text) {
    $("busy-text").textContent = text || "Analysing…";
    $("busy").classList.toggle("hidden", !on);
  }

  // ---------- sign-in with Clerk (only if a publishable key is set) ----------
  //
  // Clerk's own sign-in box is loaded from your Clerk instance. When signed
  // in, every scan request carries a short-lived Clerk session token, which
  // the Python backend checks (backend/clerk_auth.py).
  const Auth = {
    enabled: Boolean(CONFIG.clerkPublishableKey),
    pendingShare: null,

    clerk() { return window.Clerk || null; },
    signedIn() { const c = this.clerk(); return Boolean(c && c.user); },

    async token() {
      if (!this.enabled) return null;
      const c = this.clerk();
      if (!c || !c.session) throw new Error("Please sign in first.");
      const token = await c.session.getToken();
      if (!token) throw new Error("Please sign in first.");
      return token;
    },

    // pk_test_<base64("your-app.clerk.accounts.dev$")> -> "your-app.clerk.accounts.dev"
    frontendApi(key) {
      try {
        const parts = key.split("_");
        const decoded = atob(parts.slice(2).join("_"));
        const domain = decoded.replace(/\$$/, "");
        return /^[a-z0-9.-]+$/i.test(domain) ? domain : null;
      } catch (e) { return null; }
    },

    loadScript(key, domain) {
      return new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = "https://" + domain + "/npm/@clerk/clerk-js@6/dist/clerk.browser.js";
        script.async = true;
        script.crossOrigin = "anonymous";
        script.setAttribute("data-clerk-publishable-key", key);
        script.onload = resolve;
        script.onerror = () => reject(new Error("Couldn't load the sign-in service. Check your internet connection."));
        document.head.appendChild(script);
      });
    },

    async init() {
      if (!this.enabled) return;
      document.body.classList.add("signed-out");
      show("signin");
      $("signin-status").textContent = "Loading sign-in…";
      const key = CONFIG.clerkPublishableKey;
      const domain = this.frontendApi(key);
      if (!domain) { $("signin-status").textContent = "⚠️ The Clerk publishable key in config.js looks wrong."; return; }
      try {
        await this.loadScript(key, domain);
        await this.clerk().load();
      } catch (e) {
        $("signin-status").textContent = "⚠️ " + (e.message || "Sign-in failed to load.");
        return;
      }
      $("signin-status").textContent = "";
      this.clerk().addListener(() => this.update());
      this.update();
    },

    update() {
      const c = this.clerk();
      if (this.signedIn()) {
        document.body.classList.remove("signed-out");
        try { c.unmountSignIn($("clerk-signin")); } catch (e) { /* not mounted */ }
        const email = c.user.primaryEmailAddress && c.user.primaryEmailAddress.emailAddress;
        $("account-name").textContent = "Signed in as " + (c.user.fullName || email || "your account");
        $("account-card").classList.remove("hidden");
        if (document.querySelector("#screen-signin.active")) show("scan");
        if (this.pendingShare) { const item = this.pendingShare; this.pendingShare = null; handleShared(item); }
      } else {
        this.showSignIn();
      }
    },

    showSignIn() {
      const c = this.clerk();
      document.body.classList.add("signed-out");
      $("account-card").classList.add("hidden");
      show("signin");
      if (c && c.loaded && !this.signedIn()) {
        try { c.mountSignIn($("clerk-signin"), { appearance: { variables: { colorPrimary: "#FF4B4B" } } }); }
        catch (e) { /* already mounted */ }
      }
    },
  };

  $("sign-out").addEventListener("click", async () => {
    const c = Auth.clerk();
    if (!c) return;
    state.report = null;
    $("results").classList.add("hidden");
    $("results-empty").classList.remove("hidden");
    await c.signOut();
  });

  // ---------- talking to the API ----------
  function apiBase() {
    return (state.apiUrl || "").trim().replace(/\/+$/, "");
  }

  async function callApi(path, options) {
    const base = apiBase();
    if (!base) throw new Error("Set the ScamShield server address in Settings (⚙️) first.");
    options = Object.assign({}, options);
    const token = await Auth.token();
    if (token) options.headers = Object.assign({}, options.headers, { Authorization: "Bearer " + token });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CONFIG.requestTimeoutMs || 45000);
    let response;
    try {
      response = await fetch(base + path, Object.assign({ signal: controller.signal }, options));
    } catch (e) {
      throw new Error(e.name === "AbortError"
        ? "The server took too long to answer. Please try again."
        : "Can't reach the ScamShield server. Check your internet connection or the server address in Settings.");
    } finally {
      clearTimeout(timer);
    }
    let data = null;
    try { data = await response.json(); } catch (e) { /* not JSON */ }
    // 401 = the server did not accept the sign-in. If Clerk says we're signed
    // out, show the sign-in box. If we ARE signed in, just show the message
    // (otherwise the user would be stuck on an empty sign-in screen).
    if (response.status === 401 && Auth.enabled && !Auth.signedIn()) Auth.showSignIn();
    if (!response.ok) {
      let detail = data && data.detail;
      if (Array.isArray(detail)) detail = "Please enter a message (up to 5,000 characters).";
      throw new Error(detail || ("The server returned an error (" + response.status + ")."));
    }
    return data;
  }

  async function scanText(text) {
    text = (text || "").trim();
    if (!text) { toast("Please enter or paste a message first."); return; }
    busy(true, "Analysing message…");
    try {
      const report = await callApi("/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      finish(report, text);
    } catch (e) {
      toast(e.message);
    } finally {
      busy(false);
    }
  }

  async function scanImage(blob, name) {
    busy(true, "Reading and analysing screenshot…");
    try {
      const prepared = await shrinkImage(blob);
      const form = new FormData();
      form.append("file", prepared, name || "screenshot.png");
      const report = await callApi("/scan-image", { method: "POST", body: form });
      finish(report, report.extracted_text || "");
    } catch (e) {
      toast(e.message);
    } finally {
      busy(false);
    }
  }

  // Big phone photos are shrunk before upload (server limit: 5 MB).
  function shrinkImage(blob) {
    const MAX_BYTES = 4.5 * 1024 * 1024;
    const MAX_SIDE = 2600;
    return new Promise((resolve) => {
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, MAX_SIDE / Math.max(img.width, img.height));
        if (scale === 1 && blob.size <= MAX_BYTES) { URL.revokeObjectURL(url); resolve(blob); return; }
        const canvas = document.createElement("canvas");
        canvas.width = Math.round(img.width * scale);
        canvas.height = Math.round(img.height * scale);
        canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(url);
        canvas.toBlob((out) => resolve(out || blob), "image/jpeg", 0.92);
      };
      img.onerror = () => { URL.revokeObjectURL(url); resolve(blob); };
      img.src = url;
    });
  }

  // ---------- showing results ----------
  const VERDICTS = {
    high: ["🚨 HIGH RISK — POSSIBLE SCAM",
      "Strong scam indicators were detected. Do not reply, click links, or share personal information."],
    review_ai: ["⚠️ NEEDS REVIEW — AI MODEL ONLY",
      "Only the AI model flagged this message. No security rule found scam behaviour. Check who sent it before acting."],
    review: ["⚠️ NEEDS REVIEW",
      "ScamShield found warning signs. Verify the message through an official channel."],
    none: ["ℹ️ NO KNOWN SCAM PATTERN DETECTED",
      "No strong pattern was detected. This does not prove the message is legitimate."],
  };

  function verdictKey(report) {
    if (report.level === "high") return "high";
    if (report.level === "review") return report.verdict_source === "ai" ? "review_ai" : "review";
    return "none";
  }

  function li(text, className) {
    const item = document.createElement("li");
    if (className) item.className = className;
    item.textContent = text;
    return item;
  }

  function render(report) {
    $("results-empty").classList.add("hidden");
    $("results").classList.remove("hidden");

    const key = verdictKey(report);
    $("verdict").className = "verdict " + (report.level || "none");
    $("verdict-title").textContent = VERDICTS[key][0];
    $("verdict-text").textContent = VERDICTS[key][1];
    $("risk-line").textContent = "Final assessment: " + report.risk;

    const source = report.verdict_source;
    $("source-label").textContent = "Verdict source: " + (report.verdict_source_label || "Unknown");
    $("badge-ai").classList.toggle("on", source === "ai" || source === "ai_and_rules");
    $("badge-rules").classList.toggle("on", source === "rules" || source === "ai_and_rules");
    const explanation = $("explanation");
    explanation.replaceChildren(...(report.explanation || []).map((line) => li(line)));

    const warnings = $("warnings");
    const items = (report.warnings || []).map((w) => {
      const item = li("", w.severity);
      const icon = w.severity === "high" ? "🚨 " : "⚠️ ";
      item.append(document.createTextNode(icon + w.description + " "));
      const tag = document.createElement("span");
      tag.className = "rule-set";
      tag.textContent = "(" + String(w.source || "").toUpperCase() + " rule)";
      item.append(tag);
      return item;
    });
    warnings.replaceChildren(...(items.length ? items : [li("No predefined warning signs detected.")]));

    const urls = report.urls || [];
    $("links-box").classList.toggle("hidden", urls.length === 0);
    $("links").replaceChildren(...urls.map((u) => li(u)));

    $("text-box").classList.toggle("hidden", !report.extracted_text);
    $("extracted").textContent = report.extracted_text || "";

    const pct = Math.round((report.ai_scam_probability || 0) * 100);
    $("ai-details").textContent =
      "V10 AI prediction: " + String(report.ai_prediction).toUpperCase() +
      " · scam probability " + pct + "% (" + report.ai_confidence + " confidence)" +
      " · original V7 prediction: " + String(report.v7_prediction).toUpperCase() +
      ". The AI alone can only give NEEDS REVIEW; HIGH RISK needs security-rule evidence.";
  }

  function finish(report, text) {
    $("toast").classList.add("hidden");
    state.report = report;
    render(report);
    show("results");
    if (report.level === "high" && Haptics) {
      Haptics.notification({ type: "WARNING" }).catch(() => {});
    }
    if (state.keepHistory) {
      state.history.unshift({
        time: new Date().toISOString(),
        preview: text.replace(/\s+/g, " ").slice(0, 80),
        risk: report.risk,
        level: report.level,
        source: report.verdict_source_label,
      });
      state.history = state.history.slice(0, CONFIG.maxHistory || 20);
      save(KEYS.history, state.history);
      renderHistory();
    }
  }

  // ---------- scan screen ----------
  const messageBox = $("message");
  messageBox.addEventListener("input", () => { $("counter").textContent = messageBox.value.length + " / 5000"; });
  $("scan-btn").addEventListener("click", () => scanText(messageBox.value));

  $("paste-btn").addEventListener("click", async () => {
    try {
      let text = "";
      if (Clipboard) text = (await Clipboard.read()).value || "";
      else if (navigator.clipboard && navigator.clipboard.readText) text = await navigator.clipboard.readText();
      if (!text) { toast("The clipboard is empty."); return; }
      messageBox.value = text.slice(0, 5000);
      messageBox.dispatchEvent(new Event("input"));
    } catch (e) {
      toast("Couldn't read the clipboard. Long-press the box and choose Paste instead.");
    }
  });

  // ---------- screenshot screen ----------
  $("image-input").addEventListener("change", (event) => {
    const file = event.target.files && event.target.files[0];
    event.target.value = ""; // allow choosing the same file again
    if (!file) return;
    if (!/^image\/(png|jpe?g|webp)$/.test(file.type)) { toast("Please choose a PNG or JPG screenshot."); return; }
    const preview = $("image-preview");
    if (preview.src.startsWith("blob:")) URL.revokeObjectURL(preview.src);
    preview.src = URL.createObjectURL(file);
    preview.classList.remove("hidden");
    scanImage(file, file.name); // analyse straight away
  });

  // ---------- results actions ----------
  $("again-btn").addEventListener("click", () => show("scan"));
  $("share-btn").addEventListener("click", async () => {
    const r = state.report;
    if (!r) return;
    const text = "ScamShield AI checked a message: " + r.risk + ". " +
      (r.warnings || []).slice(0, 3).map((w) => "• " + w.description).join(" ") +
      " Always verify through an official channel.";
    try {
      if (Share) await Share.share({ title: "ScamShield AI result", text: text });
      else if (navigator.share) await navigator.share({ title: "ScamShield AI result", text: text });
      else { await navigator.clipboard.writeText(text); toast("Result copied — paste it to share."); }
    } catch (e) { /* user cancelled */ }
  });

  // ---------- history ----------
  function renderHistory() {
    $("history-toggle").checked = state.keepHistory;
    const list = $("history-list");
    list.replaceChildren(...state.history.map((entry) => {
      const item = document.createElement("li");
      const risk = document.createElement("div");
      risk.className = "h-risk " + (entry.level || "");
      risk.textContent = entry.risk;
      const preview = document.createElement("div");
      preview.textContent = entry.preview;
      const meta = document.createElement("div");
      meta.className = "h-meta";
      meta.textContent = new Date(entry.time).toLocaleString() + (entry.source ? " · " + entry.source : "");
      item.append(risk, preview, meta);
      return item;
    }));
    $("history-empty").classList.toggle("hidden", state.history.length > 0);
    $("clear-history").classList.toggle("hidden", state.history.length === 0);
  }
  $("history-toggle").addEventListener("change", (e) => {
    state.keepHistory = e.target.checked;
    save(KEYS.keep, state.keepHistory);
    if (!state.keepHistory) { state.history = []; save(KEYS.history, []); }
    renderHistory();
  });
  $("clear-history").addEventListener("click", () => {
    state.history = [];
    save(KEYS.history, []);
    renderHistory();
  });

  // ---------- settings ----------
  function validUrl(value) {
    try {
      const url = new URL(value);
      if (url.protocol === "https:") return null;
      if (url.protocol === "http:" && ["localhost", "127.0.0.1", "10.0.2.2"].includes(url.hostname)) return null;
      return "Use an https:// address (http:// is only allowed for localhost testing).";
    } catch (e) { return "That is not a valid web address."; }
  }
  $("api-url").value = state.apiUrl;
  $("save-api").addEventListener("click", () => {
    const value = $("api-url").value.trim();
    const problem = validUrl(value);
    if (problem) { $("api-status").textContent = "⚠️ " + problem; return; }
    state.apiUrl = value;
    save(KEYS.api, value);
    $("api-status").textContent = "✅ Saved.";
  });
  $("test-api").addEventListener("click", async () => {
    $("api-status").textContent = "Testing…";
    try {
      const data = await callApi("/health", { method: "GET" });
      $("api-status").textContent = "✅ Connected · scanner " + data.version;
      $("about-version").textContent = "ScamShield AI · " + data.version + " scanner";
    } catch (e) { $("api-status").textContent = "⚠️ " + e.message; }
  });

  // ---------- sharing INTO ScamShield (Android share sheet) ----------
  function base64ToBlob(base64, type) {
    const bytes = atob(base64);
    const array = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) array[i] = bytes.charCodeAt(i);
    return new Blob([array], { type: type || "image/png" });
  }

  function handleShared(item) {
    if (!item || !item.type) return;
    if (Auth.enabled && !Auth.signedIn()) { Auth.pendingShare = item; return; } // scan after sign-in
    if (item.type === "text" && item.text) {
      messageBox.value = String(item.text).slice(0, 5000);
      messageBox.dispatchEvent(new Event("input"));
      show("scan");
      scanText(messageBox.value);
    } else if (item.type === "image" && item.base64) {
      const blob = base64ToBlob(item.base64, item.mimeType);
      const preview = $("image-preview");
      preview.src = URL.createObjectURL(blob);
      preview.classList.remove("hidden");
      show("shot");
      scanImage(blob, "shared-screenshot");
    } else if (item.error) {
      toast(item.error);
    }
  }

  if (ShareReceiver) {
    ShareReceiver.addListener("shareReceived", handleShared);
    ShareReceiver.getPending().then(handleShared).catch(() => {});
  }

  Auth.init();

  renderHistory();
})();
