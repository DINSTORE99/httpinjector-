"use strict";

const fileInput = document.getElementById("fileInput");
const uploadBox = document.getElementById("uploadBox");
const fileName = document.getElementById("fileName");
const decryptBtn = document.getElementById("decryptBtn");
const clearBtn = document.getElementById("clearBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const fileState = document.getElementById("fileState");

let selectedFile = null;
let busy = false;

fileInput?.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file) setFile(file);
});

["dragenter", "dragover"].forEach(type => uploadBox?.addEventListener(type, e => {
  e.preventDefault();
  e.stopPropagation();
  uploadBox.classList.add("dragging");
}));

["dragleave", "drop"].forEach(type => uploadBox?.addEventListener(type, e => {
  e.preventDefault();
  e.stopPropagation();
  uploadBox.classList.remove("dragging");
}));

uploadBox?.addEventListener("drop", e => {
  const file = e.dataTransfer?.files?.[0];
  if (file) setFile(file);
});

clearBtn?.addEventListener("click", resetAll);

decryptBtn?.addEventListener("click", decryptConfig);

function setFile(file) {
  if (!/\.ehi$/i.test(file.name || "")) {
    resetAll();
    showStatus("❌ Hanya file .EHI yang diperbolehkan", "error");
    return;
  }

  selectedFile = file;
  fileName.textContent = `📄 ${file.name}`;
  fileName.style.display = "block";
  decryptBtn.disabled = false;
  fileState.textContent = "READY";
  fileState.className = "waiting success";
  resultEl.innerHTML = "";
  showStatus("✅ File siap dibongkar", "success");
}

function resetAll() {
  selectedFile = null;
  busy = false;
  if (fileInput) fileInput.value = "";
  if (fileName) {
    fileName.textContent = "";
    fileName.style.display = "none";
  }
  if (decryptBtn) {
    decryptBtn.disabled = true;
    decryptBtn.textContent = "BONGKAR CONFIG";
  }
  if (fileState) {
    fileState.textContent = "WAITING";
    fileState.className = "waiting";
  }
  if (resultEl) resultEl.innerHTML = "";
  showStatus("Menunggu file...", "");
}

async function decryptConfig() {
  if (busy || !selectedFile) return;
  busy = true;
  decryptBtn.disabled = true;
  decryptBtn.textContent = "MEMPROSES...";
  fileState.textContent = "RUNNING";
  fileState.className = "waiting running";
  resultEl.innerHTML = "";
  showStatus("⏳ Sedang membongkar config...", "running");

  try {
    const formData = new FormData();
    formData.append("file", selectedFile, selectedFile.name);

    const response = await fetch("/api/decrypt", {
      method: "POST",
      body: formData,
      headers: { Accept: "application/json" }
    });

    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(text || `Server tidak mengembalikan JSON (${response.status})`);
    }

    if (!response.ok || data?.success === false) {
      throw new Error(data?.error || data?.message || "Gagal membongkar config");
    }

    renderResult(data);
    successSound();
    fileState.textContent = "SUCCESS";
    fileState.className = "waiting success";
    showStatus("✅ Config berhasil dibongkar", "success");

    setTimeout(() => resultEl.scrollIntoView({ behavior: "smooth", block: "start" }), 80);
  } catch (error) {
    console.error(error);
    fileState.textContent = "ERROR";
    fileState.className = "waiting error";
    showStatus(`❌ ${error?.message || "Terjadi kesalahan"}`, "error");
  } finally {
    busy = false;
    decryptBtn.disabled = !selectedFile;
    decryptBtn.textContent = "BONGKAR CONFIG";
  }
}

function getConfig(data) {
  if (data?.data && typeof data.data === "object") return data.data;
  if (data?.config && typeof data.config === "object") return data.config;
  if (typeof data?.result === "string") {
    try { return JSON.parse(data.result); } catch { return data.result; }
  }
  if (data?.result && typeof data.result === "object") return data.result;
  return data;
}

function renderResult(data) {
  const config = getConfig(data);
  if (typeof config === "string") {
    renderRawResult(config);
    return;
  }
  if (!config || typeof config !== "object") {
    renderRawResult(String(config ?? ""));
    return;
  }

  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-title">📋 HASIL CONFIG</div>
      <div id="configFields" class="config-fields"></div>
    </div>`;

  const fields = document.getElementById("configFields");
  const shown = new Set();

  // Urutan sengaja dikunci: SSH -> Payload -> Proxy -> SNI -> ...
  const ssh = getSSH(config);
  if (ssh) {
    fields.appendChild(createField("ssh", "🔐 SSH", ssh, true));
    ["host","hostname","server","sshHost","ssh_server","sshHostname","ssh_hostname",
     "port","sshPort","ssh_port","serverPort","server_port",
     "username","user","sshUsername","ssh_username","sshUser","ssh_user",
     "password","pass","sshPassword","ssh_password","sshPass","ssh_pass"].forEach(k => shown.add(k.toLowerCase()));
  }

  addOrderedField(config, fields, shown, ["payload","requestPayload","httpPayload","customPayload","payloadData"], "📦 Payload", true);
  addOrderedField(config, fields, shown, ["proxy","remoteProxy","remote_proxy","proxyHost","proxyServer","proxyAddress"], "🔀 Proxy");
  addOrderedField(config, fields, shown, ["sni","sniHost","sni_host","serverName","server_name"], "🎯 SNI");
  addOrderedField(config, fields, shown, ["port","serverPort","server_port"], "🔌 Port");
  addOrderedField(config, fields, shown, ["dns","dnsProfile","dns_profile","dnsResolver","dns_resolver"], "🌐 DNS");
  addOrderedField(config, fields, shown, ["localPort","local_port","listenPort","localListenPort"], "📍 Local Port");
  addOrderedField(config, fields, shown, ["defaultRoute","default_route"], "🛣️ Default Route");
  addOrderedField(config, fields, shown, ["tunnel","tunnelType","tunnel_type","mode","connectionMode"], "🚇 Tunnel");
  addOrderedField(config, fields, shown, ["lockAllConfig","configLock","config_lock","lockModes","lock_modes"], "🔒 Lock All Config");
  addOrderedField(config, fields, shown, ["expiryTime","expiry","expiryTimestamp","configExpiryTimestamp","config_expiry_timestamp"], "⏰ Expiry Time");
  addOrderedField(config, fields, shown, ["note","configMessage","message","remark","description"], "📝 Note");

  Object.entries(config).forEach(([key, value]) => {
    const lower = key.toLowerCase();
    if (shown.has(lower) || isInternalKey(key) || isEmptyValue(value)) return;
    fields.appendChild(createField(key, prettyName(key), value, lower.includes("payload")));
    shown.add(lower);
  });

  if (!fields.children.length) renderRawResult(data);
}

function addOrderedField(config, parent, shown, keys, title, payload = false) {
  for (const wanted of keys) {
    const actual = findKey(config, wanted);
    if (!actual || shown.has(actual.toLowerCase())) continue;
    const value = config[actual];
    if (isEmptyValue(value)) return;
    parent.appendChild(createField(actual, title, value, payload));
    shown.add(actual.toLowerCase());
    return;
  }
}

function createField(key, title, value, payload = false) {
  const item = document.createElement("div");
  item.className = "config-item";
  const text = formatValue(value);
  item.innerHTML = `
    <div class="config-header">
      <div class="config-name">${escapeHTML(title)}</div>
      <button type="button" class="config-copy">COPY</button>
    </div>
    <div class="config-value ${payload ? "payload" : ""}">${escapeHTML(text)}</div>`;

  item.querySelector(".config-copy")?.addEventListener("click", async e => {
    const ok = await copyText(text);
    e.currentTarget.textContent = ok ? "COPIED" : "FAILED";
    setTimeout(() => { e.currentTarget.textContent = "COPY"; }, 1200);
  });
  return item;
}

function getSSH(config) {
  const host = getValue(config, ["host","hostname","server","sshHost","ssh_server","sshHostname","ssh_hostname"]);
  const port = getValue(config, ["port","sshPort","ssh_port","serverPort","server_port"]);
  const username = getValue(config, ["username","user","sshUsername","ssh_username","sshUser","ssh_user"]);
  const password = getValue(config, ["password","pass","sshPassword","ssh_password","sshPass","ssh_pass"]);

  if ([host, port, username, password].every(isEmptyValue)) return null;

  const lines = [];
  if (!isEmptyValue(host)) lines.push(`Host     : ${formatValue(host)}`);
  if (!isEmptyValue(port)) lines.push(`Port     : ${formatValue(port)}`);
  if (!isEmptyValue(username)) lines.push(`Username : ${formatValue(username)}`);
  if (!isEmptyValue(password)) lines.push(`Password : ${formatValue(password)}`);
  return lines.join("\n");
}

function getValue(obj, keys) {
  for (const key of keys) {
    const actual = findKey(obj, key);
    if (actual && !isEmptyValue(obj[actual])) return obj[actual];
  }
  return null;
}

function findKey(obj, wanted) {
  if (!obj || typeof obj !== "object") return null;
  const target = String(wanted).toLowerCase();
  return Object.keys(obj).find(k => k.toLowerCase() === target) || null;
}

function isInternalKey(key) {
  const k = String(key).toLowerCase();
  const blocked = [
    "configaeskey","configidentifier","configsalt","configtimestamp",
    "configexpirytimestamp","lockmodeshash","confighwid",
    "configlockmobileoperatorid","v2rrawjson","overwriteserverdata",
    "masterkey","aeskey","cryptokey","ciphertext","nonce","argon",
    "argon2","aad","tag","rawjson","rawconfig"
  ];
  return blocked.some(word => k === word || k.includes(word));
}

function isEmptyValue(value) {
  if (value === null || value === undefined) return true;
  if (typeof value === "string") return value.trim() === "";
  if (Array.isArray(value)) return value.length === 0;
  return false;
}

function formatValue(value) {
  if (typeof value === "string") return value;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (Array.isArray(value)) return value.map(v => typeof v === "object" ? JSON.stringify(v, null, 2) : String(v)).join("\n");
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

function prettyName(key) {
  return String(key).replace(/([a-z])([A-Z])/g, "$1 $2").replace(/[_-]+/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

function renderRawResult(value) {
  const text = formatValue(value);
  resultEl.innerHTML = `
    <div class="result-card">
      <div class="result-title">📋 HASIL CONFIG</div>
      <div class="raw-title">RAW RESULT</div>
      <div class="config-item">
        <div class="config-header">
          <div class="config-name">📄 Result</div>
          <button type="button" class="config-copy" id="copyRaw">COPY</button>
        </div>
        <div class="config-value payload">${escapeHTML(text)}</div>
      </div>
    </div>`;
  document.getElementById("copyRaw")?.addEventListener("click", async e => {
    e.currentTarget.textContent = (await copyText(text)) ? "COPIED" : "FAILED";
    setTimeout(() => { e.currentTarget.textContent = "COPY"; }, 1200);
  });
}

function escapeHTML(value) {
  return String(value).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(String(text));
      return true;
    }
  } catch {}
  try {
    const ta = document.createElement("textarea");
    ta.value = String(text);
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

function showStatus(message, type = "") {
  if (!statusEl) return;
  statusEl.className = `console-line ${type}`.trim();
  statusEl.textContent = message;
}

function successSound() {
  try {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (!AudioContext) return;
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    osc.frequency.setValueAtTime(900, ctx.currentTime);
    gain.gain.setValueAtTime(0.001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.25);
    setTimeout(() => ctx.close().catch(() => {}), 500);
  } catch (e) {
    console.warn("Success sound tidak tersedia", e);
  }
}

showStatus("Menunggu file...", "");
