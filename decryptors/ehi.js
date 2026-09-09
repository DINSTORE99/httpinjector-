const crypto = require("crypto");
const argon2 = require("argon2");
const EHI = require("../config/ehi.keys");

function xorBytes(a, b) {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i % b.length];
  return out;
}

function aesCbcDecrypt(key, iv, data) {
  const decipher = crypto.createDecipheriv(`aes-${key.length * 8}-cbc`, key, iv);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

function customBase64Decode(value) {
  let s = Buffer.isBuffer(value) ? value.toString("utf8") : String(value);
  let translated = "";
  for (const ch of s) {
    const i = EHI.CUSTOM_ALPHABET.indexOf(ch);
    translated += i === -1 ? ch : EHI.STD_ALPHABET[i];
  }
  translated = translated.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  while (translated.length % 4) translated += "=";
  return Buffer.from(translated, "base64");
}

function toUint32Array(buffer) {
  const n = Math.ceil(buffer.length / 4);
  const out = new Uint32Array(n);
  for (let i = 0; i < n; i++) {
    const p = i * 4;
    out[i] =
      (buffer[p] || 0) |
      ((buffer[p + 1] || 0) << 8) |
      ((buffer[p + 2] || 0) << 16) |
      ((buffer[p + 3] || 0) << 24);
  }
  return out;
}

function fromUint32Array(v, length) {
  const out = Buffer.alloc(v.length * 4);
  for (let i = 0; i < v.length; i++) {
    out[i * 4] = v[i] & 255;
    out[i * 4 + 1] = (v[i] >>> 8) & 255;
    out[i * 4 + 2] = (v[i] >>> 16) & 255;
    out[i * 4 + 3] = (v[i] >>> 24) & 255;
  }
  return out.subarray(0, length);
}

function xxteaDecrypt(data, key) {
  if (!data || !data.length) return Buffer.alloc(0);

  // Exact XXTEA layout used by the reference EHI implementation.
  const rem = data.length % 4;
  if (rem) data = Buffer.concat([data, Buffer.alloc(4 - rem)]);

  const n = data.length / 4;
  const v = new Uint32Array(n);
  for (let i = 0; i < n; i++) {
    v[i] = data.readUInt32LE(i * 4);
  }

  const kk = Buffer.concat([key, Buffer.alloc(16)]).subarray(0, 16);
  const k = new Uint32Array(4);
  for (let i = 0; i < 4; i++) k[i] = kk.readUInt32LE(i * 4);

  const delta = 0x9e3779b9 >>> 0;
  let sum = Math.imul(6 + Math.floor(52 / n), delta) >>> 0;
  let y = v[0] >>> 0;

  while (sum !== 0) {
    const e = (sum >>> 2) & 3;

    for (let p = n - 1; p > 0; p--) {
      const z = v[p - 1] >>> 0;
      const mx = (
        ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^
          ((sum ^ y) + (k[(p & 3) ^ e] ^ z)))
      ) >>> 0;

      y = v[p] = (v[p] - mx) >>> 0;
    }

    const z = v[n - 1] >>> 0;
    const mx = (
      ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^
        ((sum ^ y) + (k[e] ^ z)))
    ) >>> 0;

    y = v[0] = (v[0] - mx) >>> 0;
    sum = (sum - delta) >>> 0;
  }

  const decrypted = Buffer.alloc(n * 4);
  for (let i = 0; i < n; i++) {
    decrypted.writeUInt32LE(v[i] >>> 0, i * 4);
  }

  // XXTEA payload stores the original plaintext length in the final word.
  const length = v[n - 1] >>> 0;
  if (length > 0 && length <= n * 4) {
    return decrypted.subarray(0, length);
  }

  return decrypted;
}

function decodeConfigMessage(buffer) {
  const text = buffer.toString("utf8");
  const start = text.indexOf("{");
  if (start < 0) throw new Error("JSON EHI tidak ditemukan setelah XXTEA");
  return JSON.parse(text.substring(start));
}

function extractEhiPayload(buffer) {
  // Common HTTP Injector EHI container:
  // 00 03 'ehi' ... length at 0x1c, payload starts at 0x28.
  if (buffer.length >= 40 && buffer.subarray(1, 4).toString("ascii") === "ehi") {
    const declared = buffer.readUInt32BE(0x1c);
    const start = 0x28;
    if (declared > 0 && start + declared <= buffer.length) {
      return buffer.subarray(start, start + declared);
    }
    if (start < buffer.length) return buffer.subarray(start);
  }
  return buffer;
}

function generateMasterKey(config) {
  const payload = [
    config?.configAesKey ?? "",
    config?.configIdentifier ?? "",
    config?.configSalt ?? "",
    String(config?.configTimestamp ?? 0),
    String(config?.configExpiryTimestamp ?? 0),
    config?.lockModes ?? "",
    config?.lockModesHash ?? "",
    config?.configHwid ?? "",
    config?.configLockMobileOperatorId ?? ""
  ].filter(Boolean).join("");
  return crypto.createHash("sha256").update(payload, "utf8").digest();
}

function decryptConfigData(ciphertextStr, key) {
  let s = String(ciphertextStr || "");
  if (!s.trim()) return s;
  let reversed = s.split("").reverse().join("");
  let clean = reversed.replace(/\?/g, "");
  const rem = clean.length % 4;
  if (rem) clean += "=".repeat(4 - rem);
  let translated = "";
  for (const ch of clean) {
    const i = EHI.CUSTOM_ALPHABET.indexOf(ch);
    translated += i === -1 ? ch : EHI.STD_ALPHABET[i];
  }
  const hexString = Buffer.from(translated, "base64").toString("ascii");
  const evenHex = hexString.length % 2 ? "0" + hexString : hexString;
  const raw = Buffer.from(evenHex, "hex");
  const keyBuf = Buffer.from(String(key), "utf8");
  const out = [];
  for (let i = 0; i < raw.length; i++) {
    const x = raw[i] ^ keyBuf[i % keyBuf.length];
    if (x !== 0) out.push(x);
  }
  return Buffer.from(out).toString("utf8");
}

async function decryptXChaCha(key, nonce, ciphertext, tag, aad) {
  if (key.length !== 32) throw new Error(`XChaCha key harus 32 byte, dapat ${key.length}`);
  if (nonce.length !== 24) throw new Error(`XChaCha nonce harus 24 byte, dapat ${nonce.length}`);
  const { xchacha20poly1305 } = await import("@noble/ciphers/chacha.js");
  const cipher = xchacha20poly1305(new Uint8Array(key), new Uint8Array(nonce), aad ? new Uint8Array(aad) : undefined);
  return Buffer.from(cipher.decrypt(new Uint8Array(Buffer.concat([ciphertext, tag]))));
}

function decodeConfigMessageValue(ciphertextStr) {
  if (!ciphertextStr || !String(ciphertextStr).trim()) return ciphertextStr;
  try {
    let padded = String(ciphertextStr);
    while (padded.length % 4) padded += "=";
    const raw = Buffer.from(padded, "base64");
    const utf16 = Buffer.from(raw.toString("utf8"), "utf8").toString("utf16le");
    const chars = [];
    const key = "EHIMSG";
    for (let i = 0; i < utf16.length; i++) {
      chars.push(String.fromCharCode(utf16.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
    }
    return chars.join("");
  } catch {
    return ciphertextStr;
  }
}

function decodeInnerFields(obj, saltKey) {
  if (!obj || typeof obj !== "object") return obj;
  const result = Array.isArray(obj) ? [] : {};

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === "string" && value.trim()) {
      if (key === "configMessage") {
        result[key] = decodeConfigMessageValue(value);
      } else {
        const decoded = decryptConfigData(value, saltKey);
        result[key] = decoded == null ? value : decoded;
      }
    } else {
      result[key] = value && typeof value === "object"
        ? decodeInnerFields(value, saltKey)
        : value;
    }
  }

  return result;
}

function parseNestedJSON(config) {
  for (const key of ["v2rRawJson", "overwriteServerData"]) {
    if (typeof config[key] === "string") {
      try { config[key] = JSON.parse(config[key]); } catch {}
    }
  }
  return config;
}

async function ehiDecrypt(buffer) {
  if (!Buffer.isBuffer(buffer) || !buffer.length) throw new Error("File EHI kosong");

  const payload = extractEhiPayload(buffer);
  const allIVs = [
    ...EHI.BYPASS_IVS.map(iv => ({ iv, bypass: true })),
    ...EHI.STANDARD_IVS.map(iv => ({ iv, bypass: false }))
  ];

  let parsedConfig = null;
  let matchedBypass = false;

  for (const item of allIVs) {
    try {
      const layer1 = aesCbcDecrypt(EHI.L1_KEY, item.iv, payload);
      const message = layer1.toString("utf8");
      const parts = message.split(":");
      if (parts.length < 3) continue;

      const iv2 = Buffer.from(parts[0], "base64");
      const ciphertext2 = Buffer.from(parts[2], "base64");
      if (iv2.length !== 16 || !ciphertext2.length) continue;

      const layer2 = aesCbcDecrypt(EHI.L2_KEY_STATIC, iv2, ciphertext2);
      const xxtea = xxteaDecrypt(layer2, EHI.EOO_MASTER_KEY);
      const config = decodeConfigMessage(xxtea);

      if (config && typeof config === "object") {
        parsedConfig = config;
        matchedBypass = item.bypass;
        break;
      }
    } catch {}
  }

  if (!parsedConfig) {
    throw new Error("Tidak dapat membuka layer EHI. IV/key tidak cocok.");
  }

  let finalConfig = parsedConfig;

  if (!matchedBypass) {
    if (!parsedConfig.configData) throw new Error("configData tidak ditemukan");

    const encoded = decryptConfigData(
      parsedConfig.configData,
      parsedConfig.configSalt || "EVZJNI"
    );

    const cleanEncoded = String(encoded).replace(/\s+/g, "");
    const raw = Buffer.from(cleanEncoded, "base64");
    if (raw.length < 0x32 + 16) throw new Error("Payload EHI terlalu pendek");

    const salt = raw.subarray(0x0a, 0x1a);
    const timeCost = raw.readUInt32LE(1);
    const memoryCost = raw.readUInt32LE(5);
    const parallelism = raw[9];
    const nonce = raw.subarray(0x1a, 0x32);
    const aad = raw.subarray(0, 0x1a);
    const ciphertext = raw.subarray(0x32, raw.length - 16);
    const tag = raw.subarray(raw.length - 16);

    const password = generateMasterKey(parsedConfig);
    const key = await argon2.hash(password, {
      type: argon2.argon2id,
      timeCost,
      memoryCost,
      parallelism,
      hashLength: 32,
      salt,
      raw: true
    });

    const decrypted = await decryptXChaCha(key, nonce, ciphertext, tag, aad);
    finalConfig = JSON.parse(decrypted.toString("utf8"));
  }

  finalConfig = parseNestedJSON(decodeInnerFields(finalConfig, parsedConfig.configSalt || "EVZJNI"));

  return {
    success: true,
    format: "ehi",
    result: JSON.stringify(finalConfig, null, 4),
    data: finalConfig
  };
}

module.exports = ehiDecrypt;
