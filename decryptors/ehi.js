const crypto = require("crypto");
const argon2 = require("argon2");
const EHI = require("../config/ehi.keys");

function aesCbcDecrypt(key, iv, data) {
  const decipher = crypto.createDecipheriv(
    `aes-${key.length * 8}-cbc`,
    key,
    iv
  );

  decipher.setAutoPadding(true);

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

function customB64Decode(encoded) {
  let clean = String(encoded ?? "").replace(/\?/g, "");

  if (clean.length % 4) {
    clean += "=".repeat(4 - (clean.length % 4));
  }

  let translated = "";

  for (const ch of clean) {
    const i = EHI.CUSTOM_ALPHABET.indexOf(ch);
    translated += i >= 0 ? EHI.STD_ALPHABET[i] : ch;
  }

  return Buffer.from(translated, "base64");
}

// ============================================================
// XOR LAYER
// ============================================================

function decryptXorLayer(ciphertext, key) {
  if (!ciphertext || !String(ciphertext).trim()) {
    return ciphertext;
  }

  try {
    const reversed = String(ciphertext)
      .split("")
      .reverse()
      .join("");

    const hexBytes = customB64Decode(reversed);

    let hex = hexBytes.toString("ascii");

    if (hex.length % 2 !== 0) {
      hex = `0${hex}`;
    }

    const raw = Buffer.from(hex, "hex");

    const keyText = String(key ?? "");

    if (!keyText.length) {
      return null;
    }

    const out = [];

    for (let i = 0; i < raw.length; i++) {
      const value =
        raw[i] ^
        keyText.charCodeAt(i % keyText.length);

      if (value !== 0) {
        out.push(value);
      }
    }

    const plaintext = Buffer.from(out).toString("utf8");

    if (plaintext) {
      let bad = 0;

      for (const ch of plaintext) {
        const code = ch.charCodeAt(0);

        if (
          code < 32 &&
          code !== 9 &&
          code !== 10 &&
          code !== 13
        ) {
          bad++;
        }
      }

      if (bad / plaintext.length > 0.5) {
        return null;
      }
    }

    return plaintext;
  } catch {
    return null;
  }
}

// ============================================================
// XXTEA
// ============================================================

function xxteaDecrypt(data, key) {
  if (!data || !data.length) {
    return Buffer.alloc(0);
  }

  if (data.length % 4) {
    data = Buffer.concat([
      data,
      Buffer.alloc(4 - (data.length % 4))
    ]);
  }

  const n = data.length / 4;

  const kbuf = Buffer.concat([
    key,
    Buffer.alloc(16)
  ]).subarray(0, 16);

  const k = new Uint32Array(4);

  for (let i = 0; i < 4; i++) {
    k[i] = kbuf.readUInt32LE(i * 4);
  }

  const v = new Uint32Array(n);

  for (let i = 0; i < n; i++) {
    v[i] = data.readUInt32LE(i * 4);
  }

  const delta = 0x9e3779b9 >>> 0;

  let sum =
    Math.imul(
      6 + Math.floor(52 / n),
      delta
    ) >>> 0;

  let y = v[0] >>> 0;

  while (sum !== 0) {
    const e = (sum >>> 2) & 3;

    for (let p = n - 1; p > 0; p--) {
      const z = v[p - 1] >>> 0;

      const mx = (
        (
          (((z >>> 5) ^ (y << 2)) +
            ((y >>> 3) ^ (z << 4)))
        ) ^
        (
          (sum ^ y) +
          (k[(p & 3) ^ e] ^ z)
        )
      ) >>> 0;

      y = v[p] =
        (v[p] - mx) >>> 0;
    }

    const z = v[n - 1] >>> 0;

    const mx = (
      (
        (((z >>> 5) ^ (y << 2)) +
          ((y >>> 3) ^ (z << 4)))
      ) ^
      (
        (sum ^ y) +
        (k[e] ^ z)
      )
    ) >>> 0;

    y = v[0] =
      (v[0] - mx) >>> 0;

    sum =
      (sum - delta) >>> 0;
  }

  const decrypted =
    Buffer.alloc(n * 4);

  for (let i = 0; i < n; i++) {
    decrypted.writeUInt32LE(
      v[i] >>> 0,
      i * 4
    );
  }

  const length =
    v[n - 1] >>> 0;

  if (
    length > 0 &&
    length <= n * 4
  ) {
    return decrypted.subarray(
      0,
      length
    );
  }

  let end = decrypted.length;

  while (
    end > 0 &&
    decrypted[end - 1] === 0
  ) {
    end--;
  }

  return decrypted.subarray(0, end);
}

// ============================================================
// EHI CONTAINER
// ============================================================

function parseEhiBytes(fileBytes) {
  let p = 0;

  const readU16BE = () => {
    if (p + 2 > fileBytes.length) {
      throw new Error(
        "EHI header truncated"
      );
    }

    const n =
      fileBytes.readUInt16BE(p);

    p += 2;

    return n;
  };

  const readUtf = () => {
    const n = readU16BE();

    if (p + n > fileBytes.length) {
      throw new Error(
        "EHI UTF field truncated"
      );
    }

    const s =
      fileBytes
        .subarray(p, p + n)
        .toString("utf8");

    p += n;

    return s;
  };

  // ehi
  readUtf();

  if (p + 8 > fileBytes.length) {
    throw new Error(
      "EHI header truncated"
    );
  }

  p += 8;

  // version
  readUtf();

  if (p + 8 > fileBytes.length) {
    throw new Error(
      "EHI header truncated"
    );
  }

  p += 8;

  if (p + 4 > fileBytes.length) {
    throw new Error(
      "EHI payload length missing"
    );
  }

  const payloadLength =
    fileBytes.readUInt32BE(p);

  p += 4;

  if (p + 8 > fileBytes.length) {
    throw new Error(
      "EHI payload header truncated"
    );
  }

  p += 8;

  if (
    p + payloadLength >
    fileBytes.length
  ) {
    throw new Error(
      "EHI payload truncated"
    );
  }

  return fileBytes.subarray(
    p,
    p + payloadLength
  );
}

// ============================================================
// MASTER KEY
// ============================================================

function pyString(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "boolean") {
    return value ? "True" : "False";
  }

  if (
    typeof value === "number" ||
    typeof value === "bigint"
  ) {
    return String(value);
  }

  if (Array.isArray(value)) {
    return `[${value
      .map(v => pyString(v))
      .join(", ")}]`;
  }

  if (typeof value === "object") {
    return `{${Object.entries(value)
      .map(
        ([k, v]) =>
          `'${k}': ${pyString(v)}`
      )
      .join(", ")}}`;
  }

  return String(value);
}

function generateMasterKey(config) {
  // PENTING:
  // Jangan ubah urutan field ini.
  // Ini bagian yang digunakan untuk Argon2.

  const values = [
    config?.configAesKey ?? "",
    config?.configIdentifier ?? "",
    config?.configSalt ?? "",
    String(
      config?.configTimestamp ?? 0
    ),
    String(
      config?.configExpiryTimestamp ?? 0
    ),
    config?.lockModes ?? "",
    config?.lockModesHash ?? "",
    config?.configHwid ?? "",
    config?.configLockMobileOperatorId ?? ""
  ];

  const payload = values
    .filter(
      v =>
        v !== null &&
        v !== undefined &&
        pyString(v) !== ""
    )
    .map(pyString)
    .join("");

  return crypto
    .createHash("sha256")
    .update(payload, "utf8")
    .digest();
}

// ============================================================
// CONFIG MESSAGE / NOTE
// ============================================================

function decodeConfigMessage(value) {
  if (
    !value ||
    !String(value).trim()
  ) {
    return value;
  }

  try {
    let padded = String(value);

    while (padded.length % 4 !== 0) {
      padded += "=";
    }

    const raw =
      Buffer.from(
        padded,
        "base64"
      );

    /*
     * Referensi HTTP Injector:
     *
     * base64
     *   ↓
     * UTF-8 string
     *   ↓
     * Java UTF-16 code units
     *   ↓
     * XOR EHIMSG
     */

    const text =
      raw.toString("utf8");

    const key = "EHIMSG";

    let result = "";

    for (
      let i = 0;
      i < text.length;
      i++
    ) {
      const decoded =
        text.charCodeAt(i) ^
        key.charCodeAt(
          i % key.length
        );

      result += String.fromCharCode(
        decoded & 0xffff
      );
    }

    return result;
  } catch {
    return value;
  }
}

// ============================================================
// READABILITY
// ============================================================

function looksReadable(value) {
  if (
    typeof value !== "string" ||
    !value.length
  ) {
    return false;
  }

  let bad = 0;

  for (const ch of value) {
    const code =
      ch.charCodeAt(0);

    if (
      code < 32 &&
      code !== 9 &&
      code !== 10 &&
      code !== 13
    ) {
      bad++;
    }

    if (code === 0xfffd) {
      bad++;
    }
  }

  return (
    bad / value.length <= 0.15
  );
}

// ============================================================
// POSSIBLE NOTE
// ============================================================

function decodePossibleNote(
  value,
  saltKey
) {
  // Pertama coba EHIMSG
  const javaDecoded =
    decodeConfigMessage(value);

  if (
    javaDecoded !== value &&
    looksReadable(javaDecoded)
  ) {
    return javaDecoded;
  }

  // Kemudian coba XOR layer normal
  const xorDecoded =
    decryptXorLayer(
      value,
      saltKey
    );

  if (
    xorDecoded !== null &&
    looksReadable(xorDecoded)
  ) {
    return xorDecoded;
  }

  // Kalau gagal, jangan rusak data asli
  return value;
}

// ============================================================
// DECODE INNER FIELDS
// ============================================================

function decodeInnerFields(
  parsedJson,
  saltKey
) {
  if (Array.isArray(parsedJson)) {
    return parsedJson.map(
      v =>
        decodeInnerFields(
          v,
          saltKey
        )
    );
  }

  if (
    !parsedJson ||
    typeof parsedJson !== "object"
  ) {
    return parsedJson;
  }

  const cleaned = {};

  for (
    const [key, value]
    of Object.entries(parsedJson)
  ) {
    const lower =
      key.toLowerCase();

    // Object / array
    if (
      value &&
      typeof value === "object"
    ) {
      cleaned[key] =
        decodeInnerFields(
          value,
          saltKey
        );

      continue;
    }

    // String
    if (
      typeof value === "string" &&
      value.trim()
    ) {
      // configMessage
      if (
        lower ===
        "configmessage"
      ) {
        cleaned[key] =
          decodeConfigMessage(
            value
          );

        continue;
      }

      // Note aliases
      if (
        [
          "note",
          "message",
          "remark",
          "description"
        ].includes(lower)
      ) {
        cleaned[key] =
          decodePossibleNote(
            value,
            saltKey
          );

        continue;
      }

      // Field normal
      const decrypted =
        decryptXorLayer(
          value,
          saltKey
        );

      cleaned[key] =
        decrypted !== null
          ? decrypted
          : value;

      continue;
    }

    cleaned[key] = value;
  }

  // Kalau EHI menyimpan configMessage,
  // frontend bisa langsung menampilkan sebagai Note.
  if (
    typeof cleaned.configMessage ===
      "string" &&
    !cleaned.note
  ) {
    cleaned.note =
      cleaned.configMessage;
  }

  return cleaned;
}

// ============================================================
// NESTED JSON
// ============================================================

function parseNestedJsonFields(obj) {
  if (
    !obj ||
    typeof obj !== "object"
  ) {
    return obj;
  }

  for (
    const key of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {
    if (
      typeof obj[key] !== "string"
    ) {
      continue;
    }

    try {
      const raw = obj[key];

      const start =
        raw.indexOf("{");

      const end =
        raw.lastIndexOf("}");

      if (
        start < 0 ||
        end < start
      ) {
        continue;
      }

      const parsed =
        JSON.parse(
          raw.slice(
            start,
            end + 1
          )
        );

      obj[key] =
        typeof parsed === "string"
          ? JSON.parse(parsed)
          : parsed;
    } catch (err) {
      obj[
        `${key}_PARSING_ERROR`
      ] =
        err?.message ||
        String(err);
    }
  }

  return obj;
}

// ============================================================
// XCHACHA20-POLY1305
// ============================================================

async function decryptXChaCha(
  key,
  nonce,
  ciphertext,
  tag,
  aad
) {
  const {
    xchacha20poly1305
  } = await import(
    "@noble/ciphers/chacha.js"
  );

  const cipher =
    xchacha20poly1305(
      new Uint8Array(key),
      new Uint8Array(nonce),
      new Uint8Array(aad)
    );

  return Buffer.from(
    cipher.decrypt(
      new Uint8Array(
        Buffer.concat([
          ciphertext,
          tag
        ])
      )
    )
  );
}

// ============================================================
// MAIN EHI DECRYPT
// ============================================================

async function ehiDecrypt(buffer) {
  if (
    !Buffer.isBuffer(buffer) ||
    !buffer.length
  ) {
    throw new Error(
      "File EHI kosong"
    );
  }

  // ==========================================================
  // 1. CONTAINER
  // ==========================================================

  const payload =
    parseEhiBytes(buffer);

  if (!payload.length) {
    throw new Error(
      "Payload EHI kosong"
    );
  }

  // ==========================================================
  // 2. LAYER 1 + LAYER 2 + XXTEA
  // ==========================================================

  let config = null;
  let matchedIv = null;

  const allIvs = [
    ...EHI.BYPASS_IVS,
    ...EHI.STANDARD_IVS
  ];

  for (const iv of allIvs) {
    try {
      const layer1 =
        aesCbcDecrypt(
          EHI.L1_KEY,
          iv,
          payload
        );

      const layer1Text =
        layer1.toString("utf8");

      const parts =
        layer1Text.split(":");

      if (parts.length < 3) {
        continue;
      }

      const iv2 =
        Buffer.from(
          parts[0],
          "base64"
        );

      const cipher2 =
        Buffer.from(
          parts[2],
          "base64"
        );

      if (
        iv2.length !== 16 ||
        !cipher2.length
      ) {
        continue;
      }

      const layer2 =
        aesCbcDecrypt(
          EHI.L2_KEY_STATIC,
          iv2,
          cipher2
        );

      const raw =
        xxteaDecrypt(
          layer2,
          EHI.EOO_MASTER_KEY
        );

      const start =
        raw.indexOf(0x7b);

      if (start < 0) {
        continue;
      }

      const candidate =
        JSON.parse(
          raw
            .subarray(start)
            .toString("utf8")
        );

      if (
        candidate &&
        typeof candidate ===
          "object" &&
        !Array.isArray(candidate)
      ) {
        config = candidate;
        matchedIv = iv;
        break;
      }
    } catch {
      continue;
    }
  }

  if (!config) {
    throw new Error(
      "Tidak dapat membuka layer EHI. IV/key tidak cocok."
    );
  }

  // ==========================================================
  // 3. BYPASS / STANDARD
  // ==========================================================

  const targetSalt =
    config.configSalt ||
    "EVZJNI";

  let parsedFinal;

  const isBypass =
    EHI.BYPASS_IVS.some(
      iv =>
        iv.equals(matchedIv)
    );

  // ==========================================================
  // BYPASS
  // ==========================================================

  if (isBypass) {
    parsedFinal = config;
  }

  // ==========================================================
  // STANDARD
  // ==========================================================

  else {
    const targetData =
      config.configData;

    if (!targetData) {
      throw new Error(
        "configData EHI tidak ditemukan"
      );
    }

    const decodedLayer =
      decryptXorLayer(
        targetData,
        targetSalt
      );

    if (!decodedLayer) {
      throw new Error(
        "configData EHI gagal didekripsi"
      );
    }

    let rawPayload;

    try {
      rawPayload =
        Buffer.from(
          decodedLayer,
          "base64"
        );
    } catch {
      throw new Error(
        "configData EHI bukan base64 yang valid"
      );
    }

    if (rawPayload.length <= 50) {
      throw new Error(
        "Payload EHI terlalu pendek"
      );
    }

    // ========================================================
    // RAW PAYLOAD HEADER
    // ========================================================

    const timeCost =
      rawPayload.readUInt32LE(1);

    const memoryCost =
      rawPayload.readUInt32LE(5);

    const parallelism =
      rawPayload[9];

    const salt =
      rawPayload.subarray(
        0x0a,
        0x1a
      );

    const nonce =
      rawPayload.subarray(
        0x1a,
        0x32
      );

    const aad =
      rawPayload.subarray(
        0,
        0x1a
      );

    const ciphertext =
      rawPayload.subarray(
        0x32,
        rawPayload.length - 16
      );

    const tag =
      rawPayload.subarray(
        rawPayload.length - 16
      );

    if (
      !timeCost ||
      !memoryCost ||
      !parallelism
    ) {
      throw new Error(
        "Parameter Argon2 EHI tidak valid"
      );
    }

    // ========================================================
    // ARGON2ID
    // ========================================================

    const masterKey =
      generateMasterKey(
        config
      );

    const argonKey =
      await argon2.hash(
        masterKey,
        {
          type: argon2.argon2id,
          timeCost,
          memoryCost,
          parallelism,
          hashLength: 32,
          salt,
          raw: true
        }
      );

    // ========================================================
    // XCHACHA20 POLY1305
    // ========================================================

    const decrypted =
      await decryptXChaCha(
        argonKey,
        nonce,
        ciphertext,
        tag,
        aad
      );

    // ========================================================
    // JSON
    // ========================================================

    parsedFinal =
      JSON.parse(
        decrypted.toString("utf8")
      );
  }

  // ==========================================================
  // 4. DECODE INNER FIELDS
  //
  // NOTE TIDAK DIPROSES SEBELUM XCHACHA.
  // Jadi tidak mengganggu proses authentication tag.
  // ==========================================================

  const cleaned =
    decodeInnerFields(
      parsedFinal,
      targetSalt
    );

  // ==========================================================
  // 5. NESTED JSON
  // ==========================================================

  const finalConfig =
    parseNestedJsonFields(
      cleaned
    );

  // ==========================================================
  // 6. RESULT
  // ==========================================================

  return {
    success: true,

    format: "ehi",

    result:
      JSON.stringify(
        finalConfig,
        null,
        4
      ),

    data: finalConfig
  };
}

module.exports = ehiDecrypt;
