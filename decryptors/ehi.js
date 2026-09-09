const crypto = require("crypto");
const argon2 = require("argon2");
const EHI = require("../config/ehi.keys");

// ==================================================
// XOR
// ==================================================

function xorBytes(a, b) {
  const out = Buffer.alloc(a.length);

  for (let i = 0; i < a.length; i++) {
    out[i] = a[i] ^ b[i % b.length];
  }

  return out;
}

// ==================================================
// AES CBC
// ==================================================

function aesCbcDecrypt(key, iv, data) {
  if (!Buffer.isBuffer(key)) key = Buffer.from(key);
  if (!Buffer.isBuffer(iv)) iv = Buffer.from(iv);
  if (!Buffer.isBuffer(data)) data = Buffer.from(data);

  if (iv.length !== 16) {
    throw new Error(`IV AES harus 16 byte, dapat ${iv.length}`);
  }

  const decipher = crypto.createDecipheriv(
    `aes-${key.length * 8}-cbc`,
    key,
    iv
  );

  return Buffer.concat([
    decipher.update(data),
    decipher.final()
  ]);
}

// ==================================================
// CUSTOM BASE64
// ==================================================

function customBase64Decode(value) {
  let s = Buffer.isBuffer(value)
    ? value.toString("utf8")
    : String(value);

  let translated = "";

  for (const ch of s) {
    const i = EHI.CUSTOM_ALPHABET.indexOf(ch);

    translated +=
      i === -1
        ? ch
        : EHI.STD_ALPHABET[i];
  }

  translated = translated
    .replace(/\s+/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (translated.length % 4) {
    translated += "=";
  }

  return Buffer.from(translated, "base64");
}

// ==================================================
// UINT32
// ==================================================

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

// ==================================================
// XXTEA
// ==================================================

function xxteaDecrypt(data, key) {
  if (!data || !data.length) {
    return Buffer.alloc(0);
  }

  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data);
  }

  const rem = data.length % 4;

  if (rem) {
    data = Buffer.concat([
      data,
      Buffer.alloc(4 - rem)
    ]);
  }

  const n = data.length / 4;

  if (n < 2) {
    return data;
  }

  const v = new Uint32Array(n);

  for (let i = 0; i < n; i++) {
    v[i] = data.readUInt32LE(i * 4);
  }

  const kk = Buffer.concat([
    key,
    Buffer.alloc(16)
  ]).subarray(0, 16);

  const k = new Uint32Array(4);

  for (let i = 0; i < 4; i++) {
    k[i] = kk.readUInt32LE(i * 4);
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
          (
            ((z >>> 5) ^ (y << 2)) +
            ((y >>> 3) ^ (z << 4))
          ) ^
          (
            (sum ^ y) +
            (k[(p & 3) ^ e] ^ z)
          )
        )
      ) >>> 0;

      y = v[p] =
        (v[p] - mx) >>> 0;
    }

    const z = v[n - 1] >>> 0;

    const mx = (
      (
        (
          ((z >>> 5) ^ (y << 2)) +
          ((y >>> 3) ^ (z << 4))
        ) ^
        (
          (sum ^ y) +
          (k[e] ^ z)
        )
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

  /*
   * EHI menyimpan panjang plaintext
   * pada word terakhir.
   */

  const originalLength =
    v[n - 1] >>> 0;

  if (
    originalLength > 0 &&
    originalLength <= decrypted.length
  ) {
    return decrypted.subarray(
      0,
      originalLength
    );
  }

  // fallback: buang null byte di akhir
  let end = decrypted.length;

  while (
    end > 0 &&
    decrypted[end - 1] === 0
  ) {
    end--;
  }

  return decrypted.subarray(
    0,
    end
  );
}

// ==================================================
// JSON
// ==================================================

function decodeConfigMessage(buffer) {
  const text =
    buffer.toString("utf8");

  const start =
    text.indexOf("{");

  if (start < 0) {
    throw new Error(
      "JSON EHI tidak ditemukan setelah XXTEA"
    );
  }

  return JSON.parse(
    text.substring(start)
  );
}

// ==================================================
// EHI CONTAINER PARSER
// ==================================================

function extractEhiPayload(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }

  let offset = 0;

  function readUTF() {
    if (offset + 2 > buffer.length) {
      throw new Error(
        "Header EHI tidak lengkap"
      );
    }

    const length =
      buffer.readUInt16BE(offset);

    offset += 2;

    if (
      offset + length > buffer.length
    ) {
      throw new Error(
        "Panjang UTF EHI tidak valid"
      );
    }

    const value =
      buffer
        .subarray(
          offset,
          offset + length
        )
        .toString("utf8");

    offset += length;

    return value;
  }

  // UTF #1
  readUTF();

  // 8 byte
  if (offset + 8 > buffer.length) {
    throw new Error(
      "Header EHI tidak valid"
    );
  }

  offset += 8;

  // UTF #2
  readUTF();

  // 8 byte
  if (offset + 8 > buffer.length) {
    throw new Error(
      "Header EHI tidak valid"
    );
  }

  offset += 8;

  // Payload length
  if (offset + 4 > buffer.length) {
    throw new Error(
      "Panjang payload EHI tidak ditemukan"
    );
  }

  const payloadLength =
    buffer.readUInt32BE(offset);

  offset += 4;

  // 8 byte
  if (offset + 8 > buffer.length) {
    throw new Error(
      "Header payload EHI tidak lengkap"
    );
  }

  offset += 8;

  if (
    payloadLength <= 0 ||
    offset + payloadLength > buffer.length
  ) {
    throw new Error(
      `Panjang payload EHI tidak valid: ${payloadLength}`
    );
  }

  return buffer.subarray(
    offset,
    offset + payloadLength
  );
}

// ==================================================
// PYTHON STRING HELPER
// ==================================================

function pyString(value) {
  if (value === null) {
    return "None";
  }

  if (value === undefined) {
    return "None";
  }

  if (typeof value === "boolean") {
    return value ? "True" : "False";
  }

  if (typeof value === "number") {
    return String(value);
  }

  if (typeof value === "string") {
    return value;
  }

  if (Array.isArray(value)) {
    return (
      "[" +
      value
        .map(v => pyString(v))
        .join(", ") +
      "]"
    );
  }

  if (
    typeof value === "object"
  ) {
    return (
      "{" +
      Object.entries(value)
        .map(
          ([k, v]) =>
            `'${k}': ${pyString(v)}`
        )
        .join(", ") +
      "}"
    );
  }

  return String(value);
}

// ==================================================
// MASTER KEY
// ==================================================

function generateMasterKey(config) {
  const values = [
    config?.configAesKey,
    config?.configIdentifier,
    config?.configSalt,
    config?.configTimestamp,
    config?.configExpiryTimestamp,
    config?.lockModes,
    config?.lockModesHash,
    config?.configHwid,
    config?.configLockMobileOperatorId
  ];

  const payload =
    values
      .filter(
        value =>
          value !== undefined &&
          value !== null &&
          value !== ""
      )
      .map(pyString)
      .join("");

  return crypto
    .createHash("sha256")
    .update(
      payload,
      "utf8"
    )
    .digest();
}

// ==================================================
// CONFIG DATA XOR LAYER
// ==================================================

function decryptConfigData(
  ciphertextStr,
  key
) {
  let s =
    String(ciphertextStr || "");

  if (!s.trim()) {
    return s;
  }

  // Reverse
  const reversed =
    s
      .split("")
      .reverse()
      .join("");

  // Remove ?
  let clean =
    reversed.replace(/\?/g, "");

  while (
    clean.length % 4
  ) {
    clean += "=";
  }

  let translated = "";

  for (const ch of clean) {
    const i =
      EHI.CUSTOM_ALPHABET.indexOf(ch);

    translated +=
      i === -1
        ? ch
        : EHI.STD_ALPHABET[i];
  }

  const hexString =
    Buffer
      .from(
        translated,
        "base64"
      )
      .toString("ascii");

  const evenHex =
    hexString.length % 2
      ? "0" + hexString
      : hexString;

  const raw =
    Buffer.from(
      evenHex,
      "hex"
    );

  const keyBuf =
    Buffer.from(
      String(key),
      "utf8"
    );

  if (!keyBuf.length) {
    return s;
  }

  const out = [];

  for (
    let i = 0;
    i < raw.length;
    i++
  ) {
    const x =
      raw[i] ^
      keyBuf[
        i % keyBuf.length
      ];

    /*
     * Sama dengan reference Python:
     * byte bernilai 0 setelah XOR
     * dibuang.
     */
    if (x !== 0) {
      out.push(x);
    }
  }

  return Buffer
    .from(out)
    .toString("utf8");
}

// ==================================================
// CONFIG MESSAGE
// ==================================================

function decodeConfigMessageValue(
  ciphertextStr
) {
  if (
    !ciphertextStr ||
    !String(ciphertextStr).trim()
  ) {
    return ciphertextStr;
  }

  try {
    let padded =
      String(ciphertextStr);

    while (
      padded.length % 4 !== 0
    ) {
      padded += "=";
    }

    /*
     * Reference EHI:
     *
     * Base64 decode
     * -> UTF-8
     * -> Java UTF-16 code units
     * -> XOR "EHIMSG"
     */

    const raw =
      Buffer.from(
        padded,
        "base64"
      );

    const utf8Text =
      raw.toString("utf8");

    const key =
      "EHIMSG";

    const chars = [];

    /*
     * charCodeAt() di JavaScript
     * bekerja menggunakan UTF-16 code unit,
     * sama dengan Java char.
     */
    for (
      let i = 0;
      i < utf8Text.length;
      i++
    ) {
      const javaChar =
        utf8Text.charCodeAt(i);

      const keyChar =
        key.charCodeAt(
          i % key.length
        );

      const decoded =
        javaChar ^ keyChar;

      chars.push(
        String.fromCharCode(
          decoded & 0xffff
        )
      );
    }

    return chars.join("");

  } catch {
    return ciphertextStr;
  }
}

// ==================================================
// READABLE CHECK
// ==================================================

function looksReadable(value) {
  if (
    typeof value !== "string" ||
    !value.length
  ) {
    return false;
  }

  let bad = 0;

  for (
    const ch of value
  ) {
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
  }

  return (
    bad / value.length <
    0.25
  );
}

// ==================================================
// POSSIBLE NOTE
// ==================================================

function decodePossibleNote(
  value
) {
  if (
    typeof value !== "string" ||
    !value.trim()
  ) {
    return value;
  }

  try {
    const decoded =
      decodeConfigMessageValue(
        value
      );

    if (
      decoded &&
      decoded !== value &&
      looksReadable(decoded)
    ) {
      return decoded;
    }
  } catch {}

  return value;
}

// ==================================================
// INNER FIELDS
// ==================================================

function decodeInnerFields(
  obj,
  saltKey
) {
  if (
    !obj ||
    typeof obj !== "object"
  ) {
    return obj;
  }

  const result =
    Array.isArray(obj)
      ? []
      : {};

  for (
    const [key, value]
    of Object.entries(obj)
  ) {

    // ================================================
    // STRING
    // ================================================

    if (
      typeof value === "string" &&
      value.trim()
    ) {

      // --------------------------------------------
      // configMessage
      // --------------------------------------------

      if (
        key === "configMessage"
      ) {
        result[key] =
          decodeConfigMessageValue(
            value
          );

        continue;
      }

      // --------------------------------------------
      // note / message / remark / description
      // --------------------------------------------

      if (
        [
          "note",
          "message",
          "remark",
          "description"
        ].includes(
          key.toLowerCase()
        )
      ) {
        result[key] =
          decodePossibleNote(
            value
          );

        continue;
      }

      // --------------------------------------------
      // Field normal
      // --------------------------------------------

      try {
        const decoded =
          decryptConfigData(
            value,
            saltKey
          );

        result[key] =
          decoded == null
            ? value
            : decoded;

      } catch {
        result[key] = value;
      }

      continue;
    }

    // ================================================
    // OBJECT / ARRAY
    // ================================================

    if (
      value &&
      typeof value === "object"
    ) {
      result[key] =
        decodeInnerFields(
          value,
          saltKey
        );

      continue;
    }

    // ================================================
    // OTHER
    // ================================================

    result[key] = value;
  }

  /*
   * Kalau EHI hanya memiliki configMessage,
   * buat alias note supaya frontend
   * tetap bisa menampilkan bagian Note.
   */
  if (
    typeof result.configMessage === "string" &&
    !Object.prototype.hasOwnProperty.call(
      result,
      "note"
    )
  ) {
    result.note =
      result.configMessage;
  }

  return result;
}

// ==================================================
// NESTED JSON
// ==================================================

function parseNestedJSON(
  config
) {
  for (
    const key of [
      "v2rRawJson",
      "overwriteServerData"
    ]
  ) {
    if (
      typeof config[key] === "string"
    ) {
      try {
        config[key] =
          JSON.parse(
            config[key]
          );
      } catch {
        // Bukan JSON valid,
        // biarkan sebagai string.
      }
    }
  }

  return config;
}

// ==================================================
// XCHACHA20-POLY1305
// ==================================================

async function decryptXChaCha(
  key,
  nonce,
  ciphertext,
  tag,
  aad
) {
  if (key.length !== 32) {
    throw new Error(
      `XChaCha key harus 32 byte, dapat ${key.length}`
    );
  }

  if (nonce.length !== 24) {
    throw new Error(
      `XChaCha nonce harus 24 byte, dapat ${nonce.length}`
    );
  }

  const {
    xchacha20poly1305
  } = await import(
    "@noble/ciphers/chacha.js"
  );

  const cipher =
    xchacha20poly1305(
      new Uint8Array(key),
      new Uint8Array(nonce),
      aad
        ? new Uint8Array(aad)
        : undefined
    );

  const combined =
    Buffer.concat([
      ciphertext,
      tag
    ]);

  return Buffer.from(
    cipher.decrypt(
      new Uint8Array(combined)
    )
  );
}

// ==================================================
// MAIN EHI DECRYPTOR
// ==================================================

async function ehiDecrypt(
  buffer
) {
  if (
    !Buffer.isBuffer(buffer) ||
    !buffer.length
  ) {
    throw new Error(
      "File EHI kosong"
    );
  }

  // ==================================================
  // PARSE CONTAINER
  // ==================================================

  const payload =
    extractEhiPayload(buffer);

  if (
    !payload ||
    payload.length < 16
  ) {
    throw new Error(
      "Payload EHI tidak valid"
    );
  }

  // ==================================================
  // LAYER 1
  // ==================================================

  const allIVs = [
    ...EHI.BYPASS_IVS.map(
      iv => ({
        iv,
        bypass: true
      })
    ),

    ...EHI.STANDARD_IVS.map(
      iv => ({
        iv,
        bypass: false
      })
    )
  ];

  let parsedConfig = null;
  let matchedBypass = false;

  for (
    const item of allIVs
  ) {
    try {

      // ==============================================
      // AES LAYER 1
      // ==============================================

      const layer1 =
        aesCbcDecrypt(
          EHI.L1_KEY,
          item.iv,
          payload
        );

      const message =
        layer1.toString(
          "utf8"
        );

      /*
       * Format:
       *
       * IV : something : ciphertext
       */

      const parts =
        message.split(":");

      if (
        parts.length < 3
      ) {
        continue;
      }

      // ==============================================
      // IV LAYER 2
      // ==============================================

      const iv2 =
        Buffer.from(
          parts[0].trim(),
          "base64"
        );

      const ciphertext2 =
        Buffer.from(
          parts[2].trim(),
          "base64"
        );

      if (
        iv2.length !== 16 ||
        ciphertext2.length === 0 ||
        ciphertext2.length % 16 !== 0
      ) {
        continue;
      }

      // ==============================================
      // AES LAYER 2
      // ==============================================

      const layer2 =
        aesCbcDecrypt(
          EHI.L2_KEY_STATIC,
          iv2,
          ciphertext2
        );

      // ==============================================
      // XXTEA
      // ==============================================

      const xxtea =
        xxteaDecrypt(
          layer2,
          EHI.EOO_MASTER_KEY
        );

      // ==============================================
      // JSON
      // ==============================================

      const config =
        decodeConfigMessage(
          xxtea
        );

      if (
        config &&
        typeof config === "object"
      ) {
        parsedConfig =
          config;

        matchedBypass =
          item.bypass;

        break;
      }

    } catch {
      // Coba IV berikutnya.
    }
  }

  // ==================================================
  // CONFIG GAGAL
  // ==================================================

  if (!parsedConfig) {
    throw new Error(
      "Tidak dapat membuka layer EHI. IV/key tidak cocok."
    );
  }

  // ==================================================
  // BYPASS CONFIG
  // ==================================================

  let finalConfig =
    parsedConfig;

  // ==================================================
  // STANDARD CONFIG
  // ==================================================

  if (!matchedBypass) {

    if (
      !parsedConfig.configData
    ) {
      throw new Error(
        "configData tidak ditemukan"
      );
    }

    // ==============================================
    // XOR CONFIG DATA
    // ==============================================

    const encoded =
      decryptConfigData(
        parsedConfig.configData,
        parsedConfig.configSalt ||
          "EVZJNI"
      );

    const cleanEncoded =
      String(encoded)
        .replace(/\s+/g, "");

    let raw;

    try {
      raw =
        Buffer.from(
          cleanEncoded,
          "base64"
        );
    } catch {
      throw new Error(
        "configData EHI bukan Base64 yang valid"
      );
    }

    // ==============================================
    // RAW PAYLOAD
    // ==============================================

    if (
      raw.length <
      0x32 + 16
    ) {
      throw new Error(
        "Payload EHI terlalu pendek"
      );
    }

    /*
     * Struktur:
     *
     * 00          version/header
     * 01..04      time cost
     * 05..08      memory cost
     * 09          parallelism
     * 0A..19      salt
     * 1A..31      nonce
     * 00..19      AAD
     * 32..end-16  ciphertext
     * end-16..end tag
     */

    const salt =
      raw.subarray(
        0x0a,
        0x1a
      );

    const timeCost =
      raw.readUInt32LE(1);

    const memoryCost =
      raw.readUInt32LE(5);

    const parallelism =
      raw[9];

    const nonce =
      raw.subarray(
        0x1a,
        0x32
      );

    const aad =
      raw.subarray(
        0,
        0x1a
      );

    const ciphertext =
      raw.subarray(
        0x32,
        raw.length - 16
      );

    const tag =
      raw.subarray(
        raw.length - 16
      );

    // ==============================================
    // MASTER KEY
    // ==============================================

    const password =
      generateMasterKey(
        parsedConfig
      );

    // ==============================================
    // ARGON2ID
    // ==============================================

    const key =
      await argon2.hash(
        password,
        {
          type:
            argon2.argon2id,

          timeCost,

          memoryCost,

          parallelism,

          hashLength: 32,

          salt,

          raw: true
        }
      );

    // ==============================================
    // XCHACHA20
    // ==============================================

    const decrypted =
      await decryptXChaCha(
        key,
        nonce,
        ciphertext,
        tag,
        aad
      );

    // ==============================================
    // FINAL JSON
    // ==============================================

    try {
      finalConfig =
        JSON.parse(
          decrypted.toString(
            "utf8"
          )
        );

    } catch {
      throw new Error(
        "Isi EHI berhasil didekripsi tetapi JSON final tidak valid"
      );
    }
  }

  // ==================================================
  // DECODE INNER FIELDS
  // ==================================================

  finalConfig =
    decodeInnerFields(
      finalConfig,
      parsedConfig.configSalt ||
        "EVZJNI"
    );

  // ==================================================
  // NESTED JSON
  // ==================================================

  finalConfig =
    parseNestedJSON(
      finalConfig
    );

  // ==================================================
  // RESULT
  // ==================================================

  return {
    success: true,

    format: "ehi",

    result:
      JSON.stringify(
        finalConfig,
        null,
        4
      ),

    data:
      finalConfig
  };
}

// ==================================================
// EXPORT
// ==================================================

module.exports = ehiDecrypt;
