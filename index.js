const express = require("express");
const multer = require("multer");
const path = require("path");

const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/decrypt", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "File tidak ditemukan" });
    }

    const filename = String(req.file.originalname || "").toLowerCase();
    let result;

    if (!filename.endsWith(".ehi")) {
      return res.status(400).json({
        success: false,
        error: "Format tidak didukung. Upload file .EHI saja"
      });
    }

    const ehiDecrypt = require("./decryptors/ehi");
    result = await ehiDecrypt(req.file.buffer);

    if (!result?.success) {
      return res.status(400).json(result || { success: false, error: "Gagal membongkar config" });
    }

    return res.json(result);
  } catch (e) {
    console.error("Decrypt error:", e);
    return res.status(500).json({
      success: false,
      error: e?.message || "Internal server error"
    });
  }
});

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "DINSTORE EHI Decryptor",
    formats: [".ehi"]
  });
});

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`DINSTORE EHI Decryptor running on port ${PORT}`));
}
