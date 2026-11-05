const multer = require("multer");
const crypto = require("crypto");

const upload = multer({
  dest: "/var/data",
  limits: { fileSize: 5000000 },
  fileFilter: (req, file, cb) => cb(null, file.mimetype === "image/png"),
});

const storage = multer.diskStorage({
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),
});

module.exports = { upload, storage };
