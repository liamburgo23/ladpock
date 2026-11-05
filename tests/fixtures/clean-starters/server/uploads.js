const express = require("express");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");

const storage = multer.diskStorage({
  destination: "/var/data/uploads",
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (req, file, cb) => cb(null, file.mimetype === "image/png") });

const router = express.Router();
router.post("/", upload.single("file"), (req, res) => res.json({ id: req.file.filename }));
module.exports = router;
