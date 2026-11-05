const multer = require("multer");
const path = require("path");
const fs = require("fs");

const anything = multer({ dest: "public/uploads" });
const sized = multer({ dest: "/var/data", limits: { fileSize: 1000 } });

const storage = multer.diskStorage({
  filename: (req, file, cb) => cb(null, file.originalname),
});

function save(file) {
  fs.writeFileSync(path.join("/var/data", file.originalname), file.buffer);
}
