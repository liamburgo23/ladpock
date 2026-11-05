const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  try {
    req.user = jwt.verify(header.replace("Bearer ", ""), process.env.JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    console.warn("rejected a token");
    res.status(401).json({ error: "Unauthorized" });
  }
}
module.exports = { requireAuth };
