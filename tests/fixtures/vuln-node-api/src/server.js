const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const OpenAI = require("openai");
const User = require("./models/user");
const Post = require("./models/post");
const ordersRouter = require("./routes/orders");

const app = express();
const openai = new OpenAI();

app.use(express.json({ limit: "200mb" }));
app.use(session({ secret: "keyboard cat", resave: false, saveUninitialized: true }));
app.set("trust proxy", true);
app.use("/api/orders", ordersRouter);

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").split(" ")[1];
  const payload = jwt.decode(token);
  if (!payload) return res.status(401).end();
  req.user = payload;
  next();
}

app.post("/api/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(404).json({ error: "User not found" });
  if (user.password !== req.body.password) return res.status(401).json({ error: "Wrong password" });
  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.post("/api/users", async (req, res) => {
  const user = await User.create(req.body);
  res.status(201).json(user);
});

app.get("/api/search", async (req, res) => {
  const users = await User.find(req.query);
  const pattern = new RegExp(req.query.q);
  res.json(users.filter((u) => pattern.test(u.name)));
});

app.get("/files/:name", (req, res) => {
  res.sendFile(path.join(__dirname, "uploads", req.params.name));
});

app.put("/api/settings", requireAuth, async (req, res) => {
  const settings = _.merge({}, req.body);
  await User.updateOne({ _id: req.user.id }, settings);
  res.json(settings);
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  await Post.findByIdAndDelete(req.params.id);
  res.status(204).end();
});

app.post("/api/ai/summarise", async (req, res) => {
  const result = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: req.body.text }],
  });
  res.json(result);
});

function encryptNote(text) {
  const cipher = crypto.createCipher("aes-256-ecb", process.env.NOTE_KEY);
  return cipher.update(text, "utf8", "hex") + cipher.final("hex");
}

module.exports = { app, encryptNote };
app.listen(3000);
