const path = require("path");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const User = require("./models/user");
const Post = require("./models/post");

const app = express();
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(mongoSanitize());
app.set("trust proxy", 1);

const loginRateLimit = rateLimit({ windowMs: 60_000, max: 5 });
const Credentials = z.object({ email: z.string().email(), password: z.string().min(12) });
const PostBody = z.object({ title: z.string().max(200), text: z.string().max(10_000) });

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });
    next();
  } catch {
    res.status(401).end();
  }
}

app.post("/api/login", loginRateLimit, async (req, res) => {
  const { email, password } = Credentials.parse(req.body);
  const user = await User.findOne({ email: String(email) });
  const ok = user && (await bcrypt.compare(password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: "Email or password is incorrect" });
  const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
  res.json({ token });
});

app.post("/api/posts", requireAuth, async (req, res) => {
  const body = PostBody.parse(req.body);
  const post = await Post.create({ title: body.title, text: body.text, authorId: req.user.sub });
  res.status(201).json(post);
});

app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  const result = await Post.deleteOne({ _id: String(req.params.id), authorId: req.user.sub });
  res.status(result.deletedCount ? 204 : 404).end();
});

app.get("/files/:name", requireAuth, (req, res) => {
  res.sendFile(path.basename(req.params.name), { root: path.join(__dirname, "uploads") });
});

app.listen(3000);
