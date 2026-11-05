const express = require("express");
const { execFile } = require("child_process");
const path = require("path");
const { pool } = require("./db");

const router = express.Router();
const ALLOWED_HOSTS = new Set(["hooks.example.invalid"]);

router.get("/orders/search", async (req, res) => {
  const { term } = req.query;
  const sql = "SELECT id, note FROM orders WHERE note LIKE $1 LIMIT 50";
  res.json((await pool.query(sql, [`%${term}%`])).rows);
});

router.post("/orders/thumbnail", async (req, res) => {
  const { file } = req.body;
  execFile("convert", [path.basename(file), "thumb.png"]);
  res.status(202).end();
});

router.get("/orders/receipt", async (req, res) => {
  const name = path.basename(req.query.name);
  res.sendFile(name, { root: path.join(__dirname, "receipts") });
});

router.post("/orders/webhook-test", async (req, res) => {
  const target = req.body.url;
  if (!ALLOWED_HOSTS.has(new URL(target).host)) return res.status(400).end();
  const reply = await fetch(target);
  res.json({ status: reply.status });
});

router.get("/orders/done", async (req, res) => {
  const next = req.query.next;
  if (!next.startsWith("/") || next.startsWith("//")) return res.redirect("/orders");
  res.redirect(next);
});

router.get("/orders/hello", async (req, res) => {
  const who = req.query.who;
  res.json({ greeting: `Orders for ${who}` });
});

module.exports = router;
