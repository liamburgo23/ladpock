const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const ejs = require("ejs");
const { pool } = require("./db");

const router = express.Router();

router.get("/orders/search", async (req, res) => {
  const { term } = req.query;
  const sql = `
    SELECT * FROM orders
    WHERE note LIKE '%${term}%'
  `;
  res.json((await pool.query(sql)).rows);
});

router.post("/orders/thumbnail", async (req, res) => {
  const { file } = req.body;
  const cmd = `convert ${file} thumb.png`;
  exec(cmd);
  res.status(202).end();
});

router.get("/orders/receipt", async (req, res) => {
  const name = req.query.name;
  const full = path.join(__dirname, "receipts", name);
  res.send(fs.readFileSync(full));
});

router.post("/orders/webhook-test", async (req, res) => {
  const target = req.body.url;
  const reply = await fetch(target);
  res.json({ status: reply.status });
});

router.get("/orders/done", async (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});

router.post("/orders/discount", async (req, res) => {
  const formula = req.body.formula;
  const rule = formula.trim();
  res.json({ value: vm.runInNewContext(rule) });
});

router.get("/orders/hello", async (req, res) => {
  const who = req.query.who;
  const page = "<h1>Orders for " + who + "</h1>";
  res.send(page);
});

router.post("/orders/preview", async (req, res) => {
  const layout = req.body.layout;
  res.send(ejs.render(layout, {}));
});

module.exports = router;
