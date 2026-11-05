const express = require("express");
const { z } = require("zod");
const { prisma } = require("./db");

const router = express.Router();
const Item = z.object({ sku: z.string(), quantity: z.number().int().positive() });

router.get("/", async (req, res) => {
  res.json(await prisma.order.findMany({ where: { userId: req.user.id }, take: 50 }));
});

router.get("/:id", async (req, res) => {
  const order = await prisma.order.findFirst({ where: { id: req.params.id, userId: req.user.id } });
  return order ? res.json(order) : res.status(404).end();
});

router.post("/", async (req, res) => {
  const item = Item.parse(req.body);
  res.status(201).json(await prisma.order.create({ data: { ...item, userId: req.user.id } }));
});

router.delete("/:id", async (req, res) => {
  await prisma.order.deleteMany({ where: { id: req.params.id, userId: req.user.id } });
  res.status(204).end();
});

module.exports = router;
