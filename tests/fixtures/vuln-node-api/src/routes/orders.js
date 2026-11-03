const express = require("express");
const { checkJwt } = require("../middleware/jwt");
const Order = require("../models/order");

const router = express.Router();
router.use(checkJwt);

router.get("/:id", async (req, res) => {
  const order = await Order.findById(req.params.id);
  res.json(order);
});

module.exports = router;
