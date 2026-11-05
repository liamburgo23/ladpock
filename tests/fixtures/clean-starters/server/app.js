const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { requireAuth } = require("./auth");
const orders = require("./orders");
const uploads = require("./uploads");

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(rateLimit({ windowMs: 60000, max: 100 }));
app.use("/api/orders", requireAuth, orders);
app.use("/api/uploads", requireAuth, uploads);
app.listen(process.env.PORT);
