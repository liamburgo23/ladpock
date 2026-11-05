import { Hono } from "hono";
import { jwt } from "hono/jwt";

type Bindings = { DB: D1Database; JWT_SECRET: string };
const app = new Hono<{ Bindings: Bindings }>();

app.use("/api/*", (c, next) => jwt({ secret: c.env.JWT_SECRET })(c, next));

app.get("/api/notes", async (c) => {
  const payload = c.get("jwtPayload");
  const { results } = await c.env.DB.prepare("SELECT id, title FROM notes WHERE user_id = ? LIMIT 50").bind(payload.sub).all();
  return c.json(results);
});

export default app;
