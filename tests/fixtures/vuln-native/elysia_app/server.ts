import { Elysia, t } from "elysia";
import { db } from "./db";

new Elysia()
  .get("/api/things/:id", ({ params }) => db.thing.findUnique({ where: { id: params.id } }))
  .delete("/api/things/:id", ({ params }) => db.thing.delete({ where: { id: params.id } }))
  .group("/api/v2", (app) => app.post("/things", ({ body }) => db.thing.create({ data: body })))
  .listen(3000);
