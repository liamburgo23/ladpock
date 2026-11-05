import { Elysia, t } from "elysia";
import { bearer } from "@elysiajs/bearer";
import { db } from "./db";

new Elysia()
  .use(bearer())
  .get("/api/things", ({ bearer, user }) => db.thing.findMany({ where: { userId: user.id }, take: 20 }))
  .listen(3000);
