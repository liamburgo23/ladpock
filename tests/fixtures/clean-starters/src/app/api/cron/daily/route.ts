import crypto from "node:crypto";
import { db } from "@/server/db";

export async function GET(request: Request) {
  const given = Buffer.from(request.headers.get("authorization") ?? "");
  const expected = Buffer.from(`Bearer ${process.env.CRON_SECRET}`);
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return new Response("no", { status: 401 });
  await db.session.deleteMany({ where: { expires: { lt: new Date() } } });
  return Response.json({ ok: true });
}
