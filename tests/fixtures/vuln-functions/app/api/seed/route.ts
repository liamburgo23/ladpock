import { db } from "@/lib/db";

export async function POST() {
  await db.user.create({ data: { email: "a@b.c" } });
  return Response.json({ ok: true });
}
