import { db } from "@/lib/db";

export async function GET() {
  await db.report.findMany({ take: 1 });
  return Response.json({ ok: true });
}
