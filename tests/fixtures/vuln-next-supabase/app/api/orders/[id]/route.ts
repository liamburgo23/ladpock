import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return NextResponse.json({ error: "unauthorised" }, { status: 401 });
  const order = await db.order.findUnique({ where: { id: params.id } });
  return NextResponse.json(order);
}
