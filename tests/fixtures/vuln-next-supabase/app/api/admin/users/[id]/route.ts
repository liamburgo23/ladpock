import { db } from "@/lib/db";

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.user.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
