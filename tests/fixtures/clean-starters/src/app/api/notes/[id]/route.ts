import { NextResponse } from "next/server";
import { createClient } from "@/utils/supabase/server";

export async function DELETE(_request: Request, { params }: { params: { id: string } }) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  await supabase.from("notes").delete().eq("id", params.id).eq("user_id", user.id);
  return new NextResponse(null, { status: 204 });
}
