import { NextResponse } from "next/server";
import { createClient } from "@/utils/supabase/server";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorised" }, { status: 401 });
  const { data } = await supabase.from("orders").select("*").eq("id", id).eq("user_id", user.id).single();
  return NextResponse.json(data);
}
