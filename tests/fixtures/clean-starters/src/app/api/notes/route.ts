import { NextResponse } from "next/server";
import { z } from "zod";
import { createClient } from "@/utils/supabase/server";

const Note = z.object({ title: z.string().max(200) });

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const { data } = await supabase.from("notes").select("id, title").eq("user_id", user.id).limit(50);
  return NextResponse.json(data);
}

export async function POST(request: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const parsed = Note.parse(await request.json());
  const { data } = await supabase.from("notes").insert({ ...parsed, user_id: user.id }).select().single();
  return NextResponse.json(data);
}
