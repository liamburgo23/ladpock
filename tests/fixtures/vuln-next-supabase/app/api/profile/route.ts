import { createClient } from "@/utils/supabase/server";

export async function GET() {
  const supabase = await createClient();
  const { data: { session } } = await supabase.auth.getSession();
  if (!session) return Response.json({ error: "Unauthorised" }, { status: 401 });
  const { data } = await supabase.from("profiles").select("*").eq("id", session.user.id).single();
  return Response.json(data);
}
