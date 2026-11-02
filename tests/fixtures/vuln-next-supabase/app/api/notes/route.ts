import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function POST(req: Request) {
  const body = await req.json();
  try {
    const { data } = await supabase.from("notes").insert(body);
    return Response.json({ data });
  } catch (err: any) {
    return Response.json({ error: err.stack }, { status: 500 });
  }
}
