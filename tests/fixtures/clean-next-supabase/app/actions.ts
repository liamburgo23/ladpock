"use server";

import { z } from "zod";
import { createClient } from "@/utils/supabase/server";

const NoteId = z.string().uuid();

export async function deleteNote(id: string) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error("Not signed in");
  await supabase.from("notes").delete().eq("id", NoteId.parse(id)).eq("user_id", user.id);
}
