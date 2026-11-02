import Anthropic from "@anthropic-ai/sdk";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { z } from "zod";
import { createClient } from "@/utils/supabase/server";

const anthropic = new Anthropic();
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(10, "1 m") });
const Body = z.object({ prompt: z.string().max(2000) });

export async function POST(req: Request) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return Response.json({ error: "Unauthorised" }, { status: 401 });
  const { success } = await ratelimit.limit(user.id);
  if (!success) return Response.json({ error: "Too many requests" }, { status: 429 });
  const { prompt } = Body.parse(await req.json());
  const message = await anthropic.messages.create({
    model: "claude-sonnet-5-5",
    max_tokens: 1024,
    messages: [{ role: "user", content: prompt }],
  });
  return Response.json(message);
}
