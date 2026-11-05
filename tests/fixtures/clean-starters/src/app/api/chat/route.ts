import { openai } from "@ai-sdk/openai";
import { streamText } from "ai";
import { Ratelimit } from "@upstash/ratelimit";
import { getServerSession } from "next-auth";
import { authOptions } from "@/server/auth";
import { z } from "zod";

const limiter = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(10, "1 m") });
const Body = z.object({ messages: z.array(z.object({ role: z.enum(["user", "assistant"]), content: z.string() })) });

export async function POST(req: Request) {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const { success } = await limiter.limit(session.user.id);
  if (!success) return new Response("Slow down", { status: 429 });
  const { messages } = Body.parse(await req.json());
  const result = streamText({ model: openai("gpt-4o-mini"), maxTokens: 800, system: "You are a helpful cooking assistant.", messages });
  return result.toDataStreamResponse();
}
