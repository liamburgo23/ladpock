import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { auth } from "@/lib/auth";

export async function POST(req: Request) {
  const session = await auth();
  if (!session) return new Response("Unauthorised", { status: 401 });
  const { text } = await req.json();
  const result = await generateText({ model: openai("gpt-4o-mini"), prompt: `Summarise: ${text}` });
  return Response.json({ summary: result.text });
}
