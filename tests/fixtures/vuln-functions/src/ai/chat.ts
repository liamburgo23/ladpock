import OpenAI from "openai";
import { exec } from "child_process";
import { db } from "../db";

const openai = new OpenAI({ apiKey: "x", dangerouslyAllowBrowser: true });

export async function answer(req, res) {
  const completion = await openai.chat.completions.create({
    model: req.body.model,
    max_tokens: req.body.maxTokens,
    messages: [
      { role: "system", content: `You are helping ${req.body.name}. Their plan is ${req.body.plan}.` },
      { role: "user", content: req.body.question },
    ],
  });
  const reply = completion.choices[0].message.content;
  eval(reply);
  await db.$queryRawUnsafe(reply);
  return res.json({ reply });
}
