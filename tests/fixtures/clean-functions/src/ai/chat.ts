import OpenAI from "openai";
import { getUser } from "../auth";

const openai = new OpenAI();

export async function answer(req, res) {
  const user = await getUser(req);
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    max_tokens: 500,
    messages: [
      { role: "system", content: "You answer questions about cooking." },
      { role: "user", content: req.body.question },
    ],
  });
  const reply = completion.choices[0].message.content;
  console.log("answered for", user.id);
  return res.json({ reply });
}
