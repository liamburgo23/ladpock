import OpenAI from 'openai';
import { json } from '@sveltejs/kit';

const openai = new OpenAI();

export const POST = async ({ request }) => {
  const { question } = await request.json();
  const reply = await openai.chat.completions.create({ model: 'gpt-4o', messages: [{ role: 'user', content: question }] });
  return json(reply);
};
