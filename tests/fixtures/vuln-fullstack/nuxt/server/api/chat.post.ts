import OpenAI from 'openai';

const openai = new OpenAI();

export default defineEventHandler(async (event) => {
  const body = await readBody(event);
  return openai.chat.completions.create({ model: 'gpt-4o', messages: body.messages });
});
