import type { APIRoute } from 'astro';
import { db } from '../../db';

export const POST: APIRoute = async ({ request }) => {
  const body = await request.json();
  await db.comment.create({ data: { text: body.text } });
  return new Response(null, { status: 201 });
};
