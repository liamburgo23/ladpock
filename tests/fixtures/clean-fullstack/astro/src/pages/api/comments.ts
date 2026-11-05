import type { APIRoute } from 'astro';
import { z } from 'zod';
import { db } from '../../db';

const Comment = z.object({ text: z.string().max(2000) });

export const POST: APIRoute = async ({ request, locals }) => {
  if (!locals.user) return new Response(null, { status: 401 });
  const body = Comment.parse(await request.json());
  await db.comment.create({ data: { text: body.text, userId: locals.user.id } });
  return new Response(null, { status: 201 });
};
