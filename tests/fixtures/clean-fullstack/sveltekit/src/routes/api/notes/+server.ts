import { error, json } from '@sveltejs/kit';
import { z } from 'zod';
import { prisma } from '$lib/db';

const Note = z.object({ text: z.string().max(5000) });

export async function POST({ request, locals }) {
  if (!locals.user) throw error(401);
  const body = Note.parse(await request.json());
  const note = await prisma.note.create({ data: { text: body.text, userId: locals.user.id } });
  return json(note);
}
