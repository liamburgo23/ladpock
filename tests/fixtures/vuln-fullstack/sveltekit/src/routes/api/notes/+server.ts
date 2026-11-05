import { json } from '@sveltejs/kit';
import { prisma } from '$lib/db';

export async function POST({ request }) {
  const body = await request.json();
  const note = await prisma.note.create({ data: { text: body.text } });
  return json(note);
}
