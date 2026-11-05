import { error, json } from '@sveltejs/kit';
import { prisma } from '$lib/db';

export const DELETE = async ({ params, locals }) => {
  if (!locals.user) throw error(401);
  await prisma.note.delete({ where: { id: params.id } });
  return json({ ok: true });
};
