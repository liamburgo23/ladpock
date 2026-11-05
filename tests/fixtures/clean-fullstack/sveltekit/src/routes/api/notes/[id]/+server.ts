import { error, json } from '@sveltejs/kit';
import { prisma } from '$lib/db';

export const DELETE = async ({ params, locals }) => {
  if (!locals.user) throw error(401);
  await prisma.note.deleteMany({ where: { id: params.id, userId: locals.user.id } });
  return json({ ok: true });
};
