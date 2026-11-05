import { db } from '~/server/db';

export default defineEventHandler(async (event) => {
  const { user } = await requireUserSession(event);
  const id = getRouterParam(event, 'id');
  await db.post.deleteMany({ where: { id, authorId: user.id } });
  return { ok: true };
});
