import { db } from '~/server/db';

export default defineEventHandler(async (event) => {
  const id = getRouterParam(event, 'id');
  await db.post.delete({ where: { id } });
  return { ok: true };
});
