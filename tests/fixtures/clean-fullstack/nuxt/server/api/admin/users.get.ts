import { db } from '~/server/db';

export default defineEventHandler(async (event) => {
  await requireUserSession(event);
  return db.user.findMany();
});
