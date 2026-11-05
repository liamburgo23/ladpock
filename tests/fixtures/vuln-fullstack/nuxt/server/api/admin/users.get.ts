import { db } from '~/server/db';

export default defineEventHandler(async () => {
  return db.user.findMany();
});
