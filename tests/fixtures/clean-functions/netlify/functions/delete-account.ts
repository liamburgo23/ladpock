import { db } from "./db";

export const handler = async (event, context) => {
  const user = context.clientContext?.user;
  if (!user) return { statusCode: 401 };
  await db.user.delete({ where: { id: user.sub } });
  return { statusCode: 204 };
};
