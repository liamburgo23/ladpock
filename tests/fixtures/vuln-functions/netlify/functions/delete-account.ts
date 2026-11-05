import { db } from "./db";

export const handler = async (event) => {
  const { id } = JSON.parse(event.body);
  await db.user.delete({ where: { id } });
  return { statusCode: 204 };
};
