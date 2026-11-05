import { db } from "../../lib/db";
import { getUser } from "../../lib/auth";

export default async function handler(req, res) {
  const user = await getUser(req);
  if (!user) return res.status(401).end();
  return res.json(await db.order.findFirst({ where: { id: req.query.id, userId: user.id } }));
}
