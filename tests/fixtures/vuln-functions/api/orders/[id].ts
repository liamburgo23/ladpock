import { db } from "../../lib/db";

export default async function handler(req, res) {
  if (req.method === "DELETE") {
    await db.order.delete({ where: { id: req.query.id } });
    return res.status(204).end();
  }
  return res.json(await db.order.findUnique({ where: { id: req.query.id } }));
}
