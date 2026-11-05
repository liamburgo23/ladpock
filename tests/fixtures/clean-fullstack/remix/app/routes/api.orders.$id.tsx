import { json } from '@remix-run/node';
import { db } from '~/db.server';
import { requireUserId } from '~/session.server';

export async function loader({ request, params }) {
  const userId = await requireUserId(request);
  const order = await db.order.findFirst({ where: { id: params.id, userId } });
  return json(order);
}

export async function action({ request, params }) {
  const userId = await requireUserId(request);
  await db.order.deleteMany({ where: { id: params.id, userId } });
  return json({ ok: true });
}
