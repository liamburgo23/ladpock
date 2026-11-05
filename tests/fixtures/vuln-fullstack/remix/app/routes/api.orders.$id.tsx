import { json } from '@remix-run/node';
import { db } from '~/db.server';
import { requireUserId } from '~/session.server';

export async function loader({ request, params }) {
  await requireUserId(request);
  const order = await db.order.findUnique({ where: { id: params.id } });
  return json(order);
}

export async function action({ request, params }) {
  await requireUserId(request);
  await db.order.delete({ where: { id: params.id } });
  return json({ ok: true });
}
