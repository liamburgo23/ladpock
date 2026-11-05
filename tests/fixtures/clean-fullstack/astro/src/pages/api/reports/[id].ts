import type { APIRoute } from 'astro';
import { db } from '../../../db';

export const GET: APIRoute = async ({ params, locals }) => {
  if (!locals.user) return new Response(null, { status: 401 });
  const report = await db.report.findFirst({ where: { id: params.id, userId: locals.user.id } });
  return Response.json(report);
};
