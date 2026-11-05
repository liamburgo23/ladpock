import type { APIRoute } from 'astro';
import { db } from '../../../db';

export const GET: APIRoute = async ({ params, locals }) => {
  if (!locals.user) return new Response(null, { status: 401 });
  const report = await db.report.findUnique({ where: { id: params.id } });
  return Response.json(report);
};
