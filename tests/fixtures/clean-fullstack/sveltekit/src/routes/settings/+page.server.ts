import { error } from '@sveltejs/kit';
import { z } from 'zod';
import { prisma } from '$lib/db';

const Settings = z.object({ theme: z.string() });

export const actions = {
  default: async ({ request, locals }) => {
    if (!locals.user) throw error(401);
    const form = Settings.parse(Object.fromEntries(await request.formData()));
    await prisma.setting.update({ where: { userId: locals.user.id }, data: { value: form.theme } });
  },
};
