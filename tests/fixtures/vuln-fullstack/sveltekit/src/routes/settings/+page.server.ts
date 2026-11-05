import { prisma } from '$lib/db';

export const actions = {
  default: async ({ request }) => {
    const form = await request.formData();
    await prisma.setting.update({ where: { key: 'theme' }, data: { value: form.get('theme') } });
  },
  reset: async () => {
    await prisma.setting.deleteMany({});
  },
};
