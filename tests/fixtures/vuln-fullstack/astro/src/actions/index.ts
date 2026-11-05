import { defineAction } from 'astro:actions';
import { db } from '../db';

export const server = {
  removeAccount: defineAction({
    handler: async (input) => {
      await db.account.delete({ where: { id: input.id } });
    },
  }),
};
