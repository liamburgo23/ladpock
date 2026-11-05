import { defineAction } from 'astro:actions';
import { z } from 'astro:schema';
import { db } from '../db';

export const server = {
  removeAccount: defineAction({
    input: z.object({ id: z.string() }),
    handler: async (input, context) => {
      if (!context.locals.user) throw new Error('Sign in first');
      await db.account.deleteMany({ where: { id: input.id, userId: context.locals.user.id } });
    },
  }),
};
