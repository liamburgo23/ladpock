import { z } from "zod";
import { createTRPCRouter, publicProcedure, protectedProcedure } from "../trpc";

export const orderRouter = createTRPCRouter({
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ ctx, input }) => ctx.db.order.findFirst({ where: { id: input.id, userId: ctx.session.user.id } })),

  remove: protectedProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ ctx, input }) => ctx.db.order.deleteMany({ where: { id: input.id, userId: ctx.session.user.id } })),

  catalogue: publicProcedure.query(({ ctx }) => ctx.db.product.findMany({ select: { id: true, name: true } })),
});
