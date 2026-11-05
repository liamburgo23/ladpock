import { z } from "zod";
import { adminProcedure, createTRPCRouter, protectedProcedure } from "../trpc";

export const orderRouter = createTRPCRouter({
  byId: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ ctx, input }) => ctx.db.order.findFirst({ where: { id: input.id, userId: ctx.session.user.id } })),

  refund: adminProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ ctx, input }) => ctx.db.order.update({ where: { id: input.id }, data: { refundedBy: ctx.session.user.id } })),
});
