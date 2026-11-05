import { z } from "zod";
import OpenAI from "openai";
import { createTRPCRouter, publicProcedure, protectedProcedure } from "../trpc";

const openai = new OpenAI();

export const orderRouter = createTRPCRouter({
  getById: protectedProcedure
    .input(z.object({ id: z.string() }))
    .query(({ ctx, input }) => ctx.db.order.findUnique({ where: { id: input.id } })),

  remove: publicProcedure
    .input(z.object({ id: z.string() }))
    .mutation(({ ctx, input }) => ctx.db.order.delete({ where: { id: input.id } })),

  allInvoices: publicProcedure.query(({ ctx }) => ctx.db.invoice.findMany()),

  summarise: publicProcedure
    .input(z.object({ text: z.string() }))
    .mutation(({ input }) => openai.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: input.text }] })),
});
