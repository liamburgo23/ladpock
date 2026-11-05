import { initTRPC, TRPCError } from "@trpc/server";
import superjson from "superjson";

const t = initTRPC.context<Context>().create({ transformer: superjson });

export const createTRPCRouter = t.router;
export const publicProcedure = t.procedure;
export const protectedProcedure = t.procedure.use(({ ctx, next }) => {
  if (!ctx.session?.user) throw new TRPCError({ code: "UNAUTHORIZED" });
  return next({ ctx: { session: { ...ctx.session, user: ctx.session.user } } });
});
export const adminProcedure = protectedProcedure.use(({ ctx, next }) => {
  if (ctx.session.user.role !== "ADMIN") throw new TRPCError({ code: "FORBIDDEN" });
  return next();
});
