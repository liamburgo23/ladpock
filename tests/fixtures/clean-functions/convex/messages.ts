import { v } from "convex/values";
import { query, mutation } from "./_generated/server";

export const list = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not signed in");
    return ctx.db.query("messages").withIndex("by_user", (q) => q.eq("userId", identity.subject)).collect();
  },
});

export const remove = mutation({
  args: { id: v.id("messages") },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not signed in");
    const message = await ctx.db.get(args.id);
    if (message?.userId !== identity.subject) throw new Error("Not yours");
    await ctx.db.delete(args.id);
  },
});
