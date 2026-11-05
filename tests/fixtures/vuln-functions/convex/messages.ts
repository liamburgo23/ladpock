import { v } from "convex/values";
import { query, mutation, internalMutation } from "./_generated/server";

export const list = query({
  args: {},
  handler: async (ctx) => ctx.db.query("messages").collect(),
});

export const remove = mutation({
  args: { id: v.id("messages") },
  handler: async (ctx, args) => {
    await ctx.db.delete(args.id);
  },
});

export const read = query({
  args: { id: v.id("messages") },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not signed in");
    return ctx.db.get(args.id);
  },
});

export const purge = internalMutation({
  args: {},
  handler: async (ctx) => {
    await ctx.db.delete("x");
  },
});
