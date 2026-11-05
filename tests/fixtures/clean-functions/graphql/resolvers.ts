import { db } from "../db";

export const resolvers = {
  Query: {
    products: () => db.product.findMany({ take: 50 }),
    report: async (_, args, ctx) => {
      if (!ctx.user) throw new Error("no");
      return db.report.findFirst({ where: { id: args.id, ownerId: ctx.user.id } });
    },
  },
  Mutation: {
    deleteReport: async (_, { id }, ctx) => {
      if (!ctx.user) throw new Error("no");
      return db.report.deleteMany({ where: { id, ownerId: ctx.user.id } });
    },
  },
};
