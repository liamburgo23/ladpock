import { db } from "../db";

export const resolvers = {
  Query: {
    user: (_, { id }) => db.user.findUnique({ where: { id } }),
    secretReport: async (_, args, ctx) => {
      if (!ctx.user) throw new Error("no");
      return db.report.findUnique({ where: { id: args.id } });
    },
  },
  Mutation: {
    deleteUser: async (_, { id }) => db.user.delete({ where: { id } }),
  },
};
