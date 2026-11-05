import { createSchema } from "graphql-yoga";

export const schema = createSchema({
  typeDefs: /* GraphQL */ `type Query { me: User, posts: [Post!]! } type Mutation { renameMe(name: String!): User }`,
  resolvers: {
    Query: {
      me: (_, __, { user }) => user,
      posts: (_, __, { db }) => db.post.findMany({ take: 20 }),
    },
    Mutation: {
      renameMe: (_, { name }, { user, db }) => {
        if (!user) throw new Error("Sign in first");
        return db.user.update({ where: { id: user.id }, data: { name } });
      },
    },
  },
});
