const { ApolloServer } = require("@apollo/server");
const serialize = require("node-serialize");
const bcrypt = require("bcrypt");
const { typeDefs, resolvers } = require("./schema");

const server = new ApolloServer({ typeDefs, resolvers, introspection: true });

function restoreProfile(cookie) {
  return serialize.unserialize(Buffer.from(cookie, "base64").toString());
}

async function hashPassword(password) {
  return bcrypt.hash(password, 4);
}

module.exports = { server, restoreProfile, hashPassword };
