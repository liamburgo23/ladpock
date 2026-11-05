const Hapi = require("@hapi/hapi");
const { db } = require("./db");

const server = Hapi.server({ port: 3000 });
server.auth.default("session");
server.route({
  method: "POST",
  path: "/api/widgets",
  handler: (request) => db.widget.create({ data: { ...request.payload, userId: request.auth.credentials.id } }),
});
