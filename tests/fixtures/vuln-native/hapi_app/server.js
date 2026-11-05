const Hapi = require("@hapi/hapi");
const { db } = require("./db");

const server = Hapi.server({ port: 3000 });
server.route({
  method: "POST",
  path: "/api/widgets",
  handler: (request) => db.widget.create({ data: request.payload }),
});
server.route([
  { method: "DELETE", path: "/api/widgets/{id}", options: { auth: "session" }, handler: (request) => db.widget.delete({ where: { id: request.params.id } }) },
]);
