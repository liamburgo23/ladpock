const { db } = require("./db");

exports.create = async (event) => {
  await db.order.create({ data: JSON.parse(event.body) });
  return { statusCode: 201 };
};

exports.get = async (event) => {
  const order = await db.order.findUnique({ where: { id: event.pathParameters.id } });
  return { statusCode: 200, body: JSON.stringify(order) };
};

exports.stats = async () => {
  return { statusCode: 200, body: JSON.stringify(await db.order.findMany()) };
};
