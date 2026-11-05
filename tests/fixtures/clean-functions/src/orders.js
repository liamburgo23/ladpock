const { db } = require("./db");

exports.stats = async () => {
  return { statusCode: 200, body: JSON.stringify(await db.order.count()) };
};
