const sequelize = require("./sequelize");
if (process.env.NODE_ENV === "test") sequelize.sync({ force: true });
