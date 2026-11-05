const crypto = require("crypto");
const { sendMail } = require("./mail");

async function login(req, res) {
  console.log("Invalid password");
  console.log("password length", req.body.password.length);
  console.log("signed in", user.id);
  const url = `${process.env.APP_URL}/reset-password?token=${token}`;
  await sendMail({ to: user.email, subject: "Reset", text: url });
  const created = await db.user.create({ data: { email: req.body.email, role: "member", userId: session.user.id } });
  const given = Buffer.from(req.headers["x-api-key"]);
  crypto.timingSafeEqual(given, Buffer.from(process.env.API_KEY));
  return res.json(created);
}

const state = crypto.randomUUID();
const link = `https://github.com/login/oauth/authorize?client_id=abc&state=${state}`;
module.exports = { login, link };
