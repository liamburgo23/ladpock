const { sendMail } = require("./mail");

async function login(req, res) {
  console.log("login attempt", req.body);
  console.log("password was", req.body.password);
  console.log(`token ${session.accessToken}`);
  console.log("Invalid password");
  const url = `https://${req.headers.host}/reset-password?token=${token}`;
  await sendMail({ to: req.body.email, subject: "Reset", text: url });
  const user = await db.user.create({ data: { email: req.body.email, role: req.body.role, userId: req.body.userId } });
  if (req.cookies.isAdmin) return res.json(await db.user.findMany());
  const who = req.headers["x-user-id"];
  if (req.headers["x-api-key"] === process.env.API_KEY) grant();
  return res.json(process.env);
}

const link = "https://github.com/login/oauth/authorize?client_id=abc&scope=read:user";
module.exports = { login, link };
