const bcrypt = require("bcrypt");
const { Resend } = require("resend");
const crypto = require("crypto");
const { prisma } = require("./db");

const resend = new Resend(process.env.RESEND_API_KEY);

async function forgotPassword(email) {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return;
  const token = crypto.randomBytes(32).toString("hex");
  await prisma.resetToken.create({ data: { userId: user.id, hash: crypto.createHash("sha256").update(token).digest("hex") } });
  await resend.emails.send({ to: user.email, subject: "Reset your password", text: `${process.env.APP_URL}/reset?token=${token}` });
  console.info("sent a password reset", user.id);
}

const hash = (password) => bcrypt.hash(password, 12);
module.exports = { forgotPassword, hash };
