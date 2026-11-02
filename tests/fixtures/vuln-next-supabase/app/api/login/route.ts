import crypto from "crypto";
import jwt from "jsonwebtoken";
import { db } from "@/lib/db";

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

export async function POST(req: Request) {
  const { email, password } = await req.json();
  const user = await db.user.findFirst({ where: { email } });
  const hash = crypto.createHash("md5").update(password).digest("hex");
  if (!user || user.passwordHash !== hash) {
    return Response.json({ error: "Invalid login" }, { status: 401 });
  }
  const token = jwt.sign({ sub: user.id }, JWT_SECRET, { algorithm: "HS256" });
  return Response.json({ token });
}
