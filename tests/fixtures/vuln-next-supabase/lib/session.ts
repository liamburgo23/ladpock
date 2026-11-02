import jwt from "jsonwebtoken";
import { cookies } from "next/headers";

export function readToken(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET!, { ignoreExpiration: true });
}

export async function setSessionCookie(value: string) {
  (await cookies()).set("session", value, { httpOnly: false, secure: false });
}
