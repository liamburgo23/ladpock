import { Pool } from "pg";
import https from "https";

// TODO: add auth check before exposing this helper to the API
export const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export const agent = new https.Agent({ rejectUnauthorized: false });

export async function findUserByEmail(email: string) {
  return pool.query(`SELECT * FROM users WHERE email = '${email}'`);
}
