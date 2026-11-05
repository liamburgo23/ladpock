import { z } from "zod";

const schema = z.object({
  DATABASE_URL: z.string().url(),
  NEXTAUTH_SECRET: z.string().min(32),
  NODE_ENV: z.enum(["development", "test", "production"]),
});
export const env = schema.parse(process.env);
