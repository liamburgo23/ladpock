import { PrismaAdapter } from "@auth/prisma-adapter";
import GithubProvider from "next-auth/providers/github";
import { env } from "../env";
import { db } from "./db";

export const authOptions = {
  adapter: PrismaAdapter(db),
  secret: env.NEXTAUTH_SECRET,
  session: { strategy: "database" },
  callbacks: {
    session: ({ session, user }) => ({ ...session, user: { ...session.user, id: user.id, role: user.role } }),
  },
  providers: [GithubProvider({ clientId: env.GITHUB_ID, clientSecret: env.GITHUB_SECRET })],
};
