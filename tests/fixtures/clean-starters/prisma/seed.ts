import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
await prisma.post.create({ data: { name: "Hello world" } });
