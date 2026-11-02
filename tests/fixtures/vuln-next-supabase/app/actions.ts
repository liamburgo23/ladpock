"use server";

import { db } from "@/lib/db";

export async function deleteAccount(formData: FormData) {
  const id = formData.get("id") as string;
  await db.user.delete({ where: { id } });
}
