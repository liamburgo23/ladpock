import { redirect } from "next/navigation";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const preview = await fetch(searchParams.get("url")!);
  redirect(searchParams.get("next")!);
}
