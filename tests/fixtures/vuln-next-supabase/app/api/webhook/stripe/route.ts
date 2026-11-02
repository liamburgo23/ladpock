import Stripe from "stripe";
import { db } from "@/lib/db";

export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === "checkout.session.completed") {
    await db.order.update({ where: { id: event.data.object.metadata.orderId }, data: { paid: true } });
  }
  return new Response("ok");
}
