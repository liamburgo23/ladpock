import Stripe from "stripe";
import { db } from "@/server/db";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const body = await request.text();
  const signature = request.headers.get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === "checkout.session.completed") {
    await db.subscription.update({ where: { customerId: event.data.object.customer as string }, data: { active: true } });
  }
  return new Response(null, { status: 200 });
}
