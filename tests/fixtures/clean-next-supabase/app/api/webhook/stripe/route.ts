import Stripe from "stripe";
import { headers } from "next/headers";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();
  const signature = (await headers()).get("stripe-signature")!;
  const event = stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET!);
  if (event.type === "checkout.session.completed") {
    // fulfil the order
  }
  return new Response("ok");
}
