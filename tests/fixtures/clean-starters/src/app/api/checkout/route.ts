import Stripe from "stripe";
import { getServerSession } from "next-auth";
import { authOptions } from "@/server/auth";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST() {
  const session = await getServerSession(authOptions);
  if (!session) return new Response("Unauthorized", { status: 401 });
  const checkout = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: process.env.STRIPE_PRICE_ID!, quantity: 1 }],
    success_url: `${process.env.APP_URL}/thanks?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.APP_URL}/pricing`,
    client_reference_id: session.user.id,
  });
  return Response.json({ url: checkout.url });
}
