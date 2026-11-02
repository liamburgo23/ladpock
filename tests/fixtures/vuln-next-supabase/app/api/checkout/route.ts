import Stripe from "stripe";
import { auth } from "@/lib/auth";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const session = await auth();
  const body = await req.json();
  const checkout = await stripe.checkout.sessions.create({
    line_items: [{ price_data: { currency: "usd", unit_amount: body.price, product_data: { name: body.name } }, quantity: 1 }],
    mode: "payment",
  });
  return Response.json({ url: checkout.url });
}
