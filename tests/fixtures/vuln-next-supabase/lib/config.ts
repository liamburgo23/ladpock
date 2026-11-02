import cors from "cors";

export const stripeKey = "{{FAKE_STRIPE_SECRET}}";
export const corsMiddleware = cors({ origin: "*", credentials: true });
