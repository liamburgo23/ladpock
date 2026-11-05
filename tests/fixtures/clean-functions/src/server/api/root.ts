import { createTRPCRouter } from "./trpc";
import { orderRouter } from "./routers/order";

export const appRouter = createTRPCRouter({
  order: orderRouter,
});
