import { createTRPCRouter } from "./trpc";
import { postRouter } from "./routers/post";
import { orderRouter } from "./routers/order";

export const appRouter = createTRPCRouter({
  post: postRouter,
  order: orderRouter,
});
export type AppRouter = typeof appRouter;
