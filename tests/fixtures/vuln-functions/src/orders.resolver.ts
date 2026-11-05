import { Resolver, Query, Mutation } from "@nestjs/graphql";

@Resolver()
export class OrdersResolver {
  @Query(() => Order)
  async order(@Args("id") id: string) {
    return this.db.order.findUnique({ where: { id } });
  }

  @Mutation(() => Order)
  async cancelOrder(@Args("id") id: string) {
    return this.db.order.update({ where: { id }, data: { cancelled: true } });
  }
}
