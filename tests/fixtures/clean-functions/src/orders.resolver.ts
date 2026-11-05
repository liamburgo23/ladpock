import { Resolver, Mutation, UseGuards } from "@nestjs/graphql";

@Resolver()
export class OrdersResolver {
  @UseGuards(GqlAuthGuard)
  @Mutation(() => Order)
  async cancelOrder(@Args("id") id: string, @CurrentUser() user: User) {
    return this.db.order.updateMany({ where: { id, userId: user.id }, data: { cancelled: true } });
  }
}
