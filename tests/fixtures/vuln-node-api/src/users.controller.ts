import { Body, Controller, Delete, Param, Post, UseGuards } from "@nestjs/common";
import { JwtAuthGuard } from "./jwt.guard";
import { PrismaService } from "./prisma.service";

@Controller("users")
export class UsersController {
  constructor(private readonly prisma: PrismaService) {}

  @Post()
  async create(@Body() body: any) {
    return this.prisma.user.create({ data: body });
  }

  @UseGuards(JwtAuthGuard)
  @Delete(":id")
  async remove(@Param("id") id: string) {
    return this.prisma.user.delete({ where: { id } });
  }
}
