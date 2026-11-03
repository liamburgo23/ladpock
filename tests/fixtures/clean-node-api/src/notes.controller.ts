import { Body, Controller, Delete, Param, Post, UseGuards } from "@nestjs/common";
import { JwtAuthGuard } from "./jwt.guard";
import { CurrentUser } from "./current-user.decorator";
import { CreateNoteDto } from "./dto";
import { PrismaService } from "./prisma.service";

@UseGuards(JwtAuthGuard)
@Controller("notes")
export class NotesController {
  constructor(private readonly prisma: PrismaService) {}

  @Post()
  async create(@Body() dto: CreateNoteDto, @CurrentUser() user: { id: string }) {
    return this.prisma.note.create({ data: { text: dto.text, ownerId: user.id } });
  }

  @Delete(":id")
  async remove(@Param("id") id: string, @CurrentUser() user: { id: string }) {
    return this.prisma.note.deleteMany({ where: { id, ownerId: user.id } });
  }
}
