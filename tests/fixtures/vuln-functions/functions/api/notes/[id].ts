export const onRequestDelete = async (context) => {
  await context.env.DB.prepare("DELETE FROM notes WHERE id = ?").bind(context.params.id).run();
  return new Response(null, { status: 204 });
};
