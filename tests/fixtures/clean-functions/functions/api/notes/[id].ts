export const onRequestDelete = async (context) => {
  const user = context.data.user;
  if (!user) return new Response(null, { status: 401 });
  await context.env.DB.prepare("DELETE FROM notes WHERE id = ? AND user_id = ?").bind(context.params.id, user.id).run();
  return new Response(null, { status: 204 });
};
