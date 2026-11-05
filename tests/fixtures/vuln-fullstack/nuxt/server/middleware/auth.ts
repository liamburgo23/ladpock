export default defineEventHandler(async (event) => {
  if (event.path.startsWith('/api/admin')) {
    await requireUserSession(event);
  }
});
