export function Admin({ session }) {
  if (session.user.role !== "admin") return null;
  return <div />;
}
