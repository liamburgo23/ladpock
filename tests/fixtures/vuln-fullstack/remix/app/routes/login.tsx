import { redirect } from '@remix-run/node';
import { db } from '~/db.server';

export async function action({ request }) {
  const form = await request.formData();
  const user = await db.user.findFirst({ where: { email: form.get('email') } });
  return user ? redirect('/') : null;
}

export default function Login() {
  return null;
}
