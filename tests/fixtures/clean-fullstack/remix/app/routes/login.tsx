import { redirect } from '@remix-run/node';
import { z } from 'zod';
import { signIn } from '~/auth.server';
import { rateLimit } from '~/limits.server';

const Credentials = z.object({ email: z.string().email(), password: z.string() });

export async function action({ request }) {
  await rateLimit(request);
  const form = Credentials.parse(Object.fromEntries(await request.formData()));
  await signIn(form);
  return redirect('/');
}

export default function Login() {
  return null;
}
