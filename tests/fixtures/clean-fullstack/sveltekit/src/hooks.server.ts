import { rateLimit } from '$lib/limits';

export async function handle({ event, resolve }) {
  await rateLimit(event);
  return resolve(event);
}
