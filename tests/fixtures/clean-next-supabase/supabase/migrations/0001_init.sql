create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users,
  total integer not null
);
alter table public.orders enable row level security;
create policy "Users read their own orders" on public.orders for select using (auth.uid() = user_id);

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users,
  body text
);
alter table public.notes enable row level security;
create policy "Users manage their own notes" on public.notes
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
