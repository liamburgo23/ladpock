create table public.profiles (
  id uuid primary key references auth.users,
  username text
);
alter table public.profiles enable row level security;
create policy "Profiles are viewable by everyone" on public.profiles for select using (true);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users,
  total integer
);

create table public.notes (
  id bigint generated always as identity primary key,
  body text
);
alter table public.notes enable row level security;
create policy "Anyone can do anything with notes" on public.notes for all using (true) with check (true);
