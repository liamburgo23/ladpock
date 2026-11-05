create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users on delete cascade,
  title text not null
);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);

create table public.posts (id uuid primary key default gen_random_uuid(), title text);
alter table public.posts enable row level security;
create policy "read published" on public.posts for select to anon using (true);

create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

insert into storage.buckets (id, name) values ('receipts', 'receipts');
create policy "own receipts" on storage.objects for insert to authenticated with check (bucket_id = 'receipts' and owner = auth.uid());
