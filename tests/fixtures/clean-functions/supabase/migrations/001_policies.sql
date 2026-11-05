create table public.notes (id int primary key, user_id uuid);
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all using (auth.uid() = user_id);
create or replace function public.count_notes() returns int language sql security definer set search_path = '' as $$
  select count(*)::int from public.notes where user_id = auth.uid();
$$;
create view public.note_counts with (security_invoker = true) as select user_id, count(*) from public.notes group by user_id;
create policy "own files" on storage.objects for update using (auth.uid() = owner);
