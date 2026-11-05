create table public.notes (id int primary key, user_id uuid);
alter table public.notes enable row level security;
create policy "any signed in" on public.notes for update using (auth.role() = 'authenticated');
create policy "read all signed in" on public.notes for select to authenticated using (true);
create or replace function public.grant_admin(target uuid) returns void language plpgsql security definer as $$
begin
  update public.users set role = 'admin' where id = target;
end;
$$;
create view public.people as select id, email from auth.users;
create view public.note_counts as select user_id, count(*) from public.notes group by user_id;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "anyone can replace files" on storage.objects for update using (bucket_id = 'avatars');
