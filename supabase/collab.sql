-- ============================================================
-- 班務通：多人共編（Supabase → SQL Editor → New query → 貼上 → Run）
-- 可重複執行，不會出錯，也不會動到現有資料。
-- 做了這些事：
--   1. 新增「共編成員」資料表 app_members
--   2. 把資料表 app_docs 的權限，從「只有本人」改成「本人＋被加入的成員」
--   3. 新增合併寫入函式（兩個人同時改同一份點名，不會互相蓋掉）
--   4. 新增加入／移除成員、離開共編等函式
--   5. 照片資料夾的權限同步改成「本人＋成員」
-- ============================================================

-- 1) 共編成員：owner（管理者）的資料可以讓 member（成員）一起讀寫
create table if not exists public.app_members (
  owner uuid not null references auth.users(id) on delete cascade,
  member uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (owner, member),
  check (owner <> member)
);
-- 一個帳號最多加入一個共用空間
create unique index if not exists app_members_one_space on public.app_members (member);
alter table public.app_members enable row level security;

drop policy if exists "see my memberships" on public.app_members;
create policy "see my memberships" on public.app_members
  for select to authenticated
  using (owner = (select auth.uid()) or member = (select auth.uid()));
-- 不開放直接新增／修改／刪除，只能透過下面的函式

-- 2) app_docs：本人或同一個共用空間的成員都能讀寫
drop policy if exists "own rows" on public.app_docs;
drop policy if exists "workspace rows" on public.app_docs;
create policy "workspace rows" on public.app_docs
  for all to authenticated
  using (
    owner = (select auth.uid())
    or owner in (select m.owner from public.app_members m where m.member = (select auth.uid()))
  )
  with check (
    owner = (select auth.uid())
    or owner in (select m.owner from public.app_members m where m.member = (select auth.uid()))
  );

-- 3) 合併寫入：把「修改的部分」合併進文件，而不是整份覆蓋（規則與 App 內相同：物件逐層合併，陣列與文字數字整個取代）
create or replace function public.app_jsonb_merge(a jsonb, b jsonb)
returns jsonb
language plpgsql
immutable
as $$
declare
  r jsonb;
  k text;
  v jsonb;
begin
  if jsonb_typeof(a) is distinct from 'object' or jsonb_typeof(b) is distinct from 'object' then
    return b;
  end if;
  r := a;
  for k, v in select key, value from jsonb_each(b) loop
    if jsonb_typeof(v) = 'object' and jsonb_typeof(r -> k) = 'object' then
      r := jsonb_set(r, array[k], public.app_jsonb_merge(r -> k, v), true);
    else
      r := jsonb_set(r, array[k], v, true);
    end if;
  end loop;
  return r;
end;
$$;

create or replace function public.app_patch(p_owner uuid, p_col text, p_id text, p_patch jsonb)
returns jsonb
language plpgsql
security invoker
set search_path = public
as $$
declare
  r jsonb;
begin
  insert into public.app_docs as d (owner, col, id, data, updated_at)
  values (p_owner, p_col, p_id, coalesce(p_patch, '{}'::jsonb), now())
  on conflict (owner, col, id) do update
    set data = public.app_jsonb_merge(d.data, excluded.data),
        updated_at = now()
  returning d.data into r;
  return r;
end;
$$;

-- 4) 共編管理
-- 我屬於哪個共用空間？（成員 → 回傳管理者；否則我自己就是管理者）
create or replace function public.app_workspace()
returns jsonb
language sql
stable
security definer
set search_path = public, auth
as $$
  select coalesce(
    (select jsonb_build_object('owner', m.owner, 'role', 'member', 'owner_email', u.email)
       from public.app_members m join auth.users u on u.id = m.owner
      where m.member = auth.uid() limit 1),
    jsonb_build_object('owner', auth.uid(), 'role', 'owner',
                       'owner_email', (select email from auth.users where id = auth.uid()))
  );
$$;

create or replace function public.app_members_list()
returns table (member uuid, email text, created_at timestamptz)
language sql
stable
security definer
set search_path = public, auth
as $$
  select m.member, u.email::text, m.created_at
    from public.app_members m join auth.users u on u.id = m.member
   where m.owner = auth.uid()
   order by m.created_at;
$$;

-- 用電子郵件把已建立好的帳號加進我的共用空間
create or replace function public.app_member_add(p_email text)
returns text
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  me uuid := auth.uid();
  u uuid;
begin
  if me is null then raise exception 'not_logged_in'; end if;
  if exists (select 1 from public.app_members where member = me) then raise exception 'is_member'; end if;
  select id into u from auth.users where lower(email) = lower(trim(p_email)) limit 1;
  if u is null then raise exception 'no_user'; end if;
  if u = me then raise exception 'self'; end if;
  if exists (select 1 from public.app_members where member = u) then raise exception 'already_member'; end if;
  if exists (select 1 from public.app_members where owner = u) then raise exception 'is_owner'; end if;
  insert into public.app_members (owner, member) values (me, u);
  return u::text;
end;
$$;

create or replace function public.app_member_remove(p_member uuid)
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.app_members where owner = auth.uid() and member = p_member;
$$;

create or replace function public.app_leave()
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.app_members where member = auth.uid();
$$;

revoke all on function public.app_patch(uuid, text, text, jsonb) from public, anon;
revoke all on function public.app_workspace() from public, anon;
revoke all on function public.app_members_list() from public, anon;
revoke all on function public.app_member_add(text) from public, anon;
revoke all on function public.app_member_remove(uuid) from public, anon;
revoke all on function public.app_leave() from public, anon;
grant execute on function public.app_patch(uuid, text, text, jsonb) to authenticated;
grant execute on function public.app_workspace() to authenticated;
grant execute on function public.app_members_list() to authenticated;
grant execute on function public.app_member_add(text) to authenticated;
grant execute on function public.app_member_remove(uuid) to authenticated;
grant execute on function public.app_leave() to authenticated;

-- 5) 照片（bucket 名稱 scans）：本人或同一共用空間的成員可讀寫管理者資料夾
drop policy if exists "scans read own" on storage.objects;
drop policy if exists "scans insert own" on storage.objects;
drop policy if exists "scans delete own" on storage.objects;
drop policy if exists "scans read ws" on storage.objects;
drop policy if exists "scans insert ws" on storage.objects;
drop policy if exists "scans delete ws" on storage.objects;

create policy "scans read ws" on storage.objects for select to authenticated
  using (bucket_id = 'scans' and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or (storage.foldername(name))[1] in (select m.owner::text from public.app_members m where m.member = (select auth.uid()))
  ));
create policy "scans insert ws" on storage.objects for insert to authenticated
  with check (bucket_id = 'scans' and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or (storage.foldername(name))[1] in (select m.owner::text from public.app_members m where m.member = (select auth.uid()))
  ));
create policy "scans delete ws" on storage.objects for delete to authenticated
  using (bucket_id = 'scans' and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or (storage.foldername(name))[1] in (select m.owner::text from public.app_members m where m.member = (select auth.uid()))
  ));
