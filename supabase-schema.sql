-- Run this script in the Supabase SQL Editor to create the app schema and access policies.
create extension if not exists pgcrypto;

create table if not exists public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(trim(name)) between 1 and 60),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('supervisor', 'member')),
  created_at timestamptz not null default now(),
  primary key (workspace_id, user_id),
  unique (user_id)
);

create table if not exists public.workspace_data (
  workspace_id uuid primary key references public.workspaces(id) on delete cascade,
  data jsonb not null default '{"rooms":[],"workspaceName":"مساحة فريقي"}'::jsonb,
  updated_at timestamptz not null default now()
);

create or replace function public.is_workspace_member(target_workspace uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.workspace_members
    where workspace_id = target_workspace
      and user_id = auth.uid()
  );
$$;

create or replace function public.is_workspace_supervisor(target_workspace uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.workspace_members
    where workspace_id = target_workspace
      and user_id = auth.uid()
      and role = 'supervisor'
  );
$$;

create or replace function public.create_workspace(workspace_name text)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  new_workspace_id uuid;
  clean_name text := trim(coalesce(workspace_name, ''));
begin
  if auth.uid() is null then
    raise exception 'يجب تسجيل الدخول لإنشاء مساحة عمل.';
  end if;
  if char_length(clean_name) < 1 or char_length(clean_name) > 60 then
    raise exception 'اسم مساحة العمل يجب أن يكون بين حرف و60 حرفاً.';
  end if;
  if exists (select 1 from public.workspace_members where user_id = auth.uid()) then
    raise exception 'هذا الحساب مرتبط بمساحة عمل بالفعل.';
  end if;

  insert into public.workspaces (name, created_by)
  values (clean_name, auth.uid())
  returning id into new_workspace_id;

  insert into public.workspace_members (workspace_id, user_id, role)
  values (new_workspace_id, auth.uid(), 'supervisor');

  insert into public.workspace_data (workspace_id, data)
  values (new_workspace_id, jsonb_build_object('workspaceName', clean_name, 'rooms', '[]'::jsonb));

  return new_workspace_id;
end;
$$;

create or replace function public.join_workspace(target_workspace uuid)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'يجب تسجيل الدخول للانضمام إلى مساحة عمل.';
  end if;
  if not exists (select 1 from public.workspaces where id = target_workspace) then
    raise exception 'رمز مساحة العمل غير صحيح.';
  end if;
  if exists (
    select 1 from public.workspace_members
    where user_id = auth.uid() and workspace_id <> target_workspace
  ) then
    raise exception 'هذا الحساب مرتبط بمساحة عمل أخرى.';
  end if;

  insert into public.workspace_members (workspace_id, user_id, role)
  values (target_workspace, auth.uid(), 'member')
  on conflict (workspace_id, user_id) do nothing;

  return target_workspace;
end;
$$;

revoke all on function public.is_workspace_member(uuid) from public;
revoke all on function public.is_workspace_supervisor(uuid) from public;
revoke all on function public.create_workspace(text) from public;
revoke all on function public.join_workspace(uuid) from public;
grant execute on function public.is_workspace_member(uuid) to authenticated;
grant execute on function public.is_workspace_supervisor(uuid) to authenticated;
grant execute on function public.create_workspace(text) to authenticated;
grant execute on function public.join_workspace(uuid) to authenticated;

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.workspace_data enable row level security;

drop policy if exists "Members can view their workspace" on public.workspaces;
create policy "Members can view their workspace"
  on public.workspaces for select to authenticated
  using (public.is_workspace_member(id));

drop policy if exists "Supervisors can update their workspace" on public.workspaces;
create policy "Supervisors can update their workspace"
  on public.workspaces for update to authenticated
  using (public.is_workspace_supervisor(id))
  with check (public.is_workspace_supervisor(id));

drop policy if exists "Members can view workspace membership" on public.workspace_members;
create policy "Members can view workspace membership"
  on public.workspace_members for select to authenticated
  using (user_id = auth.uid() or public.is_workspace_member(workspace_id));

drop policy if exists "Members can view shared workspace data" on public.workspace_data;
create policy "Members can view shared workspace data"
  on public.workspace_data for select to authenticated
  using (public.is_workspace_member(workspace_id));

drop policy if exists "Members can create shared workspace data" on public.workspace_data;
create policy "Members can create shared workspace data"
  on public.workspace_data for insert to authenticated
  with check (public.is_workspace_member(workspace_id));

drop policy if exists "Members can update shared workspace data" on public.workspace_data;
create policy "Members can update shared workspace data"
  on public.workspace_data for update to authenticated
  using (public.is_workspace_member(workspace_id))
  with check (public.is_workspace_member(workspace_id));

grant select, update (name) on public.workspaces to authenticated;
grant select on public.workspace_members to authenticated;
grant select, insert, update on public.workspace_data to authenticated;

do $$
begin
  alter publication supabase_realtime add table public.workspace_data;
exception
  when duplicate_object then null;
end;
$$;
