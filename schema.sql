-- ============================================================
-- 2AM v1 schema — Supabase (Postgres + Auth + Realtime)
-- Week-one scope only: login -> intent -> match -> session -> rate.
-- Assumptions: GitHub OAuth via Supabase Auth; RLS on everywhere;
-- sessions are P2P (no server media); timer + rating are client-driven,
-- this schema is the source of truth they read/write.
-- ============================================================

-- ---------- profiles ----------
-- One row per builder, created on first GitHub login (trigger below).
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  github_username text,
  display_name text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "profiles_read_all"
  on public.profiles for select
  to authenticated
  using (true);

create policy "profiles_update_own"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, github_username, display_name)
  values (
    new.id,
    new.raw_user_meta_data ->> 'user_name',
    coalesce(new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'user_name')
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- intents ----------
-- The two dropdowns on the landing widget: WHAT you're building
-- (project_kind) and WHO you want beside you (need_kind).
-- skill_kind is intentionally a tiny closed enum for v1 — the matcher
-- only has to complement across four buckets, exactly what the page
-- promises ("Devs · PMs · Designers · Founders").
do $$
begin
  if not exists (select 1 from pg_type where typname = 'skill_kind') then
    create type public.skill_kind as enum ('dev', 'pm', 'design', 'founder');
  end if;
  if not exists (select 1 from pg_type where typname = 'intent_status') then
    create type public.intent_status as enum ('waiting', 'matched', 'cancelled', 'expired');
  end if;
end
$$;

create table if not exists public.intents (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid not null references public.profiles (id) on delete cascade,
  project_text text not null,          -- "one clear line", e.g. "a fitness app"
  have_kind public.skill_kind not null, -- what this builder brings
  need_kind public.skill_kind not null, -- who they want beside them
  status public.intent_status not null default 'waiting',
  created_at timestamptz not null default now(),
  constraint intents_complementary check (have_kind <> need_kind)
);

alter table public.intents enable row level security;

create policy "intents_read_own"
  on public.intents for select
  to authenticated
  using (auth.uid() = profile_id);

create policy "intents_insert_own"
  on public.intents for insert
  to authenticated
  with check (auth.uid() = profile_id);

create policy "intents_update_own"
  on public.intents for update
  to authenticated
  using (auth.uid() = profile_id);

create index if not exists intents_waiting_idx
  on public.intents (status, created_at)
  where status = 'waiting';

-- ---------- presence ----------
-- One row per online builder, heartbeat-updated by the client every
-- ~20s. A row newer than 60s means "online right now" (the 23-online
-- pill and the matcher's candidate pool). Realtime enabled so the
-- lobby count ticks live.
create table if not exists public.presence (
  profile_id uuid primary key references public.profiles (id) on delete cascade,
  last_seen_at timestamptz not null default now()
);

alter table public.presence enable row level security;

create policy "presence_read_all"
  on public.presence for select
  to authenticated
  using (true);

create policy "presence_write_own"
  on public.presence for all
  to authenticated
  using (auth.uid() = profile_id)
  with check (auth.uid() = profile_id);

-- ---------- sessions ----------
-- A matched 25-minute P2P session. started_at starts the shared
-- countdown; ended_at is set by whichever client sees the timer hit
-- zero first (idempotent). state is deliberately tiny for v1.
do $$
begin
  if not exists (select 1 from pg_type where typname = 'session_state') then
    create type public.session_state as enum ('live', 'ended');
  end if;
end
$$;

create table if not exists public.sessions (
  id uuid primary key default gen_random_uuid(),
  intent_a_id uuid not null references public.intents (id),
  intent_b_id uuid not null references public.intents (id),
  profile_a_id uuid not null references public.profiles (id),
  profile_b_id uuid not null references public.profiles (id),
  state public.session_state not null default 'live',
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  constraint sessions_two_distinct_profiles check (profile_a_id <> profile_b_id)
);

alter table public.sessions enable row level security;

create policy "sessions_read_participants"
  on public.sessions for select
  to authenticated
  using (auth.uid() = profile_a_id or auth.uid() = profile_b_id);

create policy "sessions_end_participants"
  on public.sessions for update
  to authenticated
  using (auth.uid() = profile_a_id or auth.uid() = profile_b_id);

-- ---------- ratings → partnerships ----------
-- After every session both builders answer one question.
-- would_pair_again = the "build together again?" tap.
-- Two yeses on the same session => a row in partnerships
-- ("saved to your people"), written by the rating trigger below.
create table if not exists public.ratings (
  session_id uuid not null references public.sessions (id) on delete cascade,
  rater_id uuid not null references public.profiles (id) on delete cascade,
  would_pair_again boolean not null,
  created_at timestamptz not null default now(),
  primary key (session_id, rater_id)
);

alter table public.ratings enable row level security;

create policy "ratings_read_participants"
  on public.ratings for select
  to authenticated
  using (
    exists (
      select 1 from public.sessions s
      where s.id = ratings.session_id
        and (s.profile_a_id = auth.uid() or s.profile_b_id = auth.uid())
    )
  );

create policy "ratings_insert_self"
  on public.ratings for insert
  to authenticated
  with check (auth.uid() = rater_id);

create table if not exists public.partnerships (
  id uuid primary key default gen_random_uuid(),
  profile_a_id uuid not null references public.profiles (id) on delete cascade,
  profile_b_id uuid not null references public.profiles (id) on delete cascade,
  session_id uuid not null references public.sessions (id),
  created_at timestamptz not null default now(),
  constraint partnerships_distinct check (profile_a_id <> profile_b_id),
  constraint partnerships_ordered check (profile_a_id < profile_b_id),
  unique (profile_a_id, profile_b_id)
);

alter table public.partnerships enable row level security;

create policy "partnerships_read_own"
  on public.partnerships for select
  to authenticated
  using (auth.uid() = profile_a_id or auth.uid() = profile_b_id);

-- Mutual yes => saved partnership. Ordered pair keeps one row per duo.
create or replace function public.maybe_create_partnership()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  other_id uuid;
  other_yes boolean;
  sess uuid;
begin
  sess := new.session_id;
  select case when s.profile_a_id = new.rater_id then s.profile_b_id else s.profile_a_id end
    into other_id
    from public.sessions s
    where s.id = sess;

  select exists (
    select 1 from public.ratings r
    where r.session_id = sess
      and r.rater_id = other_id
      and r.would_pair_again
  ) into other_yes;

  if new.would_pair_again and other_yes then
    insert into public.partnerships (profile_a_id, profile_b_id, session_id)
    values (
      least(new.rater_id, other_id),
      greatest(new.rater_id, other_id),
      sess
    )
    on conflict (profile_a_id, profile_b_id) do nothing;
  end if;

  return new;
end;
$$;

drop trigger if exists ratings_mutual_yes on public.ratings;
create trigger ratings_mutual_yes
  after insert on public.ratings
  for each row execute function public.maybe_create_partnership();

-- ============================================================
-- THE HEART: match_make()
-- Called by the matching Edge Function with the caller's waiting
-- intent id. Finds the oldest waiting complementary intent from a
-- *currently online* builder (presence < 60s), pairs have<>need both
-- ways, never self, never the same duo twice in a row. Locks the
-- partner row (FOR UPDATE SKIP LOCKED) so concurrent matchers can't
-- double-book. Marks both intents matched and opens the session.
-- Returns the session id + partner profile id, or NULL when nobody
-- is available yet (client keeps polling / waiting state).
-- ============================================================
create or replace function public.match_make(p_intent_id uuid)
returns table (session_id uuid, partner_profile_id uuid)
language plpgsql
security definer set search_path = public
as $$
declare
  mine public.intents%rowtype;
  partner public.intents%rowtype;
  new_session_id uuid;
begin
  select * into mine
  from public.intents
  where id = p_intent_id
    and profile_id = auth.uid()
    and status = 'waiting'
  for update;

  if not found then
    return; -- nothing to match (or not yours): stay waiting
  end if;

  select pi.* into partner
  from public.intents pi
  join public.presence pr
    on pr.profile_id = pi.profile_id
   and pr.last_seen_at > now() - interval '60 seconds'
  where pi.status = 'waiting'
    and pi.profile_id <> mine.profile_id
    and pi.have_kind = mine.need_kind   -- they bring what you lack
    and pi.need_kind = mine.have_kind   -- you bring what they lack
    and not exists (                    -- not the duo you just rated yes
      select 1 from public.partnerships ps
      where (ps.profile_a_id = mine.profile_id and ps.profile_b_id = pi.profile_id)
         or (ps.profile_a_id = pi.profile_id and ps.profile_b_id = mine.profile_id)
    )
  order by pi.created_at asc
  limit 1
  for update of pi skip locked;

  if not found then
    return; -- nobody right now: client stays in "matching live"
  end if;

  update public.intents set status = 'matched' where id in (mine.id, partner.id);

  insert into public.sessions (intent_a_id, intent_b_id, profile_a_id, profile_b_id)
  values (mine.id, partner.id, mine.profile_id, partner.profile_id)
  returning id into new_session_id;

  delete from public.presence where profile_id in (mine.profile_id, partner.profile_id);

  session_id := new_session_id;
  partner_profile_id := partner.profile_id;
  return next;
end;
$$;
