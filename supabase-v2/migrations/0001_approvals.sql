-- approve-2fa v2: phone 2FA approvals for privileged agent actions and destructive decisions.
-- Fresh project only. Fixes the 8 known flaws of the Morgan Toolbox approval system
-- (D:\Vault\infra\security-architecture.md §7.3):
--   1 no client inserts at all (service role only, via the approval-request function)
--   2 AAL2 (and a TOTP verified AFTER the request was created) enforced in SQL, not page JS
--   3 the approver is a fixed row in `approvers`; sign-ups are disabled after setup (runbook)
--   4 exact-action binding: action_hash, recomputed server-side from the structured action
--   5 only sha256(secret) is stored; the secret travels in the URL #fragment
--   6 push text is built from the row by the function; CORS pinned; verifier credential required; rate limit below
--   7 single use (consumed_at, set atomically) and expiry enforced in every RPC
--   8 fresh project = fresh anon/service/VAPID keys
--
-- All functions use `set search_path = ''` and fully qualified names (pg_catalog is always searched implicitly).

-- ============================================================ tables

create table public.approvers (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  email      text not null,
  created_at timestamptz not null default now()
);
-- At most one approver. Inserted once by the service role (runbook step), never by a client.
create unique index approvers_single_row on public.approvers ((true));

create table public.approval_requests (
  request_id      uuid primary key default gen_random_uuid(),
  secret_hash     text not null check (secret_hash ~ '^[0-9a-f]{64}$'),
  kind            text not null check (kind in ('decision', 'action', 'pin-key')),
  ref             text not null check (length(ref) between 1 and 200),
  action_hash     text not null check (action_hash ~ '^[0-9a-f]{64}$'),
  summary         text not null check (length(summary) between 1 and 600),
  data_lost       text check (data_lost is null or length(data_lost) between 1 and 4000),
  detail          text check (detail is null or length(detail) <= 16000),  -- exact text/JSON that action_hash commits to
  status          text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'expired')),
  created_at      timestamptz not null default now(),
  expires_at      timestamptz not null default (now() + interval '10 minutes'),
  approved_by     uuid,
  approved_aal    text check (approved_aal is null or approved_aal = 'aal2'),
  approved_at     timestamptz,
  approved_totp_at timestamptz,          -- the TOTP verification time taken from the JWT amr claim
  consumed_at     timestamptz,
  constraint expiry_window check (expires_at > created_at and expires_at <= created_at + interval '15 minutes'),
  constraint decided_fields check (
    (status in ('approved', 'denied') and approved_by is not null and approved_aal = 'aal2' and approved_at is not null
       and approved_totp_at is not null)
    or (status in ('pending', 'expired') and approved_by is null and approved_aal is null and approved_at is null
       and approved_totp_at is null)),
  constraint consumed_only_approved check (consumed_at is null or status = 'approved'),
  constraint pin_key_shape check (kind <> 'pin-key' or ref ~ '^[0-9a-f]{64}$')
);
create index approval_requests_created on public.approval_requests (created_at);

create table public.push_subscriptions (
  id           bigint generated always as identity primary key,
  user_id      uuid not null references auth.users (id) on delete cascade,
  endpoint     text not null unique check (endpoint ~ '^https://' and length(endpoint) <= 1000),
  subscription jsonb not null,
  user_agent   text check (user_agent is null or length(user_agent) <= 400),
  is_active    boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  last_used_at timestamptz
);

-- ============================================================ lock-down

alter table public.approvers enable row level security;
alter table public.approval_requests enable row level security;
alter table public.push_subscriptions enable row level security;
-- No policies on purpose: anon/authenticated can't select, insert, update or delete any row. The phone reads and
-- decides only through get_request/decide_request below (security definer). The service role bypasses RLS.
revoke all on table public.approvers, public.approval_requests, public.push_subscriptions from public, anon, authenticated;
revoke all on sequence public.push_subscriptions_id_seq from public, anon, authenticated;

-- ============================================================ triggers

-- INSERT: the server decides status, timestamps and expiry, whatever the inserter sent. Global rate limit.
create or replace function public.approval_requests_before_insert()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.status := 'pending';
  new.created_at := now();
  new.expires_at := now() + interval '10 minutes';
  new.approved_by := null;
  new.approved_aal := null;
  new.approved_at := null;
  new.approved_totp_at := null;
  new.consumed_at := null;
  -- Serialise inserts so the counts below are exact (requests are rare; contention is not a concern).
  perform pg_catalog.pg_advisory_xact_lock(4242002);
  if (select count(*) from public.approval_requests r where r.created_at > now() - interval '10 minutes') >= 30 then
    raise exception 'approve-2fa: rate limit (30 requests per 10 minutes)' using errcode = '53400';
  end if;
  if (select count(*) from public.approval_requests r where r.status = 'pending' and r.expires_at > now()) >= 10 then
    raise exception 'approve-2fa: too many open requests (10)' using errcode = '53400';
  end if;
  return new;
end
$$;

create trigger approval_requests_before_insert
before insert on public.approval_requests
for each row execute function public.approval_requests_before_insert();

-- UPDATE: freeze what the approval is about; status only moves out of 'pending', once; decision fields are
-- server-stamped once; consumed_at goes null -> now() once, only on an approved row.
create or replace function public.approval_requests_before_update()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if new.request_id is distinct from old.request_id
     or new.kind is distinct from old.kind
     or new.ref is distinct from old.ref
     or new.action_hash is distinct from old.action_hash
     or new.summary is distinct from old.summary
     or new.data_lost is distinct from old.data_lost
     or new.detail is distinct from old.detail
     or new.expires_at is distinct from old.expires_at
     or new.secret_hash is distinct from old.secret_hash
     or new.created_at is distinct from old.created_at then
    raise exception 'approve-2fa: request content is frozen' using errcode = '42501';
  end if;

  if old.status <> 'pending' then
    if new.status is distinct from old.status
       or new.approved_by is distinct from old.approved_by
       or new.approved_aal is distinct from old.approved_aal
       or new.approved_at is distinct from old.approved_at
       or new.approved_totp_at is distinct from old.approved_totp_at then
      raise exception 'approve-2fa: a decided or expired request is final' using errcode = '42501';
    end if;
  elsif new.status in ('approved', 'denied') then
    if old.expires_at <= now() then
      raise exception 'approve-2fa: request expired' using errcode = '42501';
    end if;
    new.approved_at := now();   -- server time, whatever the updater sent
    if new.approved_totp_at is null or new.approved_totp_at > now() + interval '5 seconds' then
      raise exception 'approve-2fa: decision without a TOTP time' using errcode = '42501';
    end if;
  elsif new.status = 'expired' then
    if old.expires_at > now() then
      raise exception 'approve-2fa: not expired yet' using errcode = '42501';
    end if;
  end if;

  if old.consumed_at is not null and new.consumed_at is distinct from old.consumed_at then
    raise exception 'approve-2fa: already consumed' using errcode = '42501';
  end if;
  if old.consumed_at is null and new.consumed_at is not null then
    if old.status <> 'approved' then
      raise exception 'approve-2fa: only an approved request can be consumed' using errcode = '42501';
    end if;
    new.consumed_at := now();
  end if;
  return new;
end
$$;

create trigger approval_requests_before_update
before update on public.approval_requests
for each row execute function public.approval_requests_before_update();

-- DELETE: keep everything for 30 days (evidence), and never delete an open request.
create or replace function public.approval_requests_before_delete()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if old.created_at > now() - interval '30 days' then
    raise exception 'approve-2fa: requests are kept for 30 days' using errcode = '42501';
  end if;
  return old;
end
$$;

create trigger approval_requests_before_delete
before delete on public.approval_requests
for each row execute function public.approval_requests_before_delete();

revoke execute on function public.approval_requests_before_insert() from public, anon, authenticated;
revoke execute on function public.approval_requests_before_update() from public, anon, authenticated;
revoke execute on function public.approval_requests_before_delete() from public, anon, authenticated;

-- ============================================================ phone RPCs (authenticated only)

create or replace function public.secret_hash_of(p_secret text)
returns text
language sql
immutable
set search_path = ''
as $$
  select pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_secret, 'UTF8')), 'hex')
$$;
revoke execute on function public.secret_hash_of(text) from public, anon, authenticated;

-- Returns the request only to the approver holding the per-request secret. No row = unknown, wrong secret, or
-- not the approver (no oracle telling which).
create or replace function public.get_request(p_id uuid, p_secret text)
returns table (kind text, ref text, summary text, data_lost text, detail text, status text, expires_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  if auth.uid() is null or not exists (select 1 from public.approvers a where a.user_id = auth.uid()) then
    return;
  end if;
  if p_id is null or p_secret is null or length(p_secret) not between 32 and 128 then
    return;
  end if;
  return query
    select r.kind, r.ref, r.summary, r.data_lost, r.detail,
           case when r.status = 'pending' and r.expires_at <= now() then 'expired' else r.status end,
           r.expires_at
    from public.approval_requests r
    where r.request_id = p_id and r.secret_hash = public.secret_hash_of(p_secret);
end
$$;

-- The one way a request gets approved or denied. Requires: the fixed approver, an AAL2 session, a TOTP verified
-- AFTER the request was created (amr claim) and within the last 5 minutes, the secret, pending, not expired.
-- Returns the new status, or 'unavailable' (unknown / wrong secret / not pending / expired).
create or replace function public.decide_request(p_id uuid, p_secret text, p_decision text)
returns text
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_uid     uuid := auth.uid();
  v_jwt     jsonb := auth.jwt();
  v_totp_at timestamptz;
  v_created timestamptz;
  v_status  text;
begin
  if p_decision is null or p_decision not in ('approved', 'denied') then
    raise exception 'approve-2fa: decision must be approved or denied' using errcode = '22023';
  end if;
  if v_uid is null or not exists (select 1 from public.approvers a where a.user_id = v_uid) then
    raise exception 'approve-2fa: not the approver' using errcode = '42501';
  end if;
  if coalesce(v_jwt ->> 'aal', '') <> 'aal2' then
    raise exception 'approve-2fa: an AAL2 (TOTP-verified) session is required' using errcode = '42501';
  end if;
  if p_id is null or p_secret is null or length(p_secret) not between 32 and 128 then
    return 'unavailable';
  end if;

  -- Latest TOTP verification of this session (Supabase puts {method, timestamp} entries in the amr claim).
  select pg_catalog.to_timestamp(max((e ->> 'timestamp')::bigint))
    into v_totp_at
    from pg_catalog.jsonb_array_elements(coalesce(v_jwt -> 'amr', '[]'::jsonb)) e
    where e ->> 'method' = 'totp';

  select r.created_at into v_created
    from public.approval_requests r
    where r.request_id = p_id and r.secret_hash = public.secret_hash_of(p_secret)
      and r.status = 'pending' and r.expires_at > now()
    for update;
  if not found then
    update public.approval_requests r set status = 'expired'
      where r.request_id = p_id and r.secret_hash = public.secret_hash_of(p_secret)
        and r.status = 'pending' and r.expires_at <= now();
    return 'unavailable';
  end if;

  -- Per-approval TOTP: a session that was MFA-verified hours ago is not enough.
  if v_totp_at is null or v_totp_at < pg_catalog.date_trunc('second', v_created) or v_totp_at < now() - interval '5 minutes' then
    raise exception 'approve-2fa: enter a fresh authenticator code for this request' using errcode = '42501';
  end if;

  update public.approval_requests r
     set status = p_decision, approved_by = v_uid, approved_aal = 'aal2', approved_at = now(),
         approved_totp_at = v_totp_at
   where r.request_id = p_id
   returning r.status into v_status;
  return v_status;
end
$$;

revoke execute on function public.get_request(uuid, text) from public, anon;
revoke execute on function public.decide_request(uuid, text, text) from public, anon;
grant execute on function public.get_request(uuid, text) to authenticated;
grant execute on function public.decide_request(uuid, text, text) to authenticated;

-- ============================================================ verifier RPCs (service role only)

-- Atomic single use: marks the approval consumed and returns the facts to sign, or no row.
create or replace function public.consume_request(p_id uuid, p_kind text, p_ref text, p_action_hash text)
returns table (kind text, ref text, action_hash text, approver_uid uuid, verified_at text)
language plpgsql
volatile
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  return query
    with u as (
    update public.approval_requests r
       set consumed_at = now()
     where r.request_id = p_id
       and r.status = 'approved'
       and r.approved_aal = 'aal2'
       and r.consumed_at is null
       and r.expires_at > now()
       and r.kind = p_kind
       and r.ref = p_ref
       and r.action_hash = p_action_hash
       and exists (select 1 from public.approvers a where a.user_id = r.approved_by)
    returning r.kind, r.ref, r.action_hash, r.approved_by,
              pg_catalog.to_char(r.approved_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))
    select * from u;
end
$$;

-- Why a request can't be consumed (for the verifier's 202/409 answer). No secrets returned.
create or replace function public.request_state(p_id uuid, p_kind text default null, p_ref text default null,
                                                p_action_hash text default null)
returns table (status text, expires_at timestamptz, consumed boolean, matches boolean, kind text)
language sql
stable
security definer
set search_path = ''
as $$
  select case when r.status = 'pending' and r.expires_at <= now() then 'expired'
              when r.status = 'approved' and r.consumed_at is null and r.expires_at <= now() then 'expired'
              else r.status end,
         r.expires_at,
         r.consumed_at is not null,
         (p_kind is null or r.kind = p_kind) and (p_ref is null or r.ref = p_ref)
           and (p_action_hash is null or r.action_hash = p_action_hash),
         r.kind
  from public.approval_requests r
  where r.request_id = p_id
$$;

-- Marks stale pending rows expired (called by the functions opportunistically, or by pg_cron below).
create or replace function public.expire_stale_requests()
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare n integer;
begin
  update public.approval_requests r set status = 'expired'
   where r.status = 'pending' and r.expires_at <= now();
  get diagnostics n = row_count;
  return n;
end
$$;

revoke execute on function public.consume_request(uuid, text, text, text) from public, anon, authenticated;
revoke execute on function public.request_state(uuid, text, text, text) from public, anon, authenticated;
revoke execute on function public.expire_stale_requests() from public, anon, authenticated;
grant execute on function public.consume_request(uuid, text, text, text) to service_role;
grant execute on function public.request_state(uuid, text, text, text) to service_role;
grant execute on function public.expire_stale_requests() to service_role;

-- ============================================================ optional: pg_cron
-- Expiry is enforced in every RPC regardless; this only tidies the table. Enable pg_cron in the dashboard first.
-- select cron.schedule('approve-2fa-expire', '*/5 * * * *', $$select public.expire_stale_requests()$$);

comment on table public.approval_requests is 'approve-2fa: one row per phone approval. Service-role writes only; phone uses get_request/decide_request.';
comment on table public.approvers is 'approve-2fa: the single approver (Supabase auth uid). Inserted once by the service role.';
comment on table public.push_subscriptions is 'approve-2fa: web push subscriptions of the approver. Service role only.';
