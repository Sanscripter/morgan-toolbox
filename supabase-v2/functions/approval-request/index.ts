// approve-2fa: create an approval request (verifier only) and register phone push subscriptions (approver only).
//
// POST, header x-verifier-key: VERIFIER_KEY. Body:
//   {kind:'decision', ref, action_hash, decision:{question, options, answer, data_lost, answered_at}}
//       The function rebuilds homelab-db's canonical decision text from these fields and refuses the request
//       unless sha256 -> digest -> action_hash equals the given action_hash. The phone summary and data_lost are
//       taken from those same fields, so what the user reads is exactly what gets signed.
//   {kind:'action', ref, action_hash, action:<JSON object>, summary, data_lost?}
//       action_hash must equal sha256(canonical JSON of action). summary is the requester's description;
//       the phone also shows the exact canonical JSON.
//   {kind:'pin-key', ref:<new key fpr>, action_hash}
//       action_hash must equal sha256('{"fpr":"<ref>","kind":"pin-key","ns":"approve-2fa"}'); the summary is fixed.
//   -> 200 {request_id, expires_at, pushed, approval_url?}   (approval_url only when ALLOW_LINK_FALLBACK=true)
//
// POST {op:'subscribe', subscription} with the approver's user JWT (AAL2) in Authorization: stores a web push
//   subscription. Browser-only path; CORS allows PAGE_ORIGIN only.
//
// Env (function secrets): VERIFIER_KEY, PAGE_ORIGIN, PAGE_URL, WEB_PUSH_PUBLIC_KEY, WEB_PUSH_PRIVATE_KEY,
//   WEB_PUSH_SUBJECT, ALLOW_LINK_FALLBACK (default false). SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY are injected.
// Deploy with --no-verify-jwt (auth is done here: verifier key, or the user JWT checked via auth.getUser).

import { createClient } from 'npm:@supabase/supabase-js@2.45.4'
import webpush from 'npm:web-push@3.6.7'
import {
  actionHashOf, canonicalJson, cleanText, decisionActionHash, decisionText, KINDS, pinKeyActionHash,
  pinKeyMessage, randomSecret, RE_HEX64, RE_REF, sha256Hex, timingSafeEqual,
} from '../_shared/approve2fa.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const VERIFIER_KEY = Deno.env.get('VERIFIER_KEY') ?? ''
const PAGE_ORIGIN = Deno.env.get('PAGE_ORIGIN') ?? ''
const PAGE_URL = Deno.env.get('PAGE_URL') ?? ''
const VAPID_PUBLIC = Deno.env.get('WEB_PUSH_PUBLIC_KEY') ?? ''
const VAPID_PRIVATE = Deno.env.get('WEB_PUSH_PRIVATE_KEY') ?? ''
const VAPID_SUBJECT = Deno.env.get('WEB_PUSH_SUBJECT') ?? ''
const ALLOW_LINK_FALLBACK = (Deno.env.get('ALLOW_LINK_FALLBACK') ?? 'false').toLowerCase() === 'true'

const MAX_BODY = 64 * 1024
const MAX_SUBSCRIPTIONS = 5

if (VAPID_PUBLIC && VAPID_PRIVATE && VAPID_SUBJECT) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE)
}

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
})

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get('origin') ?? ''
  if (PAGE_ORIGIN && origin === PAGE_ORIGIN) {
    return {
      'Access-Control-Allow-Origin': PAGE_ORIGIN,
      'Access-Control-Allow-Headers': 'authorization, apikey, content-type, x-client-info',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Max-Age': '600',
      Vary: 'Origin',
    }
  }
  return { Vary: 'Origin' }
}

function json(req: Request, status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders(req) },
  })
}

async function readBody(req: Request): Promise<Record<string, unknown> | null> {
  const text = await req.text()
  if (text.length > MAX_BODY) return null
  try {
    const v = JSON.parse(text)
    return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : null
  } catch {
    return null
  }
}

function str(v: unknown, max: number, allowEmpty = false): string | null {
  if (typeof v !== 'string') return null
  if (!allowEmpty && v.length === 0) return null
  if (v.length > max) return null
  return v
}

async function verifierOk(req: Request): Promise<boolean> {
  // The verifier key never lives in a browser: refuse it on any request that carries an Origin header.
  if (req.headers.get('origin')) return false
  if (VERIFIER_KEY.length < 32) return false // fail closed when the secret is unset or weak
  return await timingSafeEqual(req.headers.get('x-verifier-key') ?? '', VERIFIER_KEY)
}

async function approverId(): Promise<string | null> {
  const { data, error } = await admin.from('approvers').select('user_id').limit(2)
  if (error || !data || data.length !== 1) return null
  return data[0].user_id as string
}

// ---------------------------------------------------------------- request

interface Prepared {
  kind: string
  ref: string
  action_hash: string
  summary: string
  data_lost: string | null
  detail: string
}

async function prepare(body: Record<string, unknown>): Promise<Prepared | string> {
  const kind = str(body.kind, 20)
  if (!kind || !KINDS.includes(kind)) return 'kind must be decision, action or pin-key'
  const ref = str(body.ref, 200)
  if (!ref || !RE_REF[kind].test(ref)) return 'bad ref for kind ' + kind
  const action_hash = str(body.action_hash, 64)
  if (!action_hash || !RE_HEX64.test(action_hash)) return 'action_hash must be 64 lowercase hex'

  if (kind === 'decision') {
    const d = body.decision as Record<string, unknown> | undefined
    if (!d || typeof d !== 'object') return 'decision fields are required'
    const fields = {
      question: str(d.question, 4000),
      options: str(d.options, 2000),
      answer: str(d.answer, 500),
      data_lost: str(d.data_lost ?? '', 4000, true),
      answered_at: str(d.answered_at ?? '', 40, true),
    }
    if (fields.question === null || fields.options === null || fields.answer === null ||
        fields.data_lost === null || fields.answered_at === null) {
      return 'decision fields: question, options, answer (strings), data_lost, answered_at (strings, may be empty)'
    }
    const text = decisionText(ref, fields as { question: string, options: string, answer: string, data_lost: string, answered_at: string })
    const digest = await sha256Hex(text)
    if (await decisionActionHash(ref, digest) !== action_hash) {
      return 'action_hash does not match the decision fields (homelab-db construction)'
    }
    return {
      kind, ref, action_hash,
      summary: cleanText(`Decision ${ref}: ${fields.question} → answer: ${fields.answer}`, 600),
      data_lost: fields.data_lost ? fields.data_lost : null,
      detail: text,
    }
  }

  if (kind === 'action') {
    if (!body.action || typeof body.action !== 'object' || Array.isArray(body.action)) return 'action must be a JSON object'
    let canon: string
    try {
      canon = canonicalJson(body.action)
    } catch (e) {
      return 'action: ' + (e instanceof Error ? e.message : String(e))
    }
    if (canon.length > 16000) return 'action JSON too long'
    if (await actionHashOf(body.action) !== action_hash) return 'action_hash is not sha256 of the canonical action JSON'
    const summary = str(body.summary, 300)
    if (!summary) return 'summary is required for kind action (1-300 chars)'
    const dl = body.data_lost == null || body.data_lost === '' ? null : str(body.data_lost, 2000)
    if (body.data_lost != null && body.data_lost !== '' && dl === null) return 'data_lost too long (2000)'
    return { kind, ref, action_hash, summary: cleanText(`Action ${ref}: ${summary}`, 600), data_lost: dl, detail: canon }
  }

  // pin-key: the summary is fixed here; the caller cannot word it.
  if (await pinKeyActionHash(ref) !== action_hash) return 'action_hash is not sha256 of the pin-key endorsement message'
  return {
    kind, ref, action_hash,
    summary: `TRUST A NEW approve-2fa SIGNING KEY ${ref.slice(0, 16)}… Approve only if you are rotating the key right now.`,
    data_lost: null,
    detail: pinKeyMessage(ref),
  }
}

async function sendPush(approver: string, requestId: string, secret: string, row: Prepared): Promise<number> {
  if (!VAPID_PUBLIC || !VAPID_PRIVATE || !VAPID_SUBJECT || !PAGE_URL) return 0
  const { data: subs, error } = await admin
    .from('push_subscriptions')
    .select('id, endpoint, subscription')
    .eq('user_id', approver)
    .eq('is_active', true)
  if (error || !subs) return 0
  // Built ONLY from the stored row. The payload is end-to-end encrypted to the phone (RFC 8291).
  const titleKind = row.kind === 'decision' ? 'decision' : row.kind === 'pin-key' ? 'SIGNING KEY' : 'action'
  const body = cleanText(row.summary, 160) + (row.data_lost ? '\ndeletes: ' + cleanText(row.data_lost, 160) : '')
  const payload = JSON.stringify({
    title: `Approval needed (${titleKind})`,
    body,
    url: PAGE_URL + '#r=' + requestId + '&s=' + secret,
    tag: requestId,
  })
  let sent = 0
  for (const s of subs) {
    try {
      await webpush.sendNotification(s.subscription, payload, { TTL: 600, urgency: 'high' })
      sent += 1
      await admin.from('push_subscriptions').update({ last_used_at: new Date().toISOString() }).eq('id', s.id)
    } catch (e) {
      const code = (e as { statusCode?: number }).statusCode
      if (code === 404 || code === 410) {
        // Gone for good. Anything else (429, 5xx, network) is transient: keep the subscription.
        await admin.from('push_subscriptions')
          .update({ is_active: false, updated_at: new Date().toISOString() })
          .eq('id', s.id)
      }
    }
  }
  return sent
}

async function handleRequest(req: Request, body: Record<string, unknown>): Promise<Response> {
  if (!(await verifierOk(req))) return json(req, 401, { error: 'unauthorized' })
  const approver = await approverId()
  if (!approver) return json(req, 503, { error: 'no approver configured (exactly one row in approvers)' })
  const p = await prepare(body)
  if (typeof p === 'string') return json(req, 400, { error: p })

  const secret = randomSecret()
  const { data, error } = await admin
    .from('approval_requests')
    .insert({
      secret_hash: await sha256Hex(secret),
      kind: p.kind,
      ref: p.ref,
      action_hash: p.action_hash,
      summary: p.summary,
      data_lost: p.data_lost,
      detail: p.detail,
    })
    .select('request_id, expires_at')
    .single()
  if (error || !data) {
    const rate = error && /rate limit|too many open/.test(error.message ?? '')
    return json(req, rate ? 429 : 500, { error: rate ? error!.message : 'insert failed' })
  }
  const pushed = await sendPush(approver, data.request_id, secret, p)
  const out: Record<string, unknown> = { request_id: data.request_id, expires_at: data.expires_at, pushed }
  if (ALLOW_LINK_FALLBACK && PAGE_URL) {
    out.approval_url = PAGE_URL + '#r=' + data.request_id + '&s=' + secret
  }
  return json(req, 200, out)
}

// ---------------------------------------------------------------- subscribe

function jwtPayload(token: string): Record<string, unknown> | null {
  // Only called AFTER auth.getUser(token) accepted the token (server-side check), so reading claims is safe.
  try {
    const part = token.split('.')[1]
    const b = part.replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(b + '='.repeat((4 - (b.length % 4)) % 4)))
  } catch {
    return null
  }
}

async function handleSubscribe(req: Request, body: Record<string, unknown>): Promise<Response> {
  const origin = req.headers.get('origin') ?? ''
  if (!PAGE_ORIGIN || origin !== PAGE_ORIGIN) return json(req, 403, { error: 'origin not allowed' })
  const token = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '')
  if (!token) return json(req, 401, { error: 'not signed in' })
  const { data: u, error: ue } = await admin.auth.getUser(token)
  if (ue || !u?.user) return json(req, 401, { error: 'not signed in' })
  const claims = jwtPayload(token)
  if (!claims || claims.aal !== 'aal2') return json(req, 403, { error: 'verify your authenticator code first (AAL2)' })
  const approver = await approverId()
  if (!approver || approver !== u.user.id) return json(req, 403, { error: 'this account is not the approver' })

  const sub = body.subscription as Record<string, unknown> | undefined
  const keys = sub?.keys as Record<string, unknown> | undefined
  const endpoint = str(sub?.endpoint, 1000)
  if (!sub || !endpoint || !/^https:\/\//.test(endpoint) || !keys || !str(keys.p256dh, 200) || !str(keys.auth, 100)) {
    return json(req, 400, { error: 'bad push subscription' })
  }
  const clean = { endpoint, expirationTime: null, keys: { p256dh: keys.p256dh, auth: keys.auth } }
  const now = new Date().toISOString()
  const { error } = await admin.from('push_subscriptions').upsert({
    user_id: approver,
    endpoint,
    subscription: clean,
    user_agent: (req.headers.get('user-agent') ?? '').slice(0, 400),
    is_active: true,
    updated_at: now,
  }, { onConflict: 'endpoint' })
  if (error) return json(req, 500, { error: 'could not save subscription' })

  // Keep at most MAX_SUBSCRIPTIONS active (newest win).
  const { data: act } = await admin.from('push_subscriptions')
    .select('id').eq('user_id', approver).eq('is_active', true).order('updated_at', { ascending: false })
  const extra = (act ?? []).slice(MAX_SUBSCRIPTIONS).map((r: { id: number }) => r.id)
  if (extra.length) await admin.from('push_subscriptions').update({ is_active: false }).in('id', extra)
  return json(req, 200, { ok: true })
}

// ---------------------------------------------------------------- entry

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    const origin = req.headers.get('origin') ?? ''
    return new Response(null, { status: PAGE_ORIGIN && origin === PAGE_ORIGIN ? 204 : 403, headers: corsHeaders(req) })
  }
  if (req.method !== 'POST') return json(req, 405, { error: 'POST only' })
  try {
    const body = await readBody(req)
    if (!body) return json(req, 400, { error: 'body must be a JSON object (max 64 KiB)' })
    if (body.op === 'subscribe') return await handleSubscribe(req, body)
    if (body.op !== undefined && body.op !== 'request') return json(req, 400, { error: 'unknown op' })
    return await handleRequest(req, body)
  } catch (_e) {
    // Never echo internals (could include row data or keys) to the caller.
    return json(req, 500, { error: 'internal error' })
  }
})
