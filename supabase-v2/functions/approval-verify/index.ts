// approve-2fa: the executor's side. Consumes an approval atomically and returns an Ed25519 signature over it,
// made with SIGNING_KEY (function secret, raw 32-byte seed, base64). homelab-db verifies it against the public key
// pinned in homelab.db (signer_keys), so nothing on Cerberus can mint a confirmation.
//
// Every call needs header x-verifier-key: VERIFIER_KEY and must NOT carry an Origin header (no browser access).
//   {op:'verify' (default), request_id, kind, ref, action_hash}
//      200 {method:'totp', kind, approver_uid, action_hash, ref, verified_at, sig_b64, signer_fpr, signed}
//      202 {status:'pending', expires_at}
//      409 {status:'denied'|'expired'|'consumed'|'mismatch', reason}
//      404 {status:'unknown'}
//   {op:'status', request_id}  -> 200 {status, expires_at, consumed, kind}  (no secrets, nothing consumed)
//   {op:'pubkey'}              -> 200 {pub_b64, signer_fpr}   (for pinning / cross-checking)
//   {op:'ping'}                -> 200 {ok:true}   (keep-alive: one cheap DB read)
//
// verified_at = approved_at (server time, set by decide_request) as 'YYYY-MM-DDTHH:MM:SSZ' (UTC, seconds truncated),
// formatted in SQL by consume_request.

import { createClient } from 'npm:@supabase/supabase-js@2.45.4'
import {
  KINDS, loadSigningKey, RE_HEX64, RE_REF, RE_UUID, RE_VERIFIED_AT, signB64, signedMessage, type SigningKey, timingSafeEqual,
} from '../_shared/approve2fa.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ?? ''
const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
const VERIFIER_KEY = Deno.env.get('VERIFIER_KEY') ?? ''
const SIGNING_KEY = Deno.env.get('SIGNING_KEY') ?? ''

const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
})

let keyCache: SigningKey | null = null
async function signingKey(): Promise<SigningKey> {
  if (!keyCache) keyCache = await loadSigningKey(SIGNING_KEY)
  return keyCache
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  })
}

async function verifierOk(req: Request): Promise<boolean> {
  if (req.headers.get('origin')) return false
  if (VERIFIER_KEY.length < 32) return false
  return await timingSafeEqual(req.headers.get('x-verifier-key') ?? '', VERIFIER_KEY)
}

async function state(id: string, kind?: string, ref?: string, action_hash?: string) {
  const { data, error } = await admin.rpc('request_state', {
    p_id: id, p_kind: kind ?? null, p_ref: ref ?? null, p_action_hash: action_hash ?? null,
  })
  if (error) throw new Error('request_state failed')
  return (data && data.length ? data[0] : null) as
    { status: string, expires_at: string, consumed: boolean, matches: boolean, kind: string } | null
}

async function verify(body: Record<string, unknown>): Promise<Response> {
  const id = typeof body.request_id === 'string' ? body.request_id.toLowerCase() : ''
  const kind = typeof body.kind === 'string' ? body.kind : ''
  const ref = typeof body.ref === 'string' ? body.ref : ''
  const action_hash = typeof body.action_hash === 'string' ? body.action_hash : ''
  if (!RE_UUID.test(id)) return json(400, { error: 'request_id must be a uuid' })
  if (!KINDS.includes(kind)) return json(400, { error: 'bad kind' })
  if (!RE_REF[kind].test(ref)) return json(400, { error: 'bad ref' })
  if (!RE_HEX64.test(action_hash)) return json(400, { error: 'bad action_hash' })

  // Load the key BEFORE consuming, so a misconfigured key never burns an approval.
  let key: SigningKey
  try {
    key = await signingKey()
  } catch {
    return json(503, { error: 'signing key not configured' })
  }

  const { data, error } = await admin.rpc('consume_request', {
    p_id: id, p_kind: kind, p_ref: ref, p_action_hash: action_hash,
  })
  if (error) return json(500, { error: 'consume failed' })
  const row = (data && data.length ? data[0] : null) as
    { kind: string, ref: string, action_hash: string, approver_uid: string, verified_at: string } | null

  if (!row) {
    const st = await state(id, kind, ref, action_hash)
    if (!st) return json(404, { status: 'unknown', reason: 'no such request' })
    if (!st.matches) return json(409, { status: 'mismatch', reason: 'kind, ref or action_hash differ from the request' })
    if (st.status === 'pending') return json(202, { status: 'pending', expires_at: st.expires_at })
    if (st.status === 'denied') return json(409, { status: 'denied', reason: 'the approver denied it' })
    if (st.status === 'expired') return json(409, { status: 'expired', reason: 'not approved and used within 10 minutes' })
    if (st.consumed) return json(409, { status: 'consumed', reason: 'this approval was already used' })
    return json(409, { status: st.status, reason: 'not usable' })
  }

  if (!RE_VERIFIED_AT.test(row.verified_at)) return json(500, { error: 'bad verified_at from database' })
  const facts = {
    kind: row.kind, ref: row.ref, action_hash: row.action_hash, approver_uid: row.approver_uid,
    verified_at: row.verified_at,
  }
  const signed = signedMessage(facts)
  const sig_b64 = await signB64(key, signed)
  return json(200, {
    method: 'totp',
    kind: row.kind,
    approver_uid: row.approver_uid,
    action_hash: row.action_hash,
    ref: row.ref,
    verified_at: row.verified_at,
    sig_b64,
    signer_fpr: key.fpr,
    signed,
  })
}

Deno.serve(async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'POST only' })
  if (!(await verifierOk(req))) return json(401, { error: 'unauthorized' })
  try {
    const text = await req.text()
    if (text.length > 8192) return json(413, { error: 'body too large' })
    let body: Record<string, unknown>
    try {
      body = JSON.parse(text)
    } catch {
      return json(400, { error: 'body must be JSON' })
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return json(400, { error: 'body must be a JSON object' })
    const op = body.op ?? 'verify'
    if (op === 'verify') return await verify(body)
    if (op === 'status') {
      const id = typeof body.request_id === 'string' ? body.request_id.toLowerCase() : ''
      if (!RE_UUID.test(id)) return json(400, { error: 'request_id must be a uuid' })
      const st = await state(id)
      if (!st) return json(404, { status: 'unknown' })
      return json(200, { status: st.status, expires_at: st.expires_at, consumed: st.consumed, kind: st.kind })
    }
    if (op === 'pubkey') {
      try {
        const k = await signingKey()
        return json(200, { pub_b64: k.pubB64, signer_fpr: k.fpr })
      } catch {
        return json(503, { error: 'signing key not configured' })
      }
    }
    if (op === 'ping') {
      const { error } = await admin.from('approvers').select('user_id', { count: 'exact', head: true })
      if (error) return json(503, { ok: false })
      await admin.rpc('expire_stale_requests')
      return json(200, { ok: true })
    }
    return json(400, { error: 'unknown op' })
  } catch {
    return json(500, { error: 'internal error' })
  }
})
