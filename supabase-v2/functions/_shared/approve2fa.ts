// approve-2fa shared helpers. Pure: only WebCrypto, TextEncoder, btoa/atob, so the same file runs in Deno (Supabase
// Edge Functions) and in Node >= 22.6 (`node --experimental-strip-types`), which the approve-2fa skill's selftest
// uses to cross-check these bytes against homelab-db's Python construction. Keep it free of enums/namespaces.
//
// Byte contracts (homelab-db ~/.claude/skills/homelab-db/scripts/run.py + migrations 009/010):
//   canonical JSON   = Python json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False), UTF-8
//   decision text    = "homelab-decision-v1\nid=<id>\nquestion=<q>\noptions=<o>\nanswer=<a>\ndata_lost=<dl>\nanswered_at=<at>\n"
//   digest           = sha256 hex of the decision text
//   action_hash      = sha256 hex of canon({"digest": digest, "kind": "decision", "ref": id})
//   decision message = canon({"aal":"aal2","action_hash","approver_uid","ref","verified_at"})
//   pin-key message  = canon({"fpr": <new key fpr>, "kind": "pin-key", "ns": "approve-2fa"})
//   action message   = canon({"aal":"aal2","action_hash","approver_uid","kind":"action","ref","verified_at"})
//                      (approve-2fa's own format: the extra "kind" key makes it impossible to replay an action
//                       approval as a decision confirmation; homelab-db never accepts it)

export const SIGN_NS = 'approve-2fa'
const enc = new TextEncoder()

// ---------- canonical JSON (Python-compatible) ----------

function cmpCodepoints(a: string, b: string): number {
  // Python sorts str keys by code point; JS default sort is by UTF-16 code unit. They differ only above U+FFFF.
  const A = Array.from(a)
  const B = Array.from(b)
  const n = Math.min(A.length, B.length)
  for (let i = 0; i < n; i++) {
    const x = A[i].codePointAt(0) as number
    const y = B[i].codePointAt(0) as number
    if (x !== y) return x < y ? -1 : 1
  }
  return A.length - B.length
}

function jsonString(s: string): string {
  // JSON.stringify escapes exactly what Python's json.dumps(ensure_ascii=False) escapes for well-formed strings
  // (" \\ \b \f \n \r \t, other C0 controls as lowercase \u00xx). Lone surrogates differ, so refuse them.
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s)) {
    throw new Error('lone surrogate in string')
  }
  return JSON.stringify(s)
}

export function canonicalJson(v: unknown): string {
  if (v === null) return 'null'
  if (typeof v === 'boolean') return v ? 'true' : 'false'
  if (typeof v === 'number') {
    // Floats render differently in Python and JS (1.0 vs 1); only safe integers are allowed.
    if (!Number.isSafeInteger(v)) throw new Error('canonical JSON allows only safe integers')
    return String(v)
  }
  if (typeof v === 'string') return jsonString(v)
  if (Array.isArray(v)) return '[' + v.map(canonicalJson).join(',') + ']'
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).sort(cmpCodepoints)
    return '{' + keys.map((k) => jsonString(k) + ':' + canonicalJson(o[k])).join(',') + '}'
  }
  throw new Error('canonical JSON: unsupported type ' + typeof v)
}

// ---------- hashing / encoding ----------

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

export function fromHex(h: string): Uint8Array {
  if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error('bad hex')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16)
  return out
}

export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? enc.encode(data) : data
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}

export function b64encode(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += String.fromCharCode(x)
  return btoa(s)
}

export function b64decode(s: string): Uint8Array {
  const t = s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '')
  const padded = t + '='.repeat((4 - (t.length % 4)) % 4)
  const bin = atob(padded)
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

export function b64url(b: Uint8Array): string {
  return b64encode(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function randomSecret(): string {
  // 32 random bytes -> 43 base64url chars. Hashed (sha256 hex of the UTF-8 string) before storage.
  return b64url(crypto.getRandomValues(new Uint8Array(32)))
}

// Constant-time string compare (compares sha256 of both, so lengths don't leak either).
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const [x, y] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ])
  const X = new Uint8Array(x)
  const Y = new Uint8Array(y)
  let diff = 0
  for (let i = 0; i < X.length; i++) diff |= X[i] ^ Y[i]
  return diff === 0 && a.length > 0
}

// ---------- homelab-db constructions ----------

export interface DecisionFields {
  question: string
  options: string
  answer: string
  data_lost: string
  answered_at: string
}

export function decisionText(ref: string, d: DecisionFields): string {
  return 'homelab-decision-v1\nid=' + ref + '\nquestion=' + d.question + '\noptions=' + d.options + '\nanswer=' +
    d.answer + '\ndata_lost=' + (d.data_lost || '') + '\nanswered_at=' + (d.answered_at || '') + '\n'
}

export async function decisionActionHash(ref: string, digest: string): Promise<string> {
  return sha256Hex(canonicalJson({ digest, kind: 'decision', ref }))
}

export function pinKeyMessage(fpr: string): string {
  return canonicalJson({ fpr, kind: 'pin-key', ns: SIGN_NS })
}

export async function pinKeyActionHash(fpr: string): Promise<string> {
  return sha256Hex(pinKeyMessage(fpr))
}

export function actionHashOf(action: unknown): Promise<string> {
  return sha256Hex(canonicalJson(action))
}

export interface ApprovalFacts {
  kind: string
  ref: string
  action_hash: string
  approver_uid: string
  verified_at: string
}

// The exact UTF-8 string that is signed for a consumed approval.
export function signedMessage(f: ApprovalFacts): string {
  if (f.kind === 'pin-key') return pinKeyMessage(f.ref)
  const base: Record<string, string> = {
    aal: 'aal2', action_hash: f.action_hash, approver_uid: f.approver_uid, ref: f.ref, verified_at: f.verified_at,
  }
  if (f.kind === 'action') base.kind = 'action'
  else if (f.kind !== 'decision') throw new Error('unknown kind')
  return canonicalJson(base)
}

// ---------- Ed25519 (WebCrypto) ----------

const PKCS8_ED25519_PREFIX = fromHex('302e020100300506032b657004220420')

export interface SigningKey {
  key: CryptoKey
  pubB64: string
  fpr: string // sha256 hex of the raw 32-byte public key (homelab-db signer_fpr)
}

export async function loadSigningKey(seedB64: string): Promise<SigningKey> {
  const seed = b64decode(seedB64.trim())
  if (seed.length !== 32) throw new Error('SIGNING_KEY must be a base64 raw 32-byte Ed25519 seed')
  const der = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32)
  der.set(PKCS8_ED25519_PREFIX, 0)
  der.set(seed, PKCS8_ED25519_PREFIX.length)
  // One extractable import only to read the public key (JWK "x"); the signing handle is non-extractable.
  const tmp = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, true, ['sign'])
  const jwk = await crypto.subtle.exportKey('jwk', tmp) as JsonWebKey
  if (!jwk.x) throw new Error('Ed25519 key without public part')
  const pub = b64decode(jwk.x)
  if (pub.length !== 32) throw new Error('unexpected Ed25519 public key length')
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'Ed25519' }, false, ['sign'])
  der.fill(0)
  seed.fill(0)
  return { key, pubB64: b64encode(pub), fpr: await sha256Hex(pub) }
}

export async function signB64(k: SigningKey, message: string): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, k.key, enc.encode(message)))
  if (sig.length !== 64) throw new Error('unexpected Ed25519 signature length')
  return b64encode(sig)
}

// ---------- validation ----------

export const RE_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export const RE_HEX64 = /^[0-9a-f]{64}$/
export const RE_REF: Record<string, RegExp> = {
  decision: /^[A-Za-z0-9._:-]{1,200}$/,
  action: /^[A-Za-z0-9._:@\/-]{1,200}$/,
  'pin-key': /^[0-9a-f]{64}$/,
}
export const KINDS = ['decision', 'action', 'pin-key']

// Strip C0/C1 controls except newline; collapse to a bounded length (for display only).
export function cleanText(s: unknown, max: number): string {
  const t = String(s ?? '').replace(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, ' ')
  return Array.from(t).length > max ? Array.from(t).slice(0, max - 1).join('') + '…' : t
}

// verified_at contract: UTC, second precision, 'YYYY-MM-DDTHH:MM:SSZ' (homelab-db accepts \d{4}-..T..:..:..(\.\d+)?Z).
export const RE_VERIFIED_AT = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/
