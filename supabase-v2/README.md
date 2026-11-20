# approve-2fa v2: Supabase project (fresh)

Phone 2FA approvals for privileged agent actions and destructive decision-board items.
Design: `D:\Vault\infra\security-architecture.md` §7.3, §7.4, §8.2. Client: skill `approve-2fa`
(`~/.claude/skills/approve-2fa`). Page: `setup/security/approval-page-v2.html`.
The old `supabase/` folder and the paused "Morgan Toolbox" project are not used by any of this.

```
agent/executor ──(x-verifier-key)──> approval-request ──insert (service role)──> approval_requests
                                          └── web push (text built from the row) ──> phone PWA
phone PWA ── sign in + fresh TOTP (AAL2) ──> rpc get_request / decide_request (security definer)
executor ──(x-verifier-key)──> approval-verify ── consume_request (atomic, single use)
                                          └── Ed25519 sign (SIGNING_KEY) ──> {sig_b64, signer_fpr, ...}
executor ──> homelab-db decision confirm (verifies against the key pinned in homelab.db)
```

| File | What |
|---|---|
| `migrations/0001_approvals.sql` | tables `approvers`, `approval_requests`, `push_subscriptions`; RLS on, no policies; triggers; RPCs `get_request`, `decide_request` (authenticated), `consume_request`, `request_state`, `expire_stale_requests` (service role) |
| `functions/approval-request/index.ts` | create a request (verifier key) + push; `{op:'subscribe'}` for the phone (user JWT, AAL2, approver only) |
| `functions/approval-verify/index.ts` | consume + Ed25519 signature (verifier key); ops `status`, `pubkey`, `ping` |
| `functions/_shared/approve2fa.ts` | canonical JSON, homelab-db constructions, WebCrypto Ed25519 (shared; the skill's selftest runs it under Node) |
| `config.toml` | `verify_jwt = false` for both functions (they authenticate callers themselves) |

## Function secrets

| Name | Value | Notes |
|---|---|---|
| `VERIFIER_KEY` | random, >= 32 chars | same value in `~/.claude/secrets/approve-2fa.json` as `{"verifier_key": "..."}` |
| `SIGNING_KEY` | base64 of a raw 32-byte Ed25519 seed | from `approve-2fa keygen`; never stored anywhere else |
| `PAGE_ORIGIN` | `https://<GITHUB_USER>.github.io` | the only CORS origin (subscribe) |
| `PAGE_URL` | `https://<GITHUB_USER>.github.io/<PAGES_REPO>/approval-v2/` | push links are `PAGE_URL#r=<id>&s=<secret>` |
| `WEB_PUSH_PUBLIC_KEY` / `WEB_PUSH_PRIVATE_KEY` | new VAPID pair | never reuse the old pair (it is in git history) |
| `WEB_PUSH_SUBJECT` | `mailto:<ADDRESS>` | required by push services |
| `ALLOW_LINK_FALLBACK` | `false` | see "Link fallback" below |

`SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are injected by Supabase.

## Deploy runbook (later, with the user)

Placeholders: `<REF>` project ref, `<ORG_ID>`, `<REGION>`, `<GITHUB_USER>`, `<PAGES_REPO>`, `<EMAIL>`. Run in PowerShell.
Nothing in this runbook prints a secret; keep it that way (no `echo`, no `Get-Content` of secret files in a chat).

1. **Go-ahead and choices (user).** The user approves creating a free project, picks the region and the DB
   password (typed into the CLI prompt, or stored straight in `~/.claude/secrets`), and has the phone at hand.

2. **Create and link the project.**
   ```powershell
   supabase projects create approve-2fa --org-id <ORG_ID> --region <REGION>   # prompts for the DB password
   # The CLI expects <workdir>\supabase\; point a junction at supabase-v2 instead of moving files:
   New-Item -ItemType Directory -Force D:\repos\personal-tools\.sb2 | Out-Null
   New-Item -ItemType Junction -Path D:\repos\personal-tools\.sb2\supabase -Target D:\repos\personal-tools\supabase-v2
   supabase link --project-ref <REF> --workdir D:\repos\personal-tools\.sb2
   ```
   Add `.sb2/` and `supabase-v2/.temp/` to `.gitignore` (the link writes `.temp` through the junction).

3. **Push the schema.**
   ```powershell
   supabase db push --workdir D:\repos\personal-tools\.sb2
   ```
   Check in the dashboard (Table editor): three tables, RLS on, zero policies.

4. **Generate and set the secrets** (none of them is printed):
   ```powershell
   $tmp = New-Item -ItemType Directory -Force "$env:TEMP\a2fa-setup"
   # signing key: seed goes to a file; pub_b64 + signer_fpr are printed (keep them for step 13)
   node ~/.claude/skills/skillsmith/scripts/sk.js run approve-2fa keygen --out "$tmp\seed.b64"
   # verifier key: written to the secrets file and the env file, never to the screen
   python -I -c "import secrets,json,os; k=secrets.token_urlsafe(48); p=os.path.expanduser('~/.claude/secrets/approve-2fa.json'); json.dump({'verifier_key':k},open(p,'x')); open(os.environ['TEMP']+r'\a2fa-setup\verifier','w').write(k)"
   npx web-push generate-vapid-keys --json > "$tmp\vapid.json"
   $v = Get-Content "$tmp\vapid.json" | ConvertFrom-Json
   @(
     "VERIFIER_KEY=$(Get-Content "$tmp\verifier" -Raw)"
     "SIGNING_KEY=$((Get-Content "$tmp\seed.b64" -Raw).Trim())"
     "PAGE_ORIGIN=https://<GITHUB_USER>.github.io"
     "PAGE_URL=https://<GITHUB_USER>.github.io/<PAGES_REPO>/approval-v2/"
     "WEB_PUSH_PUBLIC_KEY=$($v.publicKey)"
     "WEB_PUSH_PRIVATE_KEY=$($v.privateKey)"
     "WEB_PUSH_SUBJECT=mailto:<EMAIL>"
     "ALLOW_LINK_FALLBACK=false"
   ) | Set-Content -Encoding utf8 "$tmp\secrets.env"
   supabase secrets set --env-file "$tmp\secrets.env" --workdir D:\repos\personal-tools\.sb2
   ```
   Keep `$v.publicKey` for step 9 (it is public). Delete `$tmp` after step 13 (the seed must not survive it).

5. **Deploy the functions.**
   ```powershell
   supabase functions deploy approval-request --no-verify-jwt --workdir D:\repos\personal-tools\.sb2
   supabase functions deploy approval-verify --no-verify-jwt --workdir D:\repos\personal-tools\.sb2
   ```

6. **Auth settings (dashboard → Authentication).** Email provider on; MFA → TOTP enabled; Site URL =
   `PAGE_URL`; redirect URLs = `PAGE_URL` and `PAGE_URL?setup=1`. Sign-ups stay **on** until step 8.
   Optional: set a short JWT expiry (e.g. 600 s) to shorten the life of a stolen access token.

7. **The user creates the approver account** on the phone: open `PAGE_URL?setup=1`, Create account, confirm
   the e-mail. (The sign-up form exists only with `?setup=1`.)

8. **Insert the approver row, then close sign-ups.** In the SQL editor (runs as the service owner):
   ```sql
   select id, email, created_at from auth.users;          -- must be exactly the user's one account
   insert into public.approvers (user_id, email)
     select id, email from auth.users where email = '<EMAIL>';
   ```
   Then dashboard → Authentication → Sign In / Providers → turn **off** "Allow new users to sign up".
   Re-check `select count(*) from auth.users` = 1. Note the `user_id` (the approver uid) for step 13.

9. **Publish the page (GitHub Pages).** Add repository variables (Settings → Secrets and variables → Actions →
   Variables; they are public values): `APPROVAL_V2_SUPABASE_URL` = `https://<REF>.supabase.co`,
   `APPROVAL_V2_ANON_KEY` = the project's anon (publishable) key, `APPROVAL_V2_VAPID_PUBLIC_KEY` = `$v.publicKey`.
   Add to `.github/workflows/deploy-approval-page.yml`, in "Prepare static approval site", and add
   `setup/security/approval-page-v2.html` to its `paths`:
   ```powershell
   New-Item -ItemType Directory -Force -Path public/approval-v2 | Out-Null
   Copy-Item 'setup/security/approval-page-v2.html' 'public/approval-v2/index.html' -Force
   Copy-Item 'setup/security/approval-sw.js' 'public/approval-v2/approval-sw.js' -Force
   Copy-Item 'setup/security/manifest.webmanifest' 'public/approval-v2/manifest.webmanifest' -Force
   Copy-Item 'setup/security/approval-icon.svg' 'public/approval-v2/approval-icon.svg' -Force
   $cfg = [ordered]@{ supabaseUrl = '${{ vars.APPROVAL_V2_SUPABASE_URL }}'; anonKey = '${{ vars.APPROVAL_V2_ANON_KEY }}'; vapidPublicKey = '${{ vars.APPROVAL_V2_VAPID_PUBLIC_KEY }}' }
   "window.APPROVE_2FA_CONFIG = $($cfg | ConvertTo-Json -Compress)" | Set-Content -Encoding utf8 public/approval-v2/config.js
   ```
   (Local testing: copy `setup/security/approval-config.example.js` to `config.js` next to the page.)
   Optional hardening: add an `integrity=` hash to the pinned supabase-js script tag, or vendor that file.

10. **TOTP enrollment (user, about 3 min).** On the phone: open `PAGE_URL`, sign in, Start TOTP enrollment,
    scan, verify. Install the app (Add to Home screen), enter a code (AAL2), Turn on phone alerts.

11. **Configure the skill on Cerberus.**
    ```powershell
    node ~/.claude/skills/skillsmith/scripts/sk.js run approve-2fa config --set project_url=https://<REF>.supabase.co --set page_url=https://<GITHUB_USER>.github.io/<PAGES_REPO>/approval-v2/
    node ~/.claude/skills/skillsmith/scripts/sk.js run approve-2fa keepalive          # prints ok
    node ~/.claude/skills/skillsmith/scripts/sk.js run approve-2fa pubkey --expect-fpr <signer_fpr from step 4>
    node ~/.claude/skills/skillsmith/scripts/sk.js run approve-2fa config --set signer_fpr=<signer_fpr>
    ```

12. **End-to-end test (no decision involved).** Write `{"test":"approve-2fa e2e","nonce":"<random>"}` to a file, then
    `approve-2fa request --kind action --ref e2e-test --action-json <file> --summary "approve-2fa end-to-end test"`;
    approve on the phone; `approve-2fa verify --request <rid> --kind action --ref e2e-test --action-json <file>` → exit 0.
    Repeat with Deny (→ exit 1 denied), with no answer for 10 min (→ exit 1 expired), and verify the same rid twice
    (second → cached result / consumed). Check that approving without a fresh code is refused.

13. **Pin the signing key in homelab.db (bootstrap, user's phrase).**
    ```powershell
    node ~/.claude/skills/skillsmith/scripts/sk.js run homelab-db decision pin-key approve-2fa --pub-b64 <pub_b64 from step 4> --approver-uid <uid from step 8>
    ```
    It exits 2 and prints the phrase; the user types it in a live Claude chat; re-run with `--confirmed`.
    Then delete `$env:TEMP\a2fa-setup` (seed, verifier copy, VAPID private key, env file).
    From here the decisions tick sends 2FA requests for tier-2 items by itself.

14. **Daily keep-alive** (a free project pauses after about 7 days without traffic):
    ```powershell
    schtasks /Create /SC DAILY /ST 09:17 /TN "approve-2fa keepalive" /TR "python -I $HOME\.claude\skills\approve-2fa\scripts\run.py keepalive"
    ```
    `keepalive` also expires stale pending rows. Optional: enable pg_cron and the schedule at the end of the migration.

15. **Old project: only on the user's yes.** The paused "Morgan Toolbox" project holds nothing worth keeping
    (short-lived approval rows, push subscriptions, a TOTP factor). Post it as a board decision with
    `data_lost` = "the paused Morgan Toolbox Supabase project and all its data (cannot be undone)"; after the
    yes (and its 2FA confirmation): `supabase projects delete <OLD_REF>`. Its anon key and VAPID key in git
    history then point at nothing. Request-PrivilegedApproval (setup-utils.ps1) still targets the old schema;
    move it to `approve-2fa request --kind action` / `verify` before relying on it.

### Key rotation (later)

`keygen --out new.b64` → `request --kind pin-key --ref <new fpr>` → approve on the phone → `verify --kind pin-key
--ref <new fpr>` (prints the `homelab-db decision pin-key ... --endorse-fpr --endorse-sig-b64` line) → run it with the
new pub key → `supabase secrets set SIGNING_KEY=...` → `pubkey --expect-fpr <new fpr>` → `config --set signer_fpr=<new>`
→ `homelab-db decision retire-key <old fpr>`.

## Link fallback (`ALLOW_LINK_FALLBACK`, default `false`)

With `true`, `approval-request` also returns `approval_url` (`PAGE_URL#r=<id>&s=<secret>`) to the caller, so the
skill can show a QR/link when push fails (no subscription, push service down, phone offline).

- Cost: the per-request secret then exists on Cerberus (process output, terminal scrollback), readable by anything
  running as the user. It does not let an agent approve: deciding still needs the approver's password session plus a
  fresh TOTP on the phone, enforced in SQL. What it adds is a phishing lever: an agent holding the link could show the
  user a link of its choice; with push-only, the only way a request reaches the phone is a notification whose text the
  server built from the row.
- Benefit: approvals keep working without web push.
- Recommendation: keep `false`; switch it on temporarily (`supabase secrets set ALLOW_LINK_FALLBACK=true`) only while
  push is broken, and back off afterwards.

## What the database enforces (not the page)

- No client can insert, update, delete or select any table (RLS on, no policies, privileges revoked).
- Status, timestamps and expiry are set by triggers; content is frozen after insert; decided rows are final;
  `consumed_at` is set once, to server time, only on approved rows; rows are kept 30 days.
- `decide_request`: the fixed approver, `aal = aal2`, a TOTP `amr` entry newer than the request and under 5 minutes
  old, the secret, pending, not expired.
- `consume_request`: approved, AAL2, unconsumed, unexpired, same kind/ref/action_hash, approver still configured;
  one atomic UPDATE.
- Rate limit: 30 requests per 10 minutes, 10 open at once.
