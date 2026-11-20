// approve-2fa v2 page settings. Public values only (the anon/publishable key is meant to be public; RLS and the
// security-definer RPCs are the protection). The deploy workflow writes the real file as approval-v2/config.js
// from GitHub Actions variables (README step 9); for a local test copy this to config.js next to the page.
window.APPROVE_2FA_CONFIG = {
  supabaseUrl: 'https://YOUR_PROJECT_REF.supabase.co',
  anonKey: 'YOUR_SUPABASE_ANON_OR_PUBLISHABLE_KEY',
  vapidPublicKey: 'YOUR_WEB_PUSH_PUBLIC_KEY',
}
