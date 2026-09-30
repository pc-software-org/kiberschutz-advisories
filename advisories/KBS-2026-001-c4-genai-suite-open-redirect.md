# KBS-2026-001: Open redirect after login in c4 GenAI Suite

| | |
|---|---|
| Product | [codecentric/c4-genai-suite](https://github.com/codecentric/c4-genai-suite) |
| Affected | all releases up to and including 10.0.2 (the last one); checked back to 7.1.0 |
| Fixed | no. The repository is archived, no upstream fix will ship |
| Severity | Medium, CVSS 3.1 6.1 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N`) |
| Weakness | CWE-601, URL Redirection to Untrusted Site |
| CVE | pending |

## Summary

After a successful login, the backend redirects to the path stored in the `post-login-redirect` cookie. It checks only that the value starts with `/`. A protocol-relative value such as `//attacker.example/` passes that check, and the browser follows it to another origin.

The frontend fills that cookie from `window.location.pathname` whenever an API call returns 401. Because the frontend serves `index.html` for any path, one link is enough: a user who isn't logged in opens `https://c4.example.com//attacker.example/`, the app sends them to the login page, and once they log in they end up on `attacker.example`. That's a convenient setup for phishing, since the victim has just typed their credentials into the real site and arrives on a lookalike one.

We confirmed this by reading the code. We did not test it against a live deployment.

## Details

Backend, [`auth.controller.ts:112-122`](https://github.com/codecentric/c4-genai-suite/blob/d8f1de2bbdec07086b2cb9ef69cb86ba2e46bea8/backend/src/controllers/auth/auth.controller.ts#L112-L122):

```ts
const redirect = req.cookies['post-login-redirect'] as string | undefined;
if (isString(redirect) && redirect.startsWith('/')) {
  ...
  res.redirect(redirect);
}
```

Frontend, [`appClientStore.ts:25-31`](https://github.com/codecentric/c4-genai-suite/blob/d8f1de2bbdec07086b2cb9ef69cb86ba2e46bea8/frontend/src/api/state/zustand/appClientStore.ts#L25-L31) (same in `evalClientStore.ts`):

```ts
if (context.response?.status === 401 && !window.location.pathname.startsWith('/login')) {
  ...
  cookies.set('post-login-redirect', window.location.pathname);
  navigate('/login');
}
```

The frontend `Caddyfile` answers every unknown path with `try_files {path} /index.html`, so `//attacker.example/` loads the app.

## What operators can do

Upstream won't release a fix. If you still run c4 GenAI Suite:

1. Apply the patch below to the backend. It applies cleanly to 10.0.2.
2. Or, at the reverse proxy, reject requests whose path starts with `//` or `/\`.
3. Plan a migration, because the project won't get security fixes anymore.

```diff
--- a/backend/src/controllers/auth/auth.controller.ts
+++ b/backend/src/controllers/auth/auth.controller.ts
@@ -111,7 +111,10 @@ export class AuthController {
   private redirectToApplication(req: Request, res: Response) {
     const redirect = req.cookies['post-login-redirect'] as string | undefined;
-    if (isString(redirect) && redirect.startsWith('/')) {
+    if (isString(redirect) && redirect.startsWith('/') && !redirect.startsWith('//') && !redirect.startsWith('/\\')) {
```

## Timeline

- 2026-07-24: found during a KIberschutz analysis
- 2026-07-27: reported privately via GitHub private vulnerability reporting
- 2026-08-14: follow-up in public issue #2019, without details
- 2026-08-20: 10.0.1 and 10.0.2 ship fixes for four other issues from the same report. This one isn't among them
- 2026-08-28: the project publishes advisories for those four. This report stays in triage without a reply
- 2026-08-31: last commit to the repository
- 2026-09-30: repository found archived, public disclosure

## Credit

Found and reported by Patrick Cornelißen, [KIberblick.de](https://kiberblick.de), with AI-assisted analysis.
