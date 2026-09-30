# KBS-2026-002: Session id not rotated on login in c4 GenAI Suite

| | |
|---|---|
| Product | [codecentric/c4-genai-suite](https://github.com/codecentric/c4-genai-suite) |
| Affected | all releases up to and including 10.0.2 (the last one); checked back to 7.1.0 |
| Fixed | no. The repository is archived, no upstream fix will ship |
| Severity | Medium, CVSS 3.1 6.8 (`CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N`) |
| Weakness | CWE-384, Session Fixation |
| CVE | pending |

## Summary

On login, both password and SSO, the backend writes the user into the existing `express-session` session and saves it. It never regenerates the session id. A session created before login, for example the one passport uses for the OAuth `state`, keeps its id after authentication.

If an attacker can plant a known session cookie in the victim's browser before login, they can use that same cookie as the victim afterwards. Planting the cookie is the hard part. It usually needs control over a sibling subdomain, an XSS somewhere on the site, or a plain-HTTP hop. That's why the attack complexity is rated high.

## Details

[`auth.service.ts:67-76`](https://github.com/codecentric/c4-genai-suite/blob/d8f1de2bbdec07086b2cb9ef69cb86ba2e46bea8/backend/src/domain/auth/auth.service.ts#L67-L76), called from `loginWithPassword` and from the SSO `login`:

```ts
private async setSessionUser(req: Request, user: User | UserEntity | undefined) {
  await new Promise((resolve) => {
    if (!user) {
      req.session.destroy(resolve);
    } else {
      req.session.user = user as User;
      req.session.save(resolve);   // no req.session.regenerate()
    }
  });
}
```

## What operators can do

Upstream won't release a fix. If you still run c4 GenAI Suite:

1. Apply the patch below to the backend. It applies cleanly to 10.0.2.
2. Don't host other, less trusted applications on sibling subdomains that could set cookies for the c4 domain, and serve c4 over HTTPS only.
3. Plan a migration, because the project won't get security fixes anymore.

```diff
--- a/backend/src/domain/auth/auth.service.ts
+++ b/backend/src/domain/auth/auth.service.ts
@@ -65,12 +65,18 @@ export class AuthService implements OnModuleInit {
   private async setSessionUser(req: Request, user: User | UserEntity | undefined) {
-    await new Promise((resolve) => {
+    await new Promise<void>((resolve, reject) => {
       if (!user) {
-        req.session.destroy(resolve);
+        req.session.destroy(() => resolve());
       } else {
-        req.session.user = user as User;
-        req.session.save(resolve);
+        req.session.regenerate((err) => {
+          if (err) return reject(err);
+          req.session.user = user as User;
+          req.session.save(() => resolve());
+        });
       }
     });
   }
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
