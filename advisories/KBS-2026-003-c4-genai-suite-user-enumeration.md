# KBS-2026-003: User enumeration on password login in c4 GenAI Suite

| | |
|---|---|
| Product | [codecentric/c4-genai-suite](https://github.com/codecentric/c4-genai-suite) |
| Affected | all releases up to and including 10.0.2 (the last one); checked back to 7.1.0 |
| Fixed | no. The repository is archived, no upstream fix will ship |
| Severity | Medium, CVSS 3.1 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) |
| Weakness | CWE-204, Observable Response Discrepancy; CWE-208, Observable Timing Discrepancy |
| CVE | pending |

## Summary

The password login answers `Unknown user.` for an unknown email address and `Wrong password.` for a known one. Anyone who can reach the login can use that to check which email addresses have an account. The unknown-user path also skips the bcrypt comparison, so it responds measurably faster. Even with identical messages, timing would still give it away.

On its own this doesn't break into anything. It gives an attacker a list of valid accounts for password spraying and targeted phishing.

## Details

[`auth.service.ts:269-280`](https://github.com/codecentric/c4-genai-suite/blob/d8f1de2bbdec07086b2cb9ef69cb86ba2e46bea8/backend/src/domain/auth/auth.service.ts#L269-L280):

```ts
const user = await this.users.findOne({ where: { email }, relations: ['userGroups'] });
if (!user?.passwordHash) {
  throw new UnauthorizedException('Unknown user.');      // no bcrypt, faster
}
if (!(await bcrypt.compare(password, user.passwordHash))) {
  throw new UnauthorizedException('Wrong password.');
}
```

## What operators can do

Upstream won't release a fix. If you still run c4 GenAI Suite:

1. Apply the patch below. It applies cleanly to 10.0.2. To close the timing difference as well, also run `bcrypt.compare` against a fixed dummy hash on the unknown-user path.
2. If you only use SSO, turn off password login.
3. Rate-limit the login endpoint at the reverse proxy.
4. Plan a migration, because the project won't get security fixes anymore.

```diff
--- a/backend/src/domain/auth/auth.service.ts
+++ b/backend/src/domain/auth/auth.service.ts
@@ -269,11 +269,13 @@ export class AuthService implements OnModuleInit {
     if (!user?.passwordHash) {
-      throw new UnauthorizedException('Unknown user.');
+      throw new UnauthorizedException('Invalid credentials.');
     }
     if (!(await bcrypt.compare(password, user.passwordHash))) {
-      throw new UnauthorizedException('Wrong password.');
+      throw new UnauthorizedException('Invalid credentials.');
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
