# WE4: required signed-revocation status check — SOURCE PRESTAGE ONLY

Created 2026-11-20. This code is a companion to Traffic publisher PR #76, preserving that PR's already-qualified source HEAD. It implements the named check required by GitHub ruleset #27691195; it does **not** create the protected branch, sign any real state, enroll a reviewer, authorize a publication, or publish an audience day.

## What the check does

The GitHub Actions job is named exactly **verify-traffic-v2-revocation-transition**. It runs only when a pull request targets branch traffic-v2-revocation. It checks out protected BASE code, fetches the proposed PR head as a Git commit (never executes PR code), verifies head SHA identity, and rejects all changes except one ordinary modification of ops/traffic-v2-revocation-current.json. From the protected BASE commit it reads ops/traffic-v2-revocation-owner-public.pem and ops/traffic-v2-revocation-owner-trust.json. The latter has exact schema aoe2war.traffic-v2.revocation-owner-trust.v1 and holds owner_public_key_sha256. The verifier rejects missing, symlink/non-100644, mutated, oversized and mismatched trust. It cryptographically verifies prior and proposed owner Ed25519 signatures and only permits the underlying PR76 policy's exact revision N→N+1, same delegation binding, monotonic time, and irreversible ACTIVE→REVOKED transition.

No private keys appear in code, Git, Actions, tests or logs. Tests use disposable keys, ephemeral local Git commits and negative adversarial cases.

## Non-negotiable independent production admission

The protected traffic-v2-revocation branch does not yet exist; GitHub rejected its previous creation under the active ruleset with HTTP422. **Do not bypass, relax, remove or manipulate that ruleset as a workaround.** First obtain a distinct authorized human reviewer and WE2/owner-approved independent bootstrapping procedure. The initial protected branch must have an authentic OWNER-signed ACTIVE state, an independently accepted actual public-key identity and trust SHA, and the reviewed workflow/module code from immutable source. A check created in source is not a running status check on a nonexistent branch. The owner-signed ACTIVE state and real root-local/external revocation readbacks must match exactly. State transition to REVOKED must be tested live, and reinstating old ACTIVE must fail. Any unfulfilled item => publication HOLD. GitHub admins colluding with a root operator are outside the proposed branch protection model.

This new source-only companion PR must pass fresh independent Linux CI, author restrictions, and human review before merger into the canonical protected transition workflow source. Preserve original Traffic single writer, 131 frozen days, and financial mask/ports.
