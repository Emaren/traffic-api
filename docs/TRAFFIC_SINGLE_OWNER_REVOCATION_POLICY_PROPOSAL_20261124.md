# Traffic revocation: single-owner policy proposal (2026-11-24)

**PROPOSED, NOT EFFECTIVE. Production remains HOLD.** Source-only governance
proposal for issue #31, directive #7138029903. No new runtime, credential,
signature, branch protection change, production permit or publication.
Existing November 18/20 policies remain operative until explicitly superseded
by reviewed, owner-adopted policy with equivalent independent protection.

## Exact conflict and source review

The PRODUCT single-owner runbook at app-prodn a187ada489ce76c939d6d52218ee5a7f22520921
covers app-prodn/VPSSentry nonfinancial release authority, not Traffic-specific
revocation trust. Emaren is sole human owner. AI technical analysis and
machine evidence are not second human consent.

The existing Traffic external revocation and required-check runbooks explicitly
require a distinct authorized human reviewer. This is a specific security
requirement, not a mistaken Factory wrapper. GitHub ruleset 27691195 readback
on Nov24: active; exact protected ref traffic-v2-revocation; no bypass actors;
no deletion/non-fast-forward; PR and thread resolution; strict required
verify-traffic-v2-revocation-transition; creation not exempt; zero required
approving reviews and no last-pusher/code-owner approval. The protected ref
exists at 4d4adc2334e95377b4912b75dd5c69e8513d062f, but its complete tree
lacks the state JSON, owner PEM/trust JSON and transition workflow.
Main at 9d78b50cbbb40ad87caa930e52ecb1e7971d86e2 contains the merged #78
transition verifier. V3 #84 b19da0a9bc762b61544f6446718cee576db8cb38
is frozen and not modified by this proposal.

## Proposed decision and invariants

Permit sole-human owner policy authorization only if an independently
reviewed replacement for the distinct-human security function is demonstrated
to preserve the existing external monotonic trust boundary. Distinguish
owner decision, independent technical review, and independent enforcement.
An AI COMMENT and CI alone cannot replace independent enforcement against
an owner/root/repository-administrator able to alter protections. The current
threat model excludes colluding root/repository administrators; this proposal
does not broaden that exclusion or claim protection against an owner with
unrestricted access to both trust domains. If actual equivalent independence
cannot be demonstrated under the sole-owner model, retain the existing
distinct-authority HOLD. Do not substitute a second account controlled by
the same owner.

Retain all existing cryptographic and operational requirements:
- Three distinct, independently pinned owner/operator, upstream delivery and
  classifier Ed25519 keys, purpose-bound signatures and source-owned native
  custody. No private signing material on publisher, no key reuse, no AI
  signature or assertion of independent proof without original bytes.
- Existing root-owned trust and nonroot publisher, protected source identity,
  exact V3 renderer readback, source DB/insertion clocks, original immutable
  131-day archive and UNKNOWN gaps, genuine carry/cutoff/delivery closure.
- Existing 35-day maximum delegation, date/catchup bounds, no scope expansion
  or historical corrections; every proposed day independently verifies current
  external signed state against the exact protected local state.
- Exact transition check from trusted BASE only, PR HEAD treated as data,
  one modified state file, pinned regular trust files, same delegation binding,
  exactly next revision and strictly increasing UTC effective clock;
  terminal ACTIVE to REVOKED only. No renewal by reactivation.
- Keep strict check, no bypass actors, no force pushes/deletion, no direct
  unreviewed pushes, required thread resolution, immutable accepted source
  and independent readback. Missing/unavailable/stale/foreign external state
  or unverifiable protection means HOLD. Do not alter settings in this proposal.
- Existing independent external/hardware monotonic admission evidence,
  revocation and anti-rollback acceptance remain mandatory; a root-local
  counter, self-attestation or GitHub comment is not an equivalent anchor.

## Bootstrap blocker (do not work around)

The merged #78 required check is intentionally transition-only. The existing
protected base lacks trust/state/workflow; the verifier only accepts one
ordinary modification of the state file, never additions or workflow/key
changes, and requires original BASE trust. Thus seeding this ref is not an
ordinary accepted transition. Do not attempt a seed PR that passes by skipping
the check, faking a status, changing check names, executing proposed code,
temporarily relaxing rules, rewriting the protected ref, or using an alternate
account. Do not create a placeholder ACTIVE state.

Obtain an approved supported bootstrap procedure from the repository
security/administration authority (GitHub support if needed) and independently
review the complete exact genesis/trust/verification mechanism before any
production action. If the only available bootstrap requires weakening the
current protection, HOLD and return to the owner for a separately reviewed
equivalent security design; this proposal grants no permission to weaken it.
Initial authentic owner-signed ACTIVE state must match actual admitted
delegation, exact public trust and the immutable reviewed transition source.
Verify protected external state and local root state through their original
independent evidence paths before activating the existing runner.

## Review and acceptance matrix (not completed evidence)

1. Independent engineering reviewer records exact proposal commit, actual
   ruleset/ref readback, threat-model comparison and explicit defects or
   acceptance. Identify whether distinct authority remains necessary.
   Never label AI analysis a human approval.
2. Sole owner explicitly adopts exact reviewed Traffic policy (not a
   Factory permit, not a revocation signature). Record exact decision and
   immutable source. Separate actual protected bootstrap admission, signer
   enrollment and WE2 root installation remain required.
3. Existing required check must actually run on protected PRs and reject
   additions, altered code/trust, replay, duplicate JSON, stale/foreign state,
   wrong signature, wrong revision or clock, REVOKED-to-ACTIVE. No skipped,
   missing or mocked check accepted as production proof. Keep prior green
   qualification; run new tests only for substantive new executable changes.
4. Independent enforcement/readback must demonstrate rejection of stale
   signed ACTIVE after authentic revocation, including local rollback and
   protected external state rollback attempts under authorized isolated
   acceptance conditions; prove external unavailability causes HOLD. Do not
   revoke a live delegation just for testing without scoped owner admission.
   Renewal requires a separately admitted new delegation; no reset.
5. Preserve all existing production preconditions: authorized sustained ROOT
   headroom, frozen Watcher -> Matchups -> V3 Factory T10, actual renderer
   receipt, protected runner trust/config/ledger and native install/inverse.
   No fabricated day, duplicate publisher, or alteration of three original
   acquisition jobs. First prospective day Nov25 earliest delivery Nov26
   00:31Z; actual receipt/finality/signature acceptance controls eligibility.
   Second real unattended publication must be demonstrated, not inferred.

## Exact owner decision requested after technical review

Accept or reject this proposed Traffic-specific authority model, contingent on
equivalent independent enforcement and supported bootstrap. If reviewer or
security authority concludes distinct custody/reviewer is mandatory, retain
HOLD and identify that authority. Do not request GitHub self-APPROVE, second
accounts or duplicate scope consent. No changes to financial policy, telemetry
trust, recovery authority or already-qualified #192. This proposal is not an
authorization to change settings, generate signing credentials, publish a
day or activate the runner.
