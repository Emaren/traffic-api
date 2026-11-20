# WE4/WE2 — Traffic V2 external revocation admission contract (2026-11-18)

**Source candidate only. No owner signing material, HEL1 root files, or external branch is installed by WE4.**

## Security flaw and proposed external authority

The existing owner-signed local ACTIVE/REVOKED state admits rollback: a prior genuinely signed ACTIVE file remains cryptographically valid. A local root-writable counter cannot securely defeat a local root-restoration attacker. The proposed external trust domain is the separately governed existing public GitHub repository, **not another website server**.

An admitted WE2-only branch `Emaren/traffic-api:traffic-v2-revocation` holds `ops/traffic-v2-revocation-current.json` with the exact owner-signed `state`/`signature`. The publisher has **read-only anonymous HTTPS** access to the fixed GitHub API URL. It must check CURRENT external state against the locally signed root-owned state on EVERY proposed UTC day, then verify the existing owner signature and ACTIVE status. It never falls back to an old locally signed ACTIVE state on network failure, 404, stale Date, changed content, missing external record or REVOKED.

The source verifier fixes the HTTPS origin/path/ref, denies redirects, checks GitHub response Date within 120 seconds, bounds JSON/base64 response and file size, checks Git blob SHA and exact path, compares external and local canonical signed envelopes, then invokes existing separate owner-signature verifier. It does not store GitHub tokens, fetch arbitrary URLs, sign certificates, or change Traffic data.

## Mandatory independent monotonic branch governance

The external service is not trustworthy as monotonic merely because a single GET works. Before any real activation WE2 must read back and independently approve **no force-push, no branch deletion, no administrator bypass, no unreviewed direct push, mandatory independent human review, required signed-transition CI**, plus owner signer enrollment and initial signed ACTIVE snapshot. The signed transition gate in `scripts/public_audience_v2_revocation_transition.py` accepts ONLY same delegation ID/SHA, exactly next revision, strictly increasing UTC effective clock, terminal ACTIVE → REVOKED. It rejects REVOKED → ACTIVE and ACTIVE → ACTIVE even if the attacker possesses a valid older signed state. Renewal requires a separate owner-approved NEW delegation, not reactivation.

WE2's revocation procedure: immediately stop new publisher timer, commit newly signed REVOKED state to protected external branch, verify current remote readback, atomically install matching root-owned local REVOKED state, confirm live `--once` refuses the old state and monitor timer remains disabled. If GitHub is unavailable, HOLD all publication. A GitHub administrator capable of bypassing the accepted branch rules or colluding with the root operator is out of scope without a separate independently custodied hardware or external append-only anchor. Do not advertise unconditional tamper immunity.

## Still mandatory per real UTC day

The source authority NEVER replaces the two independent Ed25519 witnesses for genuine NGINX upstream closed-log EOF/offset delivery and the original global-IP/anti-bot/30-minute cross-midnight human-classification model. PR #74's existing single-writer `TRAFFIC_INGEST_RECEIPTS_ENABLED=1` is NOT physically admitted, recent 2048 sampled historical rows have NULL insertion clocks, and no two real consecutive completed UTC days have been certified. Reuse #75 bounded cursor and restart journal, original 131-day SHA/traffic classification, no invented arrival clocks, no zeros for UNKNOWN gaps and no new website runtime.

## Release and inverse boundaries

WE2 alone: admit actual protected #74 systemd postimage and natural insertion receipts; authenticate remote completed-day source; admit owner keys and external branch governance; review site gap renderer and original API; install reviewed certificate ledger and nonroot runner/oneshot/timer using `docs/TRAFFIC_V2_WE4_WE2_RUNNER_INSTALL_CONTRACT_20261118.md`; test two physical completed days, crash recovery and actual public Traffic API/website/Chrome parity. The source tests use disposable keys and a mocked external GitHub response; they are NOT physical external branch/ruleset acceptance. Inverse disables only new timer and preserves all legitimately signed days and 131 old rows.

**Live fact at handoff:** original 131 accepted days June11–Oct19; 29 UNKNOWN dates Oct20–Nov17; 0/2 newly certified real days; no live publisher or timer; external branch protection and owner-signed external state unadmitted; `HOLD_ROOT_OWNED_RUNNER_NOT_INSTALLED` remains correct.
