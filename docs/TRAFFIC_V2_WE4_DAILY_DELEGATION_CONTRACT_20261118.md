# WE4 → WE2 — Revocable unattended Traffic V2 daily publication delegation

2026-11-18. Source candidate stacked on Traffic PR #76, #75/#73; #74 remains a separate one-writer ingest-receipt admission. No HEL1 root actions or production permits are granted by this document.

## Owner authorization without a daily signature

New root-pinned mode authorization_mode=delegation uses two distinct root-owned, non-service-writable 0644 JSON records, each with OWNER Ed25519 detached signature over canonical content:

- daily_delegation: exact daily-delegation.v1 schema, Emaren owner, aoe2hdbets ONLY, random 256-bit delegation ID, 35-day MAX expiry, first allowed UTC day no older than one day before signing, last day no later than expiry, <=3-day completed-day age, <=7 daily catchups per invocation, original 131-day SHA, exact source commit, actual source DB inode/device, loaded systemd ingest unit SHA, active API SHA, WE2 Factory gap renderer SHA, separately pinned upstream/classifier signer identities, gap renderer mandatory, no historical correction.
- delegation_state: exact delegation-revocation-state.v1 signed status ACTIVE or REVOKED, binding the delegation SHA and ID and revision/effective UTC clock. Root config pins paths, mode and all trust identities. Every publication candidate reopens and verifies both signatures and root file ownership. Missing, expired, REVOKED, altered or foreign state causes HOLD and no public write.

The owner signs one narrowly scoped delegation (and any renewal or revocation), NOT a fresh daily permit. Exceptional history rewrites, financial changes, protected service adjustments, first installation and delegation enlargement remain independently owner-signed and WE2 root-approved. Private owner signer must remain outside the publisher. No key is committed to Git, site, API, or local source; tests use disposable key material only.

The owner delegation has a bounded term, not perpetual authority: after 35 days at most, owner must renew. Days older than 3 UTC days require independently reviewed exceptional authorizations. The old one_day mode remains available for explicit separate individual-day signoffs, and is not silently transformed into recurring approval. The authorization mode is fixed in root-owned config and not changeable via CLI.

## Daily independent source evidence still essential

Each UTC day needs authentic upstream NGINX closed-log/delivery EOF and source offsets, real PR #74 natural insertion clocks, complete #75 20,000-row bounded pages with no missing/invalid clocks, stable source watermark, original global-IP and 30m cross-midnight canonical session classifier/bot filtering equivalence, independent upstream and classifier signatures over exact day/source-model/counters, and a signed ACTIVE operator delegation. Late arrivals in either 31-minute wing around midnight force HOLD. No raw request totals, invented clocks, or zero-fill. Both signed source roles remain independent of the owner delegation signer.

Runner reuses the original .canary.lock, exact source DB identity, pinned active ingest unit environment, exact WE2 Factory-renderer/API readback, original 131-day SHA and SQLite same-transaction new audience row plus signed day certificate. Existing preimage and certificate-ledger restart recovery prevent duplicate new inserts. A gap-aware site MUST leave Oct20+ missing dates visibly unknown, not draw phantom continuity. There is no new website server or duplicate source writer.

## Root-only WE2 installation delta

Required new exact keys in protected runner.json: authorization_mode, daily_delegation, delegation_state. Suggested root-owned paths under /etc/aoe2war/traffic-v2/: daily-delegation.json and delegation-state.json; WE2 must derive exact path, SHA, preimage, signing custody, inverse and root policy. The runner is nonroot with a WE2-pinned service UID/GID. Source code reads both records every attempted delegated day, not only once at startup. The existing WE2 installation contract TRAFFIC_V2_WE4_WE2_RUNNER_INSTALL_CONTRACT_20261118.md still governs protected systemd unit/timer, additive ledger, actual root ACL, rollback and original services.

Signed REVOKED state should be installed atomically by WE2 and the new timer immediately disabled. IMPORTANT LIMITATION: a root attacker able to restore an older valid ACTIVE state can defeat file-only revocation. Independent release acceptance MUST include a trusted append-only/external monotonic revocation admission record or hardware-anchored revision proof; this source verifier does not pretend to solve rollback on a compromised root. WE2 must not claim revocation is irreversibly anti-rollback safe until that is physically tested.

## Source negative acceptance and remaining physical HOLD

Local adversarial tests require success only for an in-scope Ed25519-signed delegation and two independently signed complete-day fixture witnesses. Test REVOKED state, malicious edit of REVOKED to ACTIVE without new signature, missing revocation file, expired >35-day scope, changed source SHA, changed deployed gap renderer, substituted prohibited date, excessive backfill age, missing independent classifier signature, two consecutive fictional day appends under ONE owner delegation across process restart, original 131 rows unchanged, no duplicate, and source-epoch drift.

WE2 acceptance remains separate: genuine postinstall PR #74 one-writer receipts; immutable closed upstream NGINX log byte/EOF evidence; true canonical global-IP/cross-midnight parity; two consecutive REAL completed UTC day certificates and owner-signed delegation; protected unit/DB/site identities; independently reviewed monotonic revocation; real public API + website API + Chrome three-series date parity; new root-owned unit/timer with demonstrated next-day advancement and exact inverse.

Last known production: 131 accepted days June11–Oct19, 2026, 29 UNKNOWN days Oct20–Nov17, 0/2 new real day certificates, public graph last Oct19. No admitted daily delegation, no accepted real day, no installed publisher or timer; restricted runner --status still HOLD_ROOT_OWNED_RUNNER_NOT_INSTALLED. WE2 alone may change production.
