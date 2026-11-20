# WE4 Traffic lane: shared Production Reconciliation Gate

**SOURCE ONLY — WE2 has NOT installed/activated this reader.**

Run, under a separately approved nonroot read-only identity on HEL1, from an independently reviewed, SHA-pinned Traffic API source tree:

    python3 -m scripts.public_audience_v2_production_reconciliation --read-only-production

This emits one machine-readable JSON object, with schema aoe2war.production-reconciliation.traffic.v1, lane TRAFFIC, status PASS or FAIL, severity P0 for failures, and process exit code 0 or 2. The shared Central Command / Six-Lane Watch collector must consume this JSON, display its failed checks as actual owner-visible incidents, and never mark an HTTP200 response with only 131 old dates healthy. Traffic failure must NOT stop separate LIBRARY/CHAT/PRODUCT deployments.

## Independent read-only controls

- Original PR77 installed source R0=51387589, original SQLite dev/inode=2064/131074, recent rowid and original natural insertion clocks, pre-R0 historic NULL-clock sample. Live source clock must be <=10min old.
- The original systemd ingest timer is enabled/active; original loaded receipt flag appears once, API inline ingestion is disabled, financial ports 8092-8095 stay closed. Exact original WE2 read-only live unit fingerprints are pinned: traffic-ingest.service systemctl cat SHA256 1a700eacf9e0494706fbe32111db890a33f7f620592fdfc17ec071ae6781bea9 and traffic-ingest.timer SHA256 25e477653b9ed312159177732aae5af6f2ae4acd573a96dfe74b14bc267572b2. The effective ExecStart must retain /usr/bin/flock -n -E 75 /run/traffic-ingest/sync.lock and scripts/sync_traffic_logs.py. Any unit-hash drift/lock removal fails the Traffic lane; a reviewed unit replacement requires explicit new source-pin acceptance, never silent in-band acceptance. No second ingestion writer.
- Public private SQLite day matrix, certificate ledger table, certificate IDs/hashes, latest certified/published day and signed high-water-mark; journal absence is a P0 failure, not UNKNOWN success.
- Both hardcoded public Traffic and website APIs, equality of every date+three original metrics, frozen 131-day historical SHA, UTC lag and explicit UNKNOWN later dates. Oct19 latest on Nov20 is a stale publication FAIL even if HTTP200/131-point parity PASS.
- Separate nonroot publisher service and hourly enabled timer, last real natural trigger. An inactive legacy timer or working forward-ledger timer does not prove a genuine publisher.
- Actual independent Chrome DOM/screenshot and gap renderer acceptance is separate from HTTP API and source-marker checks. Without its real timestamped proof the graph gate fails; this source never manufactures a browser acceptance receipt.

The output is an observational adapter, not a publisher permit. The reader rechecks every existing private day-certificate SHA and page SHA against independently verified upstream-delivery and classifier Ed25519 signatures using WE2's protected, separately enrolled public keys and original private evidence. If no actual keys/evidence are accessible, this check fails; a database ledger row alone never passes. It also rechecks the live owner-signed ACTIVE revocation state against the current protected external state and ruleset. PR76's original publisher and owner delegation remain the authority for writing, and WE2's exact release approval is still mandatory. Actual Chrome proof requires separately accepted browser/Factory readback. The adapter does not sign, publish, create tables, enable timers, or alter any source row.

## Required production commissioning

WE2 approves a purpose-restricted nonroot read-only invocation from exact source hashes and adds this JSON lane to the shared Production Reconciliation Gate. Keep Traffic failure separate from authorized website/Chat releases. Independently review source scope, rollback/inverse, and prevent the observer from writing original SQLite. Preserve existing traffic-ingest.timer/flock and finance masks. Authoritative partial Nov20 natural ingest is already functioning. Nov20 may not become a completed signed day before Nov21 00:31Z, plus true remote EOF/31min late closure and two separately custodied real signatures. Nov21 earliest close after Nov22 00:31Z. Older Nov17/18 no authentic clocks, so no forged backfill.

Tests:

    python3 -m unittest -v tests.test_public_audience_v2_production_reconciliation

Mandatory negative cases: stale Oct19 despite successful APIs; missing certificate ledger; absent publisher timer; orphan published day lacking a certificate; retroactive old insertion clocks; stale live ingestion; disabled inline-ingest exclusion; finance listener; missing Chrome acceptance; mismatched graph latest date.
